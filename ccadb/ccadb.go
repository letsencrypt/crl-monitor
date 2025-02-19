package ccadb

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/letsencrypt/boulder/crl/checker"
	"github.com/letsencrypt/crl-monitor/cmd"
	"github.com/letsencrypt/crl-monitor/idp"
)

const (
	CCADBAllCertificatesCSVURL cmd.EnvVar = "CCADB_ALL_CERTIFICATES_CSV_URL"
	AllIssuersURL              cmd.EnvVar = "ALL_ISSUERS_URL"
	CRLAgeLimit                cmd.EnvVar = "CRL_AGE_LIMIT"
	CAOwner                    cmd.EnvVar = "CA_OWNER"
)

type Checker struct {
	allCertificatesCSVURL string
	caOwner               string
	allIssuersURL         string
	crlAgeLimit           time.Duration
}

func NewFromEnv() (*Checker, error) {
	allIssuersURL := AllIssuersURL.MustRead("URL containing PEM of all intermediates belonging to the CA_OWNER")

	ccadbAllCertificatesCSVURL := "https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatv2"
	allCertsCSV, ok := CCADBAllCertificatesCSVURL.LookupEnv()
	if ok {
		ccadbAllCertificatesCSVURL = allCertsCSV
	}

	caOwner := "Internet Security Research Group"
	owner, ok := CAOwner.LookupEnv()
	if ok {
		caOwner = owner
	}

	ageLimitDuration := 24 * time.Hour
	crlAgeLimit, ok := CRLAgeLimit.LookupEnv()
	if ok {
		var err error
		ageLimitDuration, err = time.ParseDuration(crlAgeLimit)
		if err != nil {
			return nil, fmt.Errorf("parsing age limit: %s", err)
		}
	}
	return &Checker{
		allCertificatesCSVURL: ccadbAllCertificatesCSVURL,
		caOwner:               caOwner,
		allIssuersURL:         allIssuersURL,
		crlAgeLimit:           ageLimitDuration,
	}, nil
}

func (c *Checker) Check(ctx context.Context) error {
	issuers, err := getIssuers(c.allIssuersURL)
	if err != nil {
		return err
	}

	crlURLs, err := getCRLURLs(ctx, c.allCertificatesCSVURL, "Internet Security Research Group")
	if err != nil {
		return err
	}

	var crls, entries, bytes int

	var errs []error
	for skid, urls := range crlURLs {
		for _, url := range urls {
			crls++
			issuer := issuers[skid]
			if issuer == nil {
				return fmt.Errorf("no issuer found for skid %x", skid)
			}
			crl, err := checkCRL(ctx, url, issuer, c.crlAgeLimit)
			if err != nil {
				errs = append(errs, fmt.Errorf("fetching %s: %s", url, err))
				continue
			}
			age := time.Since(crl.ThisUpdate).Round(time.Hour)
			nextUpdate := time.Until(crl.NextUpdate).Round(time.Hour)
			entries += len(crl.RevokedCertificateEntries)
			bytes += len(crl.Raw)
			log.Printf("crl %q: %d entries, %d bytes, age %gm, nextUpdate %gh", url, len(crl.RevokedCertificateEntries), len(crl.Raw), age.Minutes(), nextUpdate.Hours())
		}
	}

	log.Printf("%d CRLs had %d entries and %d bytes", crls, entries, bytes)
	return errors.Join(errs...)
}

func checkCRL(ctx context.Context, url string, issuer *x509.Certificate, ageLimit time.Duration) (*x509.RevocationList, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP status code %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading CRL body: %s", err)
	}
	crl, err := x509.ParseRevocationList(body)
	if err != nil {
		return nil, err
	}

	idp, err := idp.Get(crl)
	if err != nil {
		return nil, err
	}

	if idp != url {
		return nil, fmt.Errorf("CRL fetched from %s had mismatched IDP %s", url, idp)
	}

	return crl, checker.Validate(crl, issuer, ageLimit)
}

// returns a map from issuer SKID to list of URLs
func getCRLURLs(ctx context.Context, csvURL string, owner string) (map[string][]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, csvURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP status code %d", resp.StatusCode)
	}
	reader := csv.NewReader(resp.Body)
	header, err := reader.Read()
	if err != nil {
		return nil, err
	}

	var ownerIndex int
	var crlIndex int
	var skidIndex int
	for i, name := range header {
		if name == "CA Owner" {
			ownerIndex = i
		}
		if name == "JSON Array of Partitioned CRLs" {
			crlIndex = i
		}
		if name == "Subject Key Identifier" {
			skidIndex = i
		}
	}
	allCRLs := make(map[string][]string)
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if record[ownerIndex] != owner {
			continue
		}
		skidBase64 := record[skidIndex]
		skid, err := base64.StdEncoding.DecodeString(skidBase64)
		if err != nil {
			return nil, err
		}
		if len(skid) == 0 {
			return nil, fmt.Errorf("no skid")
		}
		crlJSON := record[crlIndex]
		if crlJSON == "" {
			continue
		}
		var crls []string
		err = json.Unmarshal([]byte(crlJSON), &crls)
		if err != nil {
			return nil, err
		}
		// Roots have a CRL list containing a single ""
		if len(crls) == 1 && crls[0] == "" {
			continue
		}
		for _, c := range crls {
			if c == "" {
				return nil, fmt.Errorf("empty CRL in %+v", record)
			}
			allCRLs[string(skid)] = append(allCRLs[string(skid)], c)
		}
	}
	return allCRLs, nil
}

// getIssuers fetches and parses a PEM file containing multiple intermediates.
//
// The file should contain an entry for every issuer that is listed in the
// CCADB All Certificates list for the relevant CA Organization.
//
// Returns a map from SubjectKeyId (cast from []byte to string) to the
// matching intermediate.
func getIssuers(allIssuersURL string) (map[string]*x509.Certificate, error) {
	resp, err := http.Get(allIssuersURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP status code %d from %s", resp.StatusCode, allIssuersURL)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	ret := make(map[string]*x509.Certificate)

	for {
		block, remaining := pem.Decode(body)
		if block == nil {
			return ret, nil
		}
		body = remaining

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}

		ret[string(cert.SubjectKeyId)] = cert
	}
}
