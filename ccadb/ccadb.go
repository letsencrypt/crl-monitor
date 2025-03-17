package ccadb

import (
	"context"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"slices"
	"time"

	"github.com/letsencrypt/boulder/crl/checker"
	"github.com/letsencrypt/crl-monitor/cmd"
	"github.com/letsencrypt/crl-monitor/idp"
)

//go:embed intermediates.pem
var allIssuers []byte

const (
	CCADBAllCertificatesCSVURL cmd.EnvVar = "CCADB_ALL_CERTIFICATES_CSV_URL"
	CRLAgeLimit                cmd.EnvVar = "CRL_AGE_LIMIT"
	CAOwner                    cmd.EnvVar = "CA_OWNER"
)

// Checker fetches the AllCertificatesRecordsReport from CCADB, filters for a
// specific CA Owner (defaults to 'Internet Security Research Group'), and
// fetches all CRLs found.
//
// It checks that the CRLs:
//   - Are not too old
//   - Have an issuingDistributionPoint that matches the URL from which they
//     were fetched
//   - Have a valid signature based on their issuer SKID from CCADB
//     (full issuer certificates for ISRG are embedded in this binary)
//   - Don't have duplicate serial numbers across different CRLs
type Checker struct {
	allCertificatesCSVURL string
	caOwner               string
	crlAgeLimit           time.Duration

	// Map from SKID (bytes cast to string) to issuer.
	issuers map[string]*x509.Certificate
}

func NewFromEnv() (*Checker, error) {
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

	issuers, err := parseIssuers()
	if err != nil {
		return nil, err
	}

	return &Checker{
		allCertificatesCSVURL: ccadbAllCertificatesCSVURL,
		caOwner:               caOwner,
		crlAgeLimit:           ageLimitDuration,
		issuers:               issuers,
	}, nil
}

func (c *Checker) Check(ctx context.Context) error {
	crlURLs, err := c.getCRLURLs(ctx, c.allCertificatesCSVURL, c.caOwner)
	if err != nil {
		return err
	}

	var crls, entries, bytes int

	serials := make(map[string]*x509.RevocationList)

	var errs []error
	for skid, urls := range crlURLs {
		for _, url := range urls {
			crls++
			issuer := c.issuers[skid]
			if issuer == nil {
				return fmt.Errorf("no issuer found for skid %x", skid)
			}
			crl, err := checkCRL(ctx, url, issuer, c.crlAgeLimit)
			if err != nil {
				errs = append(errs, fmt.Errorf("fetching %s: %s", url, err))
				continue
			}

			// Check for duplicates across different CRLs (or within a CRL).
			// Cap any given CRL at 1M entries to limit memory use.
			for i, entry := range crl.RevokedCertificateEntries {
				if i > 1_000_000 {
					break
				}
				serialByteString := string(entry.SerialNumber.Bytes())
				if otherCRL, ok := serials[serialByteString]; ok {
					otherCRLURL, err := idp.Get(otherCRL)
					if err != nil {
						return err
					}
					errs = append(errs, fmt.Errorf("serial %x seen on multiple CRLs: %s and %s", entry.SerialNumber, otherCRLURL, url))
				}
				serials[serialByteString] = crl
			}

			age := time.Since(crl.ThisUpdate).Round(time.Minute)
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
func (c Checker) getCRLURLs(ctx context.Context, csvURL string, owner string) (map[string][]string, error) {
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

	var ownerIndex, crlIndex, skidIndex, certificateNameIndex int
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
		if name == "Certificate Name" {
			certificateNameIndex = i
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
		certificateName := record[certificateNameIndex]
		skidBase64 := record[skidIndex]
		skid, err := base64.StdEncoding.DecodeString(skidBase64)
		if err != nil {
			return nil, err
		}
		if len(skid) == 0 {
			return nil, fmt.Errorf("no skid for %q", certificateName)
		}
		stringSKID := string(skid)
		if c.issuers[stringSKID] == nil {
			return nil, fmt.Errorf("CCADB contained %q with SKID %x, but that SKID is not in embedded issuers file. Might need update and rebuild this binary",
				certificateName, skid)
		}
		// An issuer can show up multiple times, under different cross-signs. However
		// it must have the same list of CRLs each time.
		if c := allCRLs[stringSKID]; c != nil && !slices.Equal(c, crls) {
			return nil, fmt.Errorf("CCADB contained %q with SKID %x multiple times with different CRLs", certificateName, skid)
		}
		allCRLs[stringSKID] = crls
	}

	if len(allCRLs) == 0 {
		return nil, fmt.Errorf("no records found in CCADB for CA Owner %q", owner)
	}
	return allCRLs, nil
}

// getIssuers parses the embedded PEM file containing multiple intermediates.
//
// The file should contain an entry for every issuer that is listed in the
// CCADB All Certificates list for the relevant CA Organization.
//
// Returns a map from SubjectKeyId (cast from []byte to string) to the
// matching intermediate.
func parseIssuers() (map[string]*x509.Certificate, error) {
	ret := make(map[string]*x509.Certificate)

	remaining := allIssuers
	for {
		var block *pem.Block
		block, remaining = pem.Decode(remaining)
		if block == nil {
			return ret, nil
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}

		ret[string(cert.SubjectKeyId)] = cert
	}
}
