package checker

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/letsencrypt/boulder/crl/checker"
	"github.com/letsencrypt/boulder/crl/crl_x509"
	"github.com/letsencrypt/boulder/issuance"
	"github.com/letsencrypt/crl-monitor/db"
	"github.com/letsencrypt/crl-monitor/storage"
)

func New(database *db.Database, storage *storage.Storage) Checker {
	// TODO: parameterize this
	baseURL := "https://acme-v02.api.letsencrypt.org/acme/cert/"
	fetcher := boulderAPIFetcher{baseURL: baseURL}
	return Checker{db: database, storage: storage, fetcher: &fetcher}
}

type Checker struct {
	db      *db.Database
	storage *storage.Storage
	fetcher ExpFetcher
}

type ExpFetcher interface {
	FetchNotAfter(ctx context.Context, serial *big.Int) (time.Time, error)
}

type boulderAPIFetcher struct {
	baseURL string
}

func (baf *boulderAPIFetcher) FetchNotAfter(ctx context.Context, serial *big.Int) (time.Time, error) {
	// boulder implements non-acme-standard support for unauthenticated GETs of certificates
	url := fmt.Sprintf("%s/%x", baf.baseURL, serial)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return time.Time{}, err
	}

	log.Printf("fetching serial for %d", serial)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return time.Time{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return time.Time{}, fmt.Errorf("error fetching certificate with serial %d: http status %d", serial, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return time.Time{}, err
	}

	block, _ := pem.Decode(body)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}

	return cert.NotAfter, nil
}

func (c *Checker) Check(ctx context.Context, issuer *issuance.Certificate, bucket, object string) error {
	// Read the current CRL shard
	crlDER, version, err := c.storage.Fetch(ctx, bucket, object, nil)
	if err != nil {
		return err
	}

	// And the previous:
	prevVersion, err := c.storage.Previous(ctx, bucket, object, version)
	if err != nil {
		return err
	}

	prevDER, _, err := c.storage.Fetch(ctx, bucket, object, &prevVersion)
	if err != nil {
		return err
	}

	crl, err := crl_x509.ParseRevocationList(crlDER)
	if err != nil {
		return fmt.Errorf("error parsing current crl: %v", err)
	}
	prev, err := crl_x509.ParseRevocationList(prevDER)
	if err != nil {
		return fmt.Errorf("error parsing previous crl: %v", err)
	}

	log.Printf("loaded CRL %d (len %d) and previous %d (len %d)", crl.Number, len(crl.RevokedCertificates), prev.Number, len(crl.RevokedCertificates))

	ageLimit := 24 * time.Hour
	err = checker.Validate(crl, issuer, ageLimit)
	if err != nil {
		log.Printf("crl failed linting: %v", err)
		// TODO return fmt.Errorf
	}
	log.Printf("crl %d successfully linted", crl.Number)

	err = lookForEarlyRemoval(ctx, c.fetcher, prev, crl)
	if err != nil {
		return err
	}

	return c.lookForSeenCerts(ctx, crl)
}

func lookForEarlyRemoval(ctx context.Context, fetcher ExpFetcher, prev *crl_x509.RevocationList, crl *crl_x509.RevocationList) error {
	diff, err := checker.Diff(prev, crl)
	if err != nil {
		return err
	}

	log.Printf("checking for early CRL removal on %d serials\n", len(diff.Removed))

	for _, removed := range diff.Removed {
		notAfter, err := fetcher.FetchNotAfter(ctx, removed)
		if err != nil {
			return err
		}

		if prev.ThisUpdate.Before(notAfter) {
			// This certificate expired after the previous CRL was issued
			// All removed CRLs should have been expired in the previous CRL
			return fmt.Errorf("early removal of %v from crl %v: previous CRL at %v is before cert notAfter %v",
				removed, prev.Number, prev.ThisUpdate, notAfter)
		}
	}

	return nil
}

func (c *Checker) lookForSeenCerts(ctx context.Context, crl *crl_x509.RevocationList) error {
	monitoring, err := c.db.GetAllCerts(ctx)
	if err != nil {
		return fmt.Errorf("failed to read from db: %v", err)
	}
	var seenSerials [][]byte
	for _, seen := range crl.RevokedCertificates {
		if metadata, ok := monitoring[db.NewCertKey(seen.SerialNumber).SerialString()]; ok {
			seenSerials = append(seenSerials, metadata.SerialNumber)
		}
	}

	err = c.db.DeleteSerials(ctx, seenSerials)
	if err != nil {
		return fmt.Errorf("failed to delete from db: %v", err)
	}
	return nil
}
