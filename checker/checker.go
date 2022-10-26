package checker

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/letsencrypt/boulder/crl/checker"
	"github.com/letsencrypt/boulder/crl/crl_x509"
	"github.com/letsencrypt/boulder/issuance"
	"github.com/letsencrypt/crl-monitor/db"
	"github.com/letsencrypt/crl-monitor/storage"
)

func New(database *db.Database, storage *storage.Storage) Checker {
	return Checker{db: database, storage: storage}
}

type Checker struct {
	db      *db.Database
	storage *storage.Storage
}

func fetchNotAfter(serial *big.Int) time.Time {
	log.Printf("TODO: fetch cert with serial %s", serial)
	return time.Now().Add(-24 * time.Hour) // TODO: everything expired in the past!
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
		return fmt.Errorf("crl failed linting: %v", err)
	}
	log.Printf("crl %d successfully linted", crl.Number)

	err = c.lookForEarlyRemoval(prev, crl)
	if err != nil {
		return err
	}

	return c.lookForSeenCerts(ctx, crl)
}

func (c *Checker) lookForEarlyRemoval(prev *crl_x509.RevocationList, crl *crl_x509.RevocationList) error {
	diff, err := checker.Diff(prev, crl)
	if err != nil {
		return err
	}

	log.Printf("checking for early CRL removal on %d serials\n", len(diff.Removed))

	for _, removed := range diff.Removed {
		notAfter := fetchNotAfter(removed)

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
