package checker

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/letsencrypt/boulder/crl/checker"
	"github.com/letsencrypt/boulder/crl/crl_x509"
	"github.com/letsencrypt/boulder/issuance"
	"github.com/letsencrypt/crl-monitor/checker/earlyremoval"
	"github.com/letsencrypt/crl-monitor/db"
	"github.com/letsencrypt/crl-monitor/storage"
)

func New(database *db.Database, storage *storage.Storage, fetcher earlyremoval.Fetcher, ageLimit time.Duration, issuers []*issuance.Certificate) Checker {
	issuerMap := make(map[string]*issuance.Certificate, len(issuers))
	for _, issuer := range issuers {
		issuerMap[fmt.Sprintf("%d", issuer.NameID())] = issuer
	}

	return Checker{
		db:       database,
		storage:  storage,
		fetcher:  fetcher,
		ageLimit: ageLimit,
		issuers:  issuerMap,
	}
}

// The Checker handles fetching and linting CRLs.
// Use New to obtain one.
type Checker struct {
	db       *db.Database
	storage  *storage.Storage
	fetcher  earlyremoval.Fetcher
	ageLimit time.Duration
	issuers  map[string]*issuance.Certificate
}

// Check fetches a CRL and its previous version.  It runs lints on the CRL, checks for early removal, and removes any
// certificates we're waiting for out of the database.
func (c *Checker) Check(ctx context.Context, bucket, object string, startingVersion *string) error {
	// Read the current CRL shard
	crlDER, version, err := c.storage.Fetch(ctx, bucket, object, startingVersion)
	if err != nil {
		return err
	}

	crl, err := crl_x509.ParseRevocationList(crlDER)
	if err != nil {
		return fmt.Errorf("error parsing current crl: %v", err)
	}
	log.Printf("loaded CRL number %d (len %d) from %s version %s", crl.Number, len(crl.RevokedCertificates), object, version)

	issuer, err := c.issuerForObject(object)
	if err != nil {
		return err
	}
	log.Printf("issuer %s", issuer.Subject.CommonName)

	err = checker.Validate(crl, issuer, c.ageLimit)
	if err != nil {
		return fmt.Errorf("crl failed linting: %v", err)
	}
	log.Printf("crl %d successfully linted", crl.Number)

	// And the previous:
	prevVersion, err := c.storage.Previous(ctx, bucket, object, version)
	if err != nil {
		return err
	}

	prevDER, _, err := c.storage.Fetch(ctx, bucket, object, &prevVersion)
	if err != nil {
		return err
	}

	prev, err := crl_x509.ParseRevocationList(prevDER)
	if err != nil {
		return fmt.Errorf("error parsing previous crl: %v", err)
	}
	log.Printf("loaded previous CRL number %d (len %d) from version %s", prev.Number, len(prev.RevokedCertificates), prevVersion)

	earlyRemoved, err := earlyremoval.Check(ctx, c.fetcher, prev, crl)
	if err != nil {
		return fmt.Errorf("failed to check for early removal: %v", err)
	}

	if len(earlyRemoved) != 0 {
		sample := earlyRemoved
		if len(sample) > 50 {
			sample = sample[:50]
		}

		// Certificates removed early!  This is very bad.
		return fmt.Errorf("early removal of %d certificates detected! First %d: %v", len(earlyRemoved), len(sample), sample)
	}

	return c.lookForSeenCerts(ctx, crl)
}

// lookForSeenCerts removes any certs in this CRL from the database, as they've now appeared in a CRL.
// We expect the database to be much smaller than CRLs, so we load the entire database into memory.
func (c *Checker) lookForSeenCerts(ctx context.Context, crl *crl_x509.RevocationList) error {
	unseenCerts, err := c.db.GetAllCerts(ctx)
	if err != nil {
		return fmt.Errorf("failed to read from db: %v", err)
	}
	var seenSerials [][]byte
	for _, seen := range crl.RevokedCertificates {
		if metadata, ok := unseenCerts[db.NewCertKey(seen.SerialNumber).SerialString()]; ok {
			seenSerials = append(seenSerials, metadata.SerialNumber)
		}
	}

	err = c.db.DeleteSerials(ctx, seenSerials)
	if err != nil {
		return fmt.Errorf("failed to delete from db: %v", err)
	}
	return nil
}

// issuerForObject takes an s3 object path, extracts the issuer prefix, and returns the right issuance.Certificate
func (c *Checker) issuerForObject(object string) (*issuance.Certificate, error) {
	prefix, _, found := strings.Cut(object, "/")
	if !found {
		return nil, fmt.Errorf("object path did not contain /: %s", object)
	}

	issuer, ok := c.issuers[prefix]
	if !ok {
		for k := range c.issuers {
			fmt.Printf("issuer %s", k)
		}
		return nil, fmt.Errorf("unable to find an issuer for object prefix %s", prefix)
	}

	return issuer, nil
}
