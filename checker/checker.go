package checker

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"

	"github.com/letsencrypt/crl-monitor/db"
)

func New(database *db.Database) Checker {
	return Checker{db: database}
}

type Checker struct {
	db *db.Database
}

// VersionedCRLShard represents a single version of a single shard
type VersionedCRLShard struct {
	Issuer  string
	Index   string
	Version string
}

func (vcs VersionedCRLShard) Fetch() x509.RevocationList {
	return x509.RevocationList{}
}

func (vcs VersionedCRLShard) Previous() VersionedCRLShard {
	return VersionedCRLShard{}
}

func fetchNotAfter(serial *big.Int) time.Time {
	fmt.Printf("TODO: fetch cert with serial %s", serial)
	return time.Now()
}

// CRLLint
// TODO: stub function
func CRLLint(crl x509.RevocationList) error {
	return nil
}

// CRLDiff
// TODO: stub function
func CRLDiff(crl x509.RevocationList, prev x509.RevocationList) []pkix.RevokedCertificate {
	return []pkix.RevokedCertificate{}
}

func (c *Checker) Check(ctx context.Context, shard VersionedCRLShard) error {
	// Read the current CRL shard
	crl := shard.Fetch()
	prev := shard.Previous().Fetch()

	err := CRLLint(crl)
	if err != nil {
		return fmt.Errorf("crl failed linting: %v", err)
	}

	err = c.lookForEarlyRemoval(crl, prev)
	if err != nil {
		return err
	}

	return c.lookForSeenCerts(ctx, crl)
}

func (c *Checker) lookForEarlyRemoval(crl x509.RevocationList, prev x509.RevocationList) error {
	for _, removed := range CRLDiff(crl, prev) {
		notAfter := fetchNotAfter(removed.SerialNumber)

		if prev.ThisUpdate.Before(notAfter) {
			// This certificate expired after the previous CRL was issued
			// All removed CRLs should have been expired in the previous CRL
			return fmt.Errorf("early removal of %v from crl %v", removed, prev)
		}
	}
	return nil
}

func (c *Checker) lookForSeenCerts(ctx context.Context, crl x509.RevocationList) error {
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
