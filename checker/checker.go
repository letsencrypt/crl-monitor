package checker

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"log"
	"math/big"
	"sort"
	"time"

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
	fmt.Printf("TODO: fetch cert with serial %s", serial)
	return time.Now()
}

// CRLLint
// TODO: stub function
func CRLLint(crl *x509.RevocationList) error {
	return nil
}

// Diff returns the sets of serials that were added and removed between two
// CRLs. In order to be comparable, the CRLs must come from the same issuer, and
// be given in the correct order (the "old" CRL's Number and ThisUpdate must
// both precede the "new" CRL's).
func Diff(old, new *x509.RevocationList) ([]*big.Int, error) {
	if !bytes.Equal(old.AuthorityKeyId, new.AuthorityKeyId) {
		return nil, fmt.Errorf("CRLs were not issued by same issuer")
	}

	if !old.ThisUpdate.Before(new.ThisUpdate) {
		return nil, fmt.Errorf("old CRL %s does not precede new CRL %s", old.ThisUpdate, new.ThisUpdate)
	}

	if old.Number.Cmp(new.Number) > 0 {
		return nil, fmt.Errorf("old CRL %d does not precede new CRL %d (%d)", old.Number, new.Number, old.Number.Cmp(new.Number))
	}

	// Sort both sets of serials so we can march through them in order.
	oldSerials := make([]*big.Int, 0, len(old.RevokedCertificates))
	for _, rc := range old.RevokedCertificates {
		oldSerials = append(oldSerials, rc.SerialNumber)
	}
	sort.Slice(oldSerials, func(i, j int) bool {
		return oldSerials[i].Cmp(oldSerials[j]) < 0
	})

	newSerials := make([]*big.Int, 0, len(new.RevokedCertificates))
	for _, rc := range new.RevokedCertificates {
		newSerials = append(newSerials, rc.SerialNumber)
	}
	sort.Slice(newSerials, func(i, j int) bool {
		return newSerials[i].Cmp(newSerials[j]) < 0
	})

	// Work our way through both lists of sorted serials. If the old list skips
	// past a serial seen in the new list, then that serial was added. If the new
	// list skips past a serial seen in the old list, then it was removed.
	i, j := 0, 0
	added := make([]*big.Int, 0)
	removed := make([]*big.Int, 0)
	for {
		if i >= len(oldSerials) {
			added = append(added, newSerials[j:]...)
			break
		}
		if j >= len(newSerials) {
			removed = append(removed, oldSerials[i:]...)
			break
		}
		cmp := oldSerials[i].Cmp(newSerials[j])
		if cmp < 0 {
			removed = append(removed, oldSerials[i])
			i++
		} else if cmp > 0 {
			added = append(added, newSerials[j])
			j++
		} else {
			i++
			j++
		}
	}

	return removed, nil
}

func (c *Checker) Check(ctx context.Context, bucket, object string) error {
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

	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		return fmt.Errorf("error parsing current crl: %v", err)
	}
	prev, err := x509.ParseRevocationList(prevDER)
	if err != nil {
		return fmt.Errorf("error parsing previous crl: %v", err)
	}

	log.Printf("loaded CRL %d (len %d) and previous %d (len %d)", crl.Number, len(crl.RevokedCertificates), prev.Number, len(crl.RevokedCertificates))

	err = CRLLint(crl)
	if err != nil {
		return fmt.Errorf("crl failed linting: %v", err)
	}

	err = c.lookForEarlyRemoval(crl, prev)
	if err != nil {
		return err
	}

	return c.lookForSeenCerts(ctx, crl)
}

func (c *Checker) lookForEarlyRemoval(crl *x509.RevocationList, prev *x509.RevocationList) error {
	diff, err := Diff(prev, crl)
	if err != nil {
		return err
	}

	log.Printf("checking for early CRL removal on %d serials\n", len(diff))

	for _, removed := range diff {
		notAfter := fetchNotAfter(removed)

		if prev.ThisUpdate.Before(notAfter) {
			// This certificate expired after the previous CRL was issued
			// All removed CRLs should have been expired in the previous CRL
			return fmt.Errorf("early removal of %v from crl %v", removed, prev)
		}
	}

	return nil
}

func (c *Checker) lookForSeenCerts(ctx context.Context, crl *x509.RevocationList) error {
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
