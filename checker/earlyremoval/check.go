package earlyremoval

import (
	"context"
	"log"
	"math/big"
	"time"

	"github.com/letsencrypt/boulder/crl/checker"
	"github.com/letsencrypt/boulder/crl/crl_x509"
)

type Fetcher interface {
	FetchNotAfter(ctx context.Context, serial *big.Int) (time.Time, error)
}

type EarlyRemoval struct {
	Serial   *big.Int
	NotAfter time.Time
}

func Check(ctx context.Context, fetcher Fetcher, prev *crl_x509.RevocationList, crl *crl_x509.RevocationList) ([]EarlyRemoval, error) {
	diff, err := checker.Diff(prev, crl)
	if err != nil {
		return nil, err
	}

	log.Printf("checking for early CRL removal on %d serials", len(diff.Removed))

	var earlyRemovals []EarlyRemoval

	for _, removed := range diff.Removed {
		notAfter, err := fetcher.FetchNotAfter(ctx, removed)
		if err != nil {
			return nil, err
		}

		if prev.ThisUpdate.Before(notAfter) {
			// This certificate expired after the previous CRL was issued
			// All removed CRLs should have been expired in the previous CRL
			earlyRemovals = append(earlyRemovals, EarlyRemoval{
				Serial:   removed,
				NotAfter: notAfter,
			})
		}
	}

	return earlyRemovals, nil
}
