package earlyremoval

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/letsencrypt/boulder/crl/checker"
	"github.com/letsencrypt/boulder/crl/crl_x509"
)

type Fetcher interface {
	FetchNotAfter(ctx context.Context, serial *big.Int) (time.Time, error)
}

func Check(ctx context.Context, fetcher Fetcher, prev *crl_x509.RevocationList, crl *crl_x509.RevocationList) error {
	diff, err := checker.Diff(prev, crl)
	if err != nil {
		return err
	}

	log.Printf("checking for early CRL removal on %d serials", len(diff.Removed))

	for _, removed := range diff.Removed {
		notAfter, err := fetcher.FetchNotAfter(ctx, removed)
		if err != nil {
			return err
		}

		if prev.ThisUpdate.Before(notAfter) {
			// This certificate expired after the previous CRL was issued
			// All removed CRLs should have been expired in the previous CRL
			return fmt.Errorf("early removal of %d from crl %d: previous CRL at %s is before cert notAfter %s",
				removed, prev.Number, prev.ThisUpdate, notAfter)
		}
	}

	return nil
}
