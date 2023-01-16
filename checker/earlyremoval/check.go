package earlyremoval

import (
	"context"
	"log"
	"math/big"
	"math/rand"
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

// sample returns a subset from a slice of up to `max` size.
// The first 10% and last 10% of the returned data come directly from the input
// to help catch edge cases more likely to occur at the input's start and end.
// Ordering of the entries in the returned data is not preserved from the input.
func sample[T any](input []T, max int) []T {
	if len(input) <= max {
		return input
	}

	sampled := make([]T, 0, max)

	tenPercent := max / 10

	// First 10%:
	sampled = append(sampled, input[:tenPercent]...)

	// Use rand.Perm to give us the indexes to sample from the middle section,
	// truncated to the desired length.  This gives us a permutation, when we
	// only really need a subset, but order doesn't matter.
	middle := input[tenPercent : len(input)-tenPercent]
	middleSampleLen := max - 2*tenPercent
	for _, idx := range rand.Perm(len(middle))[:middleSampleLen] {
		sampled = append(sampled, middle[idx])
	}

	// Final 10%:
	sampled = append(sampled, input[len(input)-tenPercent:]...)

	return sampled
}

// Check for early removal.  If maxFetch is greater than 0, only check that many serials
func Check(ctx context.Context, fetcher Fetcher, maxFetch int, prev *crl_x509.RevocationList, crl *crl_x509.RevocationList) ([]EarlyRemoval, error) {
	diff, err := checker.Diff(prev, crl)
	if err != nil {
		return nil, err
	}

	var sampled []*big.Int
	if maxFetch > 0 {
		sampled = sample(diff.Removed, maxFetch)
	} else {
		sampled = diff.Removed
	}

	log.Printf("checking for early CRL removal on %d of %d serials", len(sampled), len(diff.Removed))

	var earlyRemovals []EarlyRemoval

	for i, removed := range sampled {
		if i%100 == 0 {
			log.Printf("fetching cert %d/%d", i, len(sampled))
		}
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
