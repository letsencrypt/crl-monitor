package checker

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	expirymock "github.com/letsencrypt/crl-monitor/checker/expiry/mock"
	"github.com/letsencrypt/crl-monitor/checker/testdata"
	dbmock "github.com/letsencrypt/crl-monitor/db/mock"
	storagemock "github.com/letsencrypt/crl-monitor/storage/mock"
)

func TestCheck(t *testing.T) {
	fetcher := expirymock.Fetcher{}
	fetcher.AddTestData(big.NewInt(1), testdata.Now.Add(30*time.Minute))
	// Cert 2 expires between crl 3 and 4
	cert2expiry := testdata.Now.Add(3*time.Hour + 30*time.Minute)
	fetcher.AddTestData(big.NewInt(2), cert2expiry)

	issuer, key := testdata.MakeIssuer(t)
	crl1der := testdata.MakeCRL(t, &testdata.CRL1, issuer, key)
	crl2der := testdata.MakeCRL(t, &testdata.CRL2, issuer, key)
	crl3der := testdata.MakeCRL(t, &testdata.CRL3, issuer, key)
	crl4der := testdata.MakeCRL(t, &testdata.CRL4, issuer, key)

	data := map[string][]storagemock.MockObject{
		"should-be-good": {
			{
				VersionID: "the-current-version",
				Data:      crl2der,
			},
			{
				VersionID: "the-previous-version",
				Data:      crl1der,
			},
		},
		"early-removal": {
			{
				VersionID: "the-current-version",
				Data:      crl4der, // CRL4 has early removals
			},
			{
				VersionID: "the-previous-version",
				Data:      crl3der,
			},
		},
	}
	bucket := "crl-test"

	checker := &Checker{
		db:       dbmock.NewMockedDB(t),
		storage:  storagemock.New(t, bucket, data),
		fetcher:  &fetcher,
		ageLimit: 24 * time.Hour,
	}

	require.NoError(t, checker.Check(context.Background(), issuer, bucket, "should-be-good", nil))
	require.ErrorContains(t, checker.Check(context.Background(), issuer, bucket, "early-removal", nil), "early removal of 1 certificates detected!")
}
