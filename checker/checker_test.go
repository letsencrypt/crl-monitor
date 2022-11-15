package checker

import (
	"context"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	expirymock "github.com/letsencrypt/crl-monitor/checker/expiry/mock"
	"github.com/letsencrypt/crl-monitor/checker/testdata"
	"github.com/letsencrypt/crl-monitor/db"
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

	ctx := context.Background()

	// Watch the first revoked cert's serial
	serial := testdata.CRL1.RevokedCertificates[0].SerialNumber
	require.NoError(t, checker.db.AddCert(ctx, &x509.Certificate{SerialNumber: serial}, testdata.Now))
	shouldNotBeSeen := big.NewInt(12345)
	require.NoError(t, checker.db.AddCert(ctx, &x509.Certificate{SerialNumber: shouldNotBeSeen}, testdata.Now))

	require.NoError(t, checker.Check(ctx, issuer, bucket, "should-be-good", nil))

	// We should have seen the monitored cert but not the 12345 serial
	unseenCerts, err := checker.db.GetAllCerts(ctx)
	require.NoError(t, err)
	serialString := db.NewCertKey(shouldNotBeSeen).SerialString()
	require.Contains(t, unseenCerts, serialString)
	delete(unseenCerts, serialString)
	require.Empty(t, unseenCerts)

	// The "early-removal" object should error on a certificate removed early
	require.ErrorContains(t, checker.Check(ctx, issuer, bucket, "early-removal", nil), "early removal of 1 certificates detected!")
}