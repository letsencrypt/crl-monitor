package checker

import (
	"context"
	"crypto/x509"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/letsencrypt/boulder/core"

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

	issuerName := nameID(issuer)
	shouldBeGood := fmt.Sprintf("%s/should-be-good.crl", issuerName)
	earlyRemoval := fmt.Sprintf("%s/early-removal.crl", issuerName)
	shouldBeGoodIDP := fmt.Sprintf("http://idp/%s", shouldBeGood)
	earlyRemovalIDP := fmt.Sprintf("http://idp/%s", earlyRemoval)

	crl1der := testdata.MakeCRL(t, &testdata.CRL1, shouldBeGoodIDP, issuer, key)
	crl2der := testdata.MakeCRL(t, &testdata.CRL2, shouldBeGoodIDP, issuer, key)
	crl3der := testdata.MakeCRL(t, &testdata.CRL3, earlyRemovalIDP, issuer, key)
	crl4der := testdata.MakeCRL(t, &testdata.CRL4, earlyRemovalIDP, issuer, key)

	data := map[string][]storagemock.MockObject{
		shouldBeGood: {
			{
				VersionID: "the-current-version",
				Data:      crl2der,
			},
			{
				VersionID: "the-previous-version",
				Data:      crl1der,
			},
		},
		earlyRemoval: {
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

	checker := New(
		dbmock.NewMockedDB(t),
		storagemock.New(t, bucket, data),
		&fetcher,
		0,
		24*time.Hour,
		[]*x509.Certificate{issuer},
	)

	ctx := context.Background()

	// Watch the first revoked cert's serial
	serial := testdata.CRL1.RevokedCertificateEntries[0].SerialNumber
	require.NoError(t, checker.db.AddCert(ctx, &x509.Certificate{SerialNumber: serial}, testdata.Now))
	shouldNotBeSeen := big.NewInt(12345)
	require.NoError(t, checker.db.AddCert(ctx, &x509.Certificate{SerialNumber: shouldNotBeSeen}, testdata.Now))

	require.NoError(t, checker.Check(ctx, bucket, shouldBeGood, nil))

	// We should have seen the monitored cert but not the 12345 serial
	unseenCerts, err := checker.db.GetAllCerts(ctx)
	require.NoError(t, err)
	serialString := db.NewCertKey(shouldNotBeSeen).SerialString()
	require.Contains(t, unseenCerts, serialString)
	delete(unseenCerts, serialString)
	require.Empty(t, unseenCerts)

	// The "early-removal" object should error on a certificate removed early
	require.ErrorContains(t, checker.Check(ctx, bucket, earlyRemoval, nil), "early removal of 1 certificates detected!")
}

func Test_nameID(t *testing.T) {
	tests := []struct {
		issuerPath string
		want       string
	}{
		{
			issuerPath: "testdata/r3.pem",
			want:       "20506757847264211",
		},
		{
			issuerPath: "testdata/e1.pem",
			want:       "67430855296768143",
		},
		{
			issuerPath: "testdata/stg-r3.pem",
			want:       "58367272336442518",
		},
		{
			issuerPath: "testdata/stg-e1.pem",
			want:       "4169287449788112",
		},
	}
	for _, tt := range tests {
		t.Run(tt.issuerPath, func(t *testing.T) {
			issuer, err := core.LoadCert(tt.issuerPath)
			require.NoError(t, err)
			require.Equal(t, tt.want, nameID(issuer))
		})
	}
}
