package earlyremoval

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/letsencrypt/boulder/crl/crl_x509"
	"github.com/letsencrypt/crl-monitor/checker/expiry/mock"
	"github.com/letsencrypt/crl-monitor/checker/testdata"
)

func TestCheck(t *testing.T) {
	now := time.Now()

	mockFetcher := mock.Fetcher{}
	// Cert 1 expires between crl 1 and 2
	mockFetcher.AddTestData(big.NewInt(1), now.Add(30*time.Minute))
	// Cert 2 expires between crl 3 and 4
	cert2expiry := now.Add(3*time.Hour + 30*time.Minute)
	mockFetcher.AddTestData(big.NewInt(2), cert2expiry)

	for _, tt := range []struct {
		name     string
		prev     *crl_x509.RevocationList
		crl      *crl_x509.RevocationList
		expected []EarlyRemoval
	}{
		{name: "no removals", prev: &testdata.CRL1, crl: &testdata.CRL2},
		{name: "remove 1", prev: &testdata.CRL2, crl: &testdata.CRL3},
		{
			name: "early removal",
			prev: &testdata.CRL3,
			crl:  &testdata.CRL4,
			expected: []EarlyRemoval{
				{Serial: big.NewInt(2), NotAfter: cert2expiry},
			}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			early, err := Check(context.Background(), &mockFetcher, tt.prev, tt.crl)
			require.NoError(t, err)
			require.Equal(t, tt.expected, early)
		})
	}

	for _, tt := range []struct {
		expectedError string
		prev          *crl_x509.RevocationList
		crl           *crl_x509.RevocationList
	}{
		{expectedError: "unknown serial 3", prev: &testdata.CRL4, crl: &testdata.CRL5},
		{expectedError: "old CRL does not precede new CRL", prev: &testdata.CRL2, crl: &testdata.CRL1},
	} {
		t.Run(tt.expectedError, func(t *testing.T) {
			early, err := Check(context.Background(), &mockFetcher, tt.prev, tt.crl)
			require.ErrorContains(t, err, tt.expectedError)
			require.Nil(t, early)
		})
	}
}
