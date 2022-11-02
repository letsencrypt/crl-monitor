package earlyremoval

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/letsencrypt/boulder/crl/crl_x509"
	"github.com/letsencrypt/crl-monitor/checker/expiry/mock"
)

func TestCheck(t *testing.T) {
	now := time.Now()

	mockFetcher := mock.Fetcher{}
	// Cert 1 expires between crl 1 and 2
	mockFetcher.AddTestData(big.NewInt(1), now.Add(30*time.Minute))
	// Cert 2 expires between crl 3 and 4
	cert2expiry := now.Add(3*time.Hour + 30*time.Minute)
	mockFetcher.AddTestData(big.NewInt(2), cert2expiry)

	// We have a series of CRLs for testing, starting with 3 serials
	crl1 := crl_x509.RevocationList{
		ThisUpdate: now,
		Number:     big.NewInt(1),
		RevokedCertificates: []crl_x509.RevokedCertificate{
			{SerialNumber: big.NewInt(1)},
			{SerialNumber: big.NewInt(2)},
			{SerialNumber: big.NewInt(3)},
		},
	}

	// CRL 2 is unchanged
	crl2 := crl_x509.RevocationList{
		ThisUpdate: now.Add(2 * time.Hour),
		Number:     big.NewInt(2),
		RevokedCertificates: []crl_x509.RevokedCertificate{
			{SerialNumber: big.NewInt(1)},
			{SerialNumber: big.NewInt(2)},
			{SerialNumber: big.NewInt(3)},
		},
	}

	// CRL 3 removes the first cert correctly: It was expired in CRL 2
	crl3 := crl_x509.RevocationList{
		ThisUpdate: now.Add(3 * time.Hour),
		Number:     big.NewInt(3),
		RevokedCertificates: []crl_x509.RevokedCertificate{
			{SerialNumber: big.NewInt(2)},
			{SerialNumber: big.NewInt(3)},
		},
	}

	// CRL 4 incorrectly removes serial 2, which has expired after CRL 3
	crl4 := crl_x509.RevocationList{
		ThisUpdate: now.Add(4 * time.Hour),
		Number:     big.NewInt(4),
		RevokedCertificates: []crl_x509.RevokedCertificate{
			{SerialNumber: big.NewInt(3)},
		},
	}

	// CRL 5 removes a cert our mock fetcher doesn't know about
	crl5 := crl_x509.RevocationList{
		ThisUpdate:          now.Add(5 * time.Hour),
		Number:              big.NewInt(5),
		RevokedCertificates: nil,
	}

	for _, tt := range []struct {
		name     string
		prev     *crl_x509.RevocationList
		crl      *crl_x509.RevocationList
		expected []EarlyRemoval
	}{
		{name: "no removals", prev: &crl1, crl: &crl2},
		{name: "remove 1", prev: &crl2, crl: &crl3},
		{
			name: "early removal",
			prev: &crl3,
			crl:  &crl4,
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
		{expectedError: "unknown serial 3", prev: &crl4, crl: &crl5},
		{expectedError: "old CRL does not precede new CRL", prev: &crl2, crl: &crl1},
	} {
		t.Run(tt.expectedError, func(t *testing.T) {
			early, err := Check(context.Background(), &mockFetcher, tt.prev, tt.crl)
			require.ErrorContains(t, err, tt.expectedError)
			require.Nil(t, early)
		})
	}
}
