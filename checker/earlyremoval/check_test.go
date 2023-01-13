package earlyremoval

import (
	"context"
	"math/big"
	"math/rand"
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
			early, err := Check(context.Background(), &mockFetcher, 500, tt.prev, tt.crl)
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
			early, err := Check(context.Background(), &mockFetcher, 500, tt.prev, tt.crl)
			require.ErrorContains(t, err, tt.expectedError)
			require.Nil(t, early)
		})
	}
}

func TestSample(t *testing.T) {
	require.Empty(t, sample([]int{}, 0))
	require.Empty(t, sample([]int{}, 999))

	var data []int
	// Generate a random array for tests.  Insecure RNG is fine.
	// #nosec G404
	length := 100 + rand.Intn(300)
	for i := 0; i < length; i++ {
		data = append(data, i)
	}

	t.Run("all elements", func(t *testing.T) {
		// if max == len, the data should be returned
		require.ElementsMatch(t, data, sample(data, len(data)))
	})

	t.Run("small data", func(t *testing.T) {
		sampled := sample(data, 100)
		// First and last 10% should be from the original data:
		require.Equal(t, []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, sampled[:10])
		require.Equal(t, data[len(data)-10:], sampled[90:])

		// The middle elements should all be from the middle of the data array
		for _, v := range sampled[10:90] {
			require.LessOrEqual(t, 10, v)
			require.LessOrEqual(t, v, len(data)-10)
		}
	})

	t.Run("various lengths", func(t *testing.T) {
		for dataLen := 0; dataLen <= len(data); dataLen++ {
			for max := 1; max <= dataLen; max++ {
				sampled := sample(data[:dataLen], max)
				require.Len(t, sampled, max, "datalen %d max %d", dataLen, max)
			}
		}
	})
}
