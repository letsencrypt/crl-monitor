//go:build integration

package expiry

import (
	"context"
	"fmt"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// This test hits the real boulder staging API!
// It is behind the integration flag as a result.
func TestBoulderAPI(t *testing.T) {
	// TODO: These integration tests hardcode certificates that we fetch from Boulder's API
	// They may not stay available in boulder's API forever.
	for _, tc := range []struct {
		subdomain string
		serial    string
		expected  time.Time
	}{
		{
			subdomain: "acme-staging-v02",
			serial:    "fad21382e31f8218bc798416cea008da6940",
			expected:  time.Date(2023, 01, 24, 12, 49, 02, 00, time.UTC),
		},
		{
			subdomain: "acme-v02",
			serial:    "04bc17a64a2c415af9ba4df32b73bf4e08e7",
			expected:  time.Date(2022, 12, 05, 17, 35, 50, 00, time.UTC),
		},
	} {
		t.Run(tc.subdomain, func(t *testing.T) {
			baseURL := fmt.Sprintf("https://%s.api.letsencrypt.org/get/cert", tc.subdomain)
			baf := BoulderAPIFetcher{Client: http.DefaultClient, BaseURL: baseURL}

			serial := new(big.Int)
			serial.SetString(tc.serial, 16)
			notAfter, err := baf.FetchNotAfter(context.Background(), serial)
			require.NoError(t, err)
			require.Equal(t, tc.expected, notAfter)
		})
	}
}
