//go:build integration

package earlyremoval

import (
	"context"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// This test hits the real boulder staging API!
// It is behind the integration flag as a result.
func TestBoulderStagingAPI(t *testing.T) {
	baseURL := "https://acme-staging-v02.api.letsencrypt.org/get/cert"
	baf := BoulderAPIFetcher{Client: http.DefaultClient, BaseURL: baseURL}

	// TODO:  This is a hardcoded serial and expiry combo.
	// It may not stay available in boulder's API forever
	serial := new(big.Int)
	serial.SetString("fad21382e31f8218bc798416cea008da6940", 16)
	expected := time.Date(2023, 01, 24, 12, 49, 02, 00, time.UTC)
	notAfter, err := baf.FetchNotAfter(context.Background(), serial)
	require.NoError(t, err)
	require.Equal(t, expected, notAfter)
}

func TestBoulderProductionAPI(t *testing.T) {
	baseURL := "https://acme-v02.api.letsencrypt.org/get/cert"
	baf := BoulderAPIFetcher{Client: http.DefaultClient, BaseURL: baseURL}

	// TODO:  This is a hardcoded serial and expiry combo.
	// It may not stay available in boulder's API forever
	serial := new(big.Int)
	serial.SetString("04bc17a64a2c415af9ba4df32b73bf4e08e7", 16)
	expected := time.Date(2022, 12, 05, 17, 35, 50, 00, time.UTC)
	notAfter, err := baf.FetchNotAfter(context.Background(), serial)
	require.NoError(t, err)
	require.Equal(t, expected, notAfter)
}
