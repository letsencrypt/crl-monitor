package expiry

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/letsencrypt/crl-monitor/retryhttp"
)

type BoulderAPIFetcher struct {
	Client  *retryhttp.Client
	BaseURL string
}

// FetchNotAfter downloads a certificate, parses it, and returns the NotAfter on
// it. It uses a non-acme path to download a certificate unauthenticated by
// serial. So it is specific to Boulder's API, not a generic ACME API client.
func (baf *BoulderAPIFetcher) FetchNotAfter(ctx context.Context, serial *big.Int) (time.Time, error) {
	// The baseURL is followed by a hex-encoded serial
	url := fmt.Sprintf("%s/%036x", baf.BaseURL, serial)

	body, err := baf.Client.GetWithRetries(ctx, url)
	if err != nil {
		return time.Time{}, fmt.Errorf("error fetching NotAfter for serial %d: %w", serial, err)
	}

	block, _ := pem.Decode(body)
	if block == nil {
		return time.Time{}, fmt.Errorf("error parsing PEM for serial %d: %s", serial, string(body))
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("error parsing certificate for serial %d: %w", serial, err)
	}

	return cert.NotAfter, nil
}
