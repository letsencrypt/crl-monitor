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
	BaseURL string
}

// FetchNotAfter downloads a certificate, parses it, and returns the NotAfter on
// it. It uses a non-acme path to download a certificate unauthenticated by
// serial. So it is specific to Boulder's API, not a generic ACME API client.
func (baf *BoulderAPIFetcher) FetchNotAfter(ctx context.Context, serial *big.Int) (time.Time, error) {
	// The baseURL is followed by a hex-encoded serial
	url := fmt.Sprintf("%s/%s", baf.BaseURL, formatSerial(serial))

	body, err := retryhttp.Get(ctx, url)
	if err != nil {
		return time.Time{}, fmt.Errorf("fetching NotAfter for serial %s: %w", formatSerial(serial), err)
	}

	block, _ := pem.Decode(body)
	if block == nil {
		return time.Time{}, fmt.Errorf("parsing PEM for serial %s: %s", formatSerial(serial), string(body))
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("parsing certificate for serial %s: %s", formatSerial(serial), err)
	}

	return cert.NotAfter, nil
}

func formatSerial(serial *big.Int) string {
	return fmt.Sprintf("%036x", serial)
}
