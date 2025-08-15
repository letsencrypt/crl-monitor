package expiry

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
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
	url, err := url.JoinPath(baf.BaseURL, formatSerial(serial))
	if err != nil {
		return time.Time{}, fmt.Errorf("determining boulder URL for serial %s: %w", formatSerial(serial), err)
	}

	body, err := retryhttp.Get(ctx, url)
	if err != nil {
		return time.Time{}, fmt.Errorf("fetching NotAfter for serial %s: %w", formatSerial(serial), err)
	}

	certinfo := struct {
		NotAfter time.Time `json:"notAfter"`
	}{}
	if err := json.Unmarshal(body, &certinfo); err != nil {
		return time.Time{}, fmt.Errorf("deserializing json certinfo for serial %s: %s", formatSerial(serial), string(body))
	}

	return certinfo.NotAfter, nil
}

func formatSerial(serial *big.Int) string {
	return fmt.Sprintf("%036x", serial)
}
