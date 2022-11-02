package expiry

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"
)

type BoulderAPIFetcher struct {
	Client  *http.Client
	BaseURL string
}

func (baf *BoulderAPIFetcher) getBody(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "CRL-Monitor/0.1")
	resp, err := baf.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http status %d (%s)", resp.StatusCode, string(body))
	}

	return body, nil
}

// getWithRetries is a simple wrapper around client.Do that will retry on a fixed backoff schedule
func (baf *BoulderAPIFetcher) getWithRetries(ctx context.Context, url string) ([]byte, error) {
	// A fixed sequence of retries. We start with 0 seconds, retrying
	// immediately, and increase a few seconds between each retry. The final
	// value is zero so that we don't sleep before returning the final error.
	var err error
	for _, backoff := range []int{0, 1, 1, 2, 3, 0} {
		var body []byte
		body, err = baf.getBody(ctx, url)
		if err == nil {
			return body, nil
		}
		time.Sleep(time.Duration(backoff) * time.Second)
	}
	return nil, err
}

// FetchNotAfter downloads a certificate, parses it, and returns the NotAfter on
// it. It uses a non-acme path to download a certificate unauthenticated by
// serial. So it is specific to Boulder's API, not a generic ACME API client.
func (baf *BoulderAPIFetcher) FetchNotAfter(ctx context.Context, serial *big.Int) (time.Time, error) {
	// The baseURL is followed by a hex-encoded serial
	url := fmt.Sprintf("%s/%036x", baf.BaseURL, serial)

	body, err := baf.getWithRetries(ctx, url)
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
