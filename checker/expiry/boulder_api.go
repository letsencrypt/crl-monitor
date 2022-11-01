package expiry

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"time"
)

type BoulderAPIFetcher struct {
	Client  *http.Client
	BaseURL string
}

func (baf *BoulderAPIFetcher) FetchNotAfter(ctx context.Context, serial *big.Int) (time.Time, error) {
	// boulder implements non-acme-standard support for unauthenticated GETs of certificates
	url := fmt.Sprintf("%s/%036x", baf.BaseURL, serial)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return time.Time{}, err
	}
	req.Header.Set("User-Agent", "CRL-Monitor/0.1")

	log.Printf("fetching serial from %s", url)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return time.Time{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return time.Time{}, err
	}

	if resp.StatusCode != http.StatusOK {
		return time.Time{}, fmt.Errorf("error fetching certificate with serial %d: http status %d (%s)", serial, resp.StatusCode, string(body))
	}

	block, _ := pem.Decode(body)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}

	return cert.NotAfter, nil
}
