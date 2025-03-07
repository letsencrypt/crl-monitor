package retryhttp

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

func getBody(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "CRL-Monitor/0.1")
	resp, err := http.DefaultClient.Do(req)
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

// Get is a simple wrapper around http.Client.Do that will retry on a fixed backoff schedule
func Get(ctx context.Context, url string) ([]byte, error) {
	// A fixed sequence of retries. We start with 0 seconds, retrying
	// immediately, and increase a few seconds between each retry. The final
	// value is zero so that we don't sleep before returning the final error.
	var err error
	for _, backoff := range []int{0, 1, 1, 2, 3, 0} {
		var body []byte
		body, err = getBody(ctx, url)
		if err == nil {
			return body, nil
		}
		time.Sleep(time.Duration(backoff) * time.Second)
	}
	return nil, err
}
