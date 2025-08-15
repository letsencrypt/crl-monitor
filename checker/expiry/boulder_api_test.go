package expiry

import (
	"context"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBoulderAPIFetcher(t *testing.T) {
	serialhex := "04bc17a64a2c415af9ba4df32b73bf4e08e7"
	somePrefix := "/get/some/path/cert"

	flaked := false
	testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		// Make sure we can handle intermittent errors
		if !flaked {
			flaked = true
			res.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		require.Equal(t, somePrefix+"/"+serialhex, req.URL.Path)
		res.Write([]byte(`{
  "notAfter": "2025-11-02T11:24:03Z"
}`))
	}))

	fetcher := BoulderAPIFetcher{BaseURL: testServer.URL + somePrefix}

	serial := new(big.Int)
	serial.SetString(serialhex, 16)
	expected := time.Date(2025, 11, 02, 11, 24, 03, 00, time.UTC)

	notAfter, err := fetcher.FetchNotAfter(context.Background(), serial)
	require.NoError(t, err)
	require.Equal(t, expected, notAfter)
}
