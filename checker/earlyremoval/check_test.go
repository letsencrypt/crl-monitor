package earlyremoval

import (
	"context"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const testCert = `
-----BEGIN CERTIFICATE-----
MIIFOjCCBCKgAwIBAgISBLwXpkosQVr5uk3zK3O/TgjnMA0GCSqGSIb3DQEBCwUA
MDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQD
EwJSMzAeFw0yMjA5MDYxNzM1NTFaFw0yMjEyMDUxNzM1NTBaMCUxIzAhBgNVBAMT
GmhlbGxvd29ybGQubGV0c2VuY3J5cHQub3JnMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAxqLTej52kNQ0e3nYgNqsuqS51W6PqwpgNXSJeBLAhuQrQ8YH
uiR1kLuoVN6Q8IAsXoxZO1nntkT68qGeOXv/Q7uzF1CYUW0pRY3b4CUsuJ8FVja3
mh7GlkeulOa9CDHar7yv3BG/B8X7j0kB7J/XYRVfFbPvpXlY69J4lcZw1L7yh/dp
kbSikh+IGrOpv8c6LnCiX0QfCpIeUvBtkQbGU8R3xT4AdLHhYLRQlGdyRP+QWV8L
Puvw+p43FKzOrbfj73oqXqTBlqN09Flncs2pMJ/mvF1CQswSmgqXfO3dbekFUxWl
YgPBeAw3jvGUIOLPDnnRXGBHnzXS6TyaWpSNoQIDAQABo4ICVTCCAlEwDgYDVR0P
AQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMB
Af8EAjAAMB0GA1UdDgQWBBRHhB/d+marXtrMYKM1/SmaPpWmkTAfBgNVHSMEGDAW
gBQULrMXt1hWy65QCUDmH6+dixTCxjBVBggrBgEFBQcBAQRJMEcwIQYIKwYBBQUH
MAGGFWh0dHA6Ly9yMy5vLmxlbmNyLm9yZzAiBggrBgEFBQcwAoYWaHR0cDovL3Iz
LmkubGVuY3Iub3JnLzAlBgNVHREEHjAcghpoZWxsb3dvcmxkLmxldHNlbmNyeXB0
Lm9yZzBMBgNVHSAERTBDMAgGBmeBDAECATA3BgsrBgEEAYLfEwEBATAoMCYGCCsG
AQUFBwIBFhpodHRwOi8vY3BzLmxldHNlbmNyeXB0Lm9yZzCCAQQGCisGAQQB1nkC
BAIEgfUEgfIA8AB3AEHIyrHfIkZKEMahOglCh15OMYsbA+vrS8do8JBilgb2AAAB
gxQWVpAAAAQDAEgwRgIhALiy1ePIYcsa4DzvYJxA4ESapomXf2TBXKXUHAKu/pYR
AiEAsWSUCtj4qyemteY2ZRtY6WX/ajG9gcwAIXT8eNeTw6wAdQApeb7wnjk5IfBW
c59jpXflvld9nGAK+PlNXSZcJV3HhAAAAYMUFlZ4AAAEAwBGMEQCICOOrxHLAYP9
enjNedrQlBYQcGC4X+6zHuM9aZIEeaGXAiBfQx7U7JMWW/9wOps16OryBHoYwKyu
xWBrwcUqCE7o4jANBgkqhkiG9w0BAQsFAAOCAQEAFIfzscbUxJtncoKRBSt9Fh99
J1Ur8KrG4Yi6f+7qS93Vn2D8W3ERb9n5d+itvPLqazUDD4OqMrTWyKj1ySOtKeZL
QEj+CyV9in6meSw7GJi/s12GMTet4rhdf9HALU6ZqGngA87uViMfyoiHph2ZFI1X
TJ/g1eaQHpI2ZqtZeD/yH6+iZtWtYF+WBDlw+gRzGBkFTy+gR7bs1XVVcfhC1BkF
6OEF59dHg6mmedRU331NPZxZo2kgmbeUWAyREN7vtDPUwXHicp4NEVTyTxnaWT+9
+j5SXuiCDC+DyDEXSfmO0ICCmpShuMyHY4eaBE82kvGA5LtS0TDTaISxokHOGg==
-----END CERTIFICATE-----
`

func TestBoulderAPIFetcher(t *testing.T) {
	serialhex := "04bc17a64a2c415af9ba4df32b73bf4e08e7"

	testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		require.Equal(t, "/acme/cert/"+serialhex, req.URL.Path)
		res.Write([]byte(testCert))
	}))

	fetcher := BoulderAPIFetcher{BaseURL: testServer.URL + "/acme/cert", Client: http.DefaultClient}

	serial := new(big.Int)
	serial.SetString(serialhex, 16)
	expected := time.Date(2022, 12, 05, 17, 35, 50, 00, time.UTC)

	notAfter, err := fetcher.FetchNotAfter(context.Background(), serial)
	require.NoError(t, err)
	require.Equal(t, expected, notAfter)
}
