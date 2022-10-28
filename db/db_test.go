package db_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/letsencrypt/crl-monitor/db"
	"github.com/letsencrypt/crl-monitor/db/mock"
)

func TestDatabaseWithMock(t *testing.T) {
	smoketest(t, mock.NewMockedDB(t))
}

// smoketest goes through a set of basic actions ensuring the basics work
// It gets run with a mocked database and can also be integration tested against
// the real DynamoDB, or the downloadable version, to ensure they align.
func smoketest(t *testing.T, handle *db.Database) {
	ctx := context.Background()

	ts1 := time.Now()
	ts2 := time.Now().Add(100 * time.Hour)
	ts3 := time.Now().Add(250 * time.Hour)

	int111 := big.NewInt(111)
	int4s := big.NewInt(444444)
	int60s := big.NewInt(606060)
	int123 := big.NewInt(123456)

	// Insert 4 entries into the database with different serials and revocation times
	require.NoError(t, handle.AddCert(ctx, &x509.Certificate{SerialNumber: int111, NotAfter: ts3}, ts1))
	require.NoError(t, handle.AddCert(ctx, &x509.Certificate{SerialNumber: int4s, NotAfter: ts2}, ts1))
	require.NoError(t, handle.AddCert(ctx, &x509.Certificate{SerialNumber: int60s, NotAfter: ts3}, ts2))
	require.NoError(t, handle.AddCert(ctx, &x509.Certificate{SerialNumber: int123, NotAfter: ts1}, ts2))

	// Timestamps stored in Dynamo as unix timestamps are truncated to second precision
	ts1 = ts1.Truncate(time.Second)
	ts2 = ts2.Truncate(time.Second)
	ts3 = ts3.Truncate(time.Second)

	certs, err := handle.GetAllCerts(ctx)
	require.NoError(t, err)
	require.Len(t, certs, 4)
	require.Equal(t, certs, map[string]db.CertMetadata{
		"00000000000000000000000000000000006f": {CertKey: db.CertKey{SerialNumber: int111.Bytes()}, NotAfter: ts3, RevocationTime: ts1},
		"00000000000000000000000000000006c81c": {CertKey: db.CertKey{SerialNumber: int4s.Bytes()}, NotAfter: ts2, RevocationTime: ts1},
		"000000000000000000000000000000093f6c": {CertKey: db.CertKey{SerialNumber: int60s.Bytes()}, NotAfter: ts3, RevocationTime: ts2},
		"00000000000000000000000000000001e240": {CertKey: db.CertKey{SerialNumber: int123.Bytes()}, NotAfter: ts1, RevocationTime: ts2},
	})

	// Delete all the serials other than the 606060 serial
	var serials [][]byte
	for _, cert := range certs {
		if !bytes.Equal(cert.SerialNumber, int60s.Bytes()) {
			serials = append(serials, cert.SerialNumber)
		}
	}
	require.NoError(t, handle.DeleteSerials(ctx, serials))

	// The only remaining entry should be the serial 606060 one
	remaining, err := handle.GetAllCerts(ctx)
	require.NoError(t, err)
	expected := map[string]db.CertMetadata{
		"000000000000000000000000000000093f6c": {CertKey: db.CertKey{SerialNumber: int60s.Bytes()}, NotAfter: ts3, RevocationTime: ts2},
	}
	require.Equal(t, expected, remaining)
}
