package db_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
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

	int111 := big.NewInt(111)
	int4s := big.NewInt(444444)
	int60s := big.NewInt(606060)
	int123 := big.NewInt(123456)

	// Insert 4 entries into the database with different serials and revocation times
	require.NoError(t, handle.AddCert(ctx, &x509.Certificate{SerialNumber: int111}, ts1))
	require.NoError(t, handle.AddCert(ctx, &x509.Certificate{SerialNumber: int4s}, ts1))
	require.NoError(t, handle.AddCert(ctx, &x509.Certificate{SerialNumber: int60s}, ts2))
	require.NoError(t, handle.AddCert(ctx, &x509.Certificate{SerialNumber: int123}, ts2))

	// Timestamps stored in Dynamo as unix timestamps are truncated to second precision
	ts1 = ts1.Truncate(time.Second)
	ts2 = ts2.Truncate(time.Second)

	certs, err := handle.GetAllCerts(ctx)
	require.NoError(t, err)
	require.Len(t, certs, 4)
	require.Equal(t, certs, map[string]db.CertMetadata{
		"00000000000000000000000000000000006f": {CertKey: db.CertKey{SerialNumber: int111.Bytes()}, RevocationTime: ts1},
		"00000000000000000000000000000006c81c": {CertKey: db.CertKey{SerialNumber: int4s.Bytes()}, RevocationTime: ts1},
		"000000000000000000000000000000093f6c": {CertKey: db.CertKey{SerialNumber: int60s.Bytes()}, RevocationTime: ts2},
		"00000000000000000000000000000001e240": {CertKey: db.CertKey{SerialNumber: int123.Bytes()}, RevocationTime: ts2},
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
		"000000000000000000000000000000093f6c": {CertKey: db.CertKey{SerialNumber: int60s.Bytes()}, RevocationTime: ts2},
	}
	require.Equal(t, expected, remaining)
}

func TestAddCertCRLDP(t *testing.T) {
	handle := mock.NewMockedDB(t)
	ctx := context.Background()

	revocationTime := time.Now().Add(100 * time.Hour)

	int111 := big.NewInt(111)
	int4s := big.NewInt(444444)
	int60s := big.NewInt(606060)

	err := handle.AddCert(ctx, &x509.Certificate{
		SerialNumber: int111,
	}, revocationTime)
	if err != nil {
		t.Errorf("inserting plain cert: %s", err)
	}

	err = handle.AddCert(ctx, &x509.Certificate{
		SerialNumber: int4s,
		CRLDistributionPoints: []string{
			"http://example.com/crl",
			"http://example.net/crl",
		},
	}, revocationTime)
	if err == nil {
		t.Errorf("inserting cert with two CRLDistributionPoints: got success, want error")
	}

	err = handle.AddCert(ctx, &x509.Certificate{
		SerialNumber: int60s,
		CRLDistributionPoints: []string{
			"http://example.com/crl",
		},
	}, revocationTime)
	if err != nil {
		t.Errorf("inserting cert with one CRLDistributionPoint: %s", err)
	}

	results, err := handle.GetAllCerts(ctx)
	if err != nil {
		t.Fatalf("getting all certs: %s", err)
	}

	serialString := fmt.Sprintf("%036x", int60s)
	metadata, ok := results[serialString]
	if !ok {
		t.Errorf("getting all certs: expected entry for %s, got %+v", serialString, metadata)
	}

	if metadata.CRLDistributionPoint != "http://example.com/crl" {
		t.Errorf("CRL for %s = %q, want %q", serialString, metadata.CRLDistributionPoint, "http://example.com/crl")
	}
}
