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

	require.NoError(t, handle.AddCert(ctx, &x509.Certificate{SerialNumber: big.NewInt(111)}, ts1))
	require.NoError(t, handle.AddCert(ctx, &x509.Certificate{SerialNumber: big.NewInt(444444)}, ts1))
	require.NoError(t, handle.AddCert(ctx, &x509.Certificate{SerialNumber: big.NewInt(606060)}, ts2))
	require.NoError(t, handle.AddCert(ctx, &x509.Certificate{SerialNumber: big.NewInt(123456)}, ts2))

	certs, err := handle.GetAllCerts(ctx)
	require.NoError(t, err)
	require.Len(t, certs, 4)

	var serials [][]byte
	for _, cert := range certs {
		if !bytes.Equal(cert.SerialNumber, big.NewInt(606060).Bytes()) {
			serials = append(serials, cert.SerialNumber)
		}
	}

	require.NoError(t, handle.DeleteSerials(ctx, serials))

	remaining, err := handle.GetAllCerts(ctx)
	require.NoError(t, err)
	expected := []db.CertMetadata{
		{CertKey: db.CertKey{SerialNumber: big.NewInt(606060).Bytes()},
			RevocationTime: ts2.Truncate(time.Second)},
	}
	require.Equal(t, expected, remaining)
}
