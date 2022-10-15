package db_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/letsencrypt/crl-monitor/db/mock"
)

func TestAPI(t *testing.T) {
	db := mock.NewMockedDB(t)
	ctx := context.Background()

	require.NoError(t, db.AddCert(ctx, &x509.Certificate{SerialNumber: big.NewInt(111)}, time.Now()))
	require.NoError(t, db.AddCert(ctx, &x509.Certificate{SerialNumber: big.NewInt(444444)}, time.Now()))
	require.NoError(t, db.AddCert(ctx, &x509.Certificate{SerialNumber: big.NewInt(606060)}, time.Now()))
	require.NoError(t, db.AddCert(ctx, &x509.Certificate{SerialNumber: big.NewInt(123456)}, time.Now()))

	certs, err := db.GetAllCerts(ctx)
	require.NoError(t, err)
	require.Len(t, certs, 4)

	var serials [][]byte
	for _, cert := range certs {
		if !bytes.Equal(cert.SerialNumber, big.NewInt(606060).Bytes()) {
			serials = append(serials, cert.SerialNumber)
		}
	}

	require.NoError(t, db.DeleteSerials(ctx, serials))

	empty, err := db.GetAllCerts(ctx)
	require.NoError(t, err)
	require.Len(t, empty, 1)
}
