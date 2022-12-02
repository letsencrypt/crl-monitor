package churner

import (
	"context"
	"crypto/x509"
	"math/big"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/letsencrypt/crl-monitor/db"
	"github.com/letsencrypt/crl-monitor/db/mock"
)

func TestRandDomains(t *testing.T) {
	base := "revoked.invalid"
	domains := randDomains(base)
	require.Len(t, domains, 1)
	require.Regexp(t, regexp.MustCompile(`r[0-9]{10}z[0-9a-f]{4}\.`+regexp.QuoteMeta(base)), domains[0])

	second := randDomains(base)
	require.NotEqual(t, domains, second, "Domains should be different each invocation")
}

func TestCheckMissing(t *testing.T) {
	now := time.Now()
	ctx := context.Background()

	churner := Churner{db: mock.NewMockedDB(t), cutoff: now.Add(-24 * time.Hour)}

	sn1 := big.NewInt(1111111)
	sn2 := big.NewInt(2022)

	yesterday := now.Add(-25 * time.Hour)

	require.NoError(t, churner.db.AddCert(ctx, &x509.Certificate{SerialNumber: sn1}, yesterday))
	require.NoError(t, churner.db.AddCert(ctx, &x509.Certificate{SerialNumber: sn2}, now))

	missing, err := churner.CheckMissing(ctx)
	require.NoError(t, err)

	// We should get back sn1 only, which was revoked more than 24 hours ago
	require.Equal(t, []db.CertMetadata{{
		CertKey:        db.CertKey{SerialNumber: sn1.Bytes()},
		RevocationTime: yesterday.Truncate(time.Second),
	}}, missing)
}
