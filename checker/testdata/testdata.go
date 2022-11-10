package testdata

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/letsencrypt/boulder/crl/crl_x509"
	"github.com/letsencrypt/boulder/issuance"
)

var Now = time.Now()

// CRL1 is the start of a series of CRLs for testing, starting with 3 serials
var CRL1 = crl_x509.RevocationList{
	ThisUpdate: Now,
	NextUpdate: Now.Add(24 * time.Hour),
	Number:     big.NewInt(1),
	RevokedCertificates: []crl_x509.RevokedCertificate{
		{SerialNumber: big.NewInt(1), RevocationTime: Now},
		{SerialNumber: big.NewInt(2), RevocationTime: Now},
		{SerialNumber: big.NewInt(3), RevocationTime: Now},
	},
}

// CRL2 has the same 3 serials as CRL1
var CRL2 = crl_x509.RevocationList{
	ThisUpdate: Now.Add(2 * time.Hour),
	NextUpdate: Now.Add(24 * time.Hour),
	Number:     big.NewInt(2),
	RevokedCertificates: []crl_x509.RevokedCertificate{
		{SerialNumber: big.NewInt(1), RevocationTime: Now},
		{SerialNumber: big.NewInt(2), RevocationTime: Now},
		{SerialNumber: big.NewInt(3), RevocationTime: Now},
	},
}

// CRL3 removes the first cert correctly: It was expired in CRL 2
var CRL3 = crl_x509.RevocationList{
	ThisUpdate: Now.Add(3 * time.Hour),
	NextUpdate: Now.Add(24 * time.Hour),
	Number:     big.NewInt(3),
	RevokedCertificates: []crl_x509.RevokedCertificate{
		{SerialNumber: big.NewInt(2), RevocationTime: Now},
		{SerialNumber: big.NewInt(3), RevocationTime: Now},
	},
}

// CRL4 incorrectly removes serial 2, which has expired after CRL 3
var CRL4 = crl_x509.RevocationList{
	ThisUpdate: Now.Add(4 * time.Hour),
	NextUpdate: Now.Add(24 * time.Hour),
	Number:     big.NewInt(4),
	RevokedCertificates: []crl_x509.RevokedCertificate{
		{SerialNumber: big.NewInt(3), RevocationTime: Now},
	},
}

// CRL5 removes a cert our mock fetcher doesn't know about
var CRL5 = crl_x509.RevocationList{
	ThisUpdate:          Now.Add(5 * time.Hour),
	NextUpdate:          Now.Add(24 * time.Hour),
	Number:              big.NewInt(5),
	RevokedCertificates: nil,
}

func MakeIssuer(t *testing.T) (*issuance.Certificate, crypto.Signer) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "test-issuer"},
		SerialNumber:          big.NewInt(123434235),
		KeyUsage:              x509.KeyUsageCRLSign,
		SubjectKeyId:          []byte{1, 2, 3},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	issuer, err := issuance.NewCertificate(cert)
	require.NoError(t, err)

	return issuer, key
}

// MakeCRL takes a revocation list and returns a DER encoded CRL along with the issuance.Certificate that signed it
func MakeCRL(t *testing.T, input *crl_x509.RevocationList, issuer *issuance.Certificate, key crypto.Signer) []byte {
	ext, err := makeIDPExt("http://dp/", issuer.NameID(), 0)
	require.NoError(t, err)

	input.ExtraExtensions = append(input.ExtraExtensions, *ext)
	der, err := crl_x509.CreateRevocationList(rand.Reader, input, issuer.Certificate, key)
	require.NoError(t, err)
	return der
}

// makeIDPExt was lifted out of Boulder
func makeIDPExt(base string, issuer issuance.IssuerNameID, shardIdx int64) (*pkix.Extension, error) {
	type distributionPointName struct {
		FullName []asn1.RawValue `asn1:"optional,tag:0"`
	}
	val := struct {
		DistributionPoint     distributionPointName `asn1:"optional,tag:0"`
		OnlyContainsUserCerts bool                  `asn1:"optional,tag:1"`
	}{
		DistributionPoint: distributionPointName{
			[]asn1.RawValue{ // GeneralNames
				{ // GeneralName
					Class: 2, // context-specific
					Tag:   6, // uniformResourceIdentifier, IA5String
					Bytes: []byte(fmt.Sprintf("%s/%d/%d.crl", base, issuer, shardIdx)),
				},
			},
		},
		OnlyContainsUserCerts: true,
	}

	valBytes, err := asn1.Marshal(val)
	if err != nil {
		return nil, err
	}

	return &pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 28}, // id-ce-issuingDistributionPoint
		Value:    valBytes,
		Critical: true,
	}, nil
}
