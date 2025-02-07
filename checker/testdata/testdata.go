package testdata

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var Now = time.Now()

// CRL1 is the start of a series of CRLs for testing, starting with 3 serials
var CRL1 = x509.RevocationList{
	ThisUpdate: Now,
	NextUpdate: Now.Add(24 * time.Hour),
	Number:     big.NewInt(1),
	RevokedCertificateEntries: []x509.RevocationListEntry{
		{SerialNumber: big.NewInt(1), RevocationTime: Now},
		{SerialNumber: big.NewInt(2), RevocationTime: Now},
		{SerialNumber: big.NewInt(3), RevocationTime: Now},
	},
}

// CRL2 has the same 3 serials as CRL1
var CRL2 = x509.RevocationList{
	ThisUpdate: Now.Add(2 * time.Hour),
	NextUpdate: Now.Add(24 * time.Hour),
	Number:     big.NewInt(2),
	RevokedCertificateEntries: []x509.RevocationListEntry{
		{SerialNumber: big.NewInt(1), RevocationTime: Now},
		{SerialNumber: big.NewInt(2), RevocationTime: Now},
		{SerialNumber: big.NewInt(3), RevocationTime: Now},
	},
}

// CRL3 removes the first cert correctly: It was expired in CRL 2
var CRL3 = x509.RevocationList{
	ThisUpdate: Now.Add(3 * time.Hour),
	NextUpdate: Now.Add(24 * time.Hour),
	Number:     big.NewInt(3),
	RevokedCertificateEntries: []x509.RevocationListEntry{
		{SerialNumber: big.NewInt(2), RevocationTime: Now},
		{SerialNumber: big.NewInt(3), RevocationTime: Now},
	},
}

// CRL4 incorrectly removes serial 2, which has expired after CRL 3
var CRL4 = x509.RevocationList{
	ThisUpdate: Now.Add(4 * time.Hour),
	NextUpdate: Now.Add(24 * time.Hour),
	Number:     big.NewInt(4),
	RevokedCertificateEntries: []x509.RevocationListEntry{
		{SerialNumber: big.NewInt(3), RevocationTime: Now},
	},
}

// CRL5 removes a cert our mock fetcher doesn't know about
var CRL5 = x509.RevocationList{
	ThisUpdate:                Now.Add(5 * time.Hour),
	NextUpdate:                Now.Add(24 * time.Hour),
	Number:                    big.NewInt(5),
	RevokedCertificateEntries: nil,
}

// CRL6 contains serial 4213, which will have a CRLDistributionPoint
// that doesn't match the CRL.
var CRL6 = x509.RevocationList{
	ThisUpdate: Now.Add(4 * time.Hour),
	NextUpdate: Now.Add(24 * time.Hour),
	Number:     big.NewInt(1),
	RevokedCertificateEntries: []x509.RevocationListEntry{
		{SerialNumber: big.NewInt(4213), RevocationTime: Now},
	},
}

// CRL7 also contains serial 4213, which will have a CRLDistributionPoint
// that doesn't match the CRL.
var CRL7 = x509.RevocationList{
	ThisUpdate: Now.Add(5 * time.Hour),
	NextUpdate: Now.Add(25 * time.Hour),
	Number:     big.NewInt(2),
	RevokedCertificateEntries: []x509.RevocationListEntry{
		{SerialNumber: big.NewInt(4213), RevocationTime: Now},
	},
}

func MakeIssuer(t *testing.T) (*x509.Certificate, crypto.Signer) {
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

	return cert, key
}

// MakeCRL takes a revocation list and issuer to sign it.  It returns a DER encoded CRL.
func MakeCRL(t *testing.T, input *x509.RevocationList, idp string, issuer *x509.Certificate, key crypto.Signer) []byte {
	ext, err := makeIDPExt(idp)
	require.NoError(t, err)

	input.ExtraExtensions = append(input.ExtraExtensions, *ext)
	der, err := x509.CreateRevocationList(rand.Reader, input, issuer, key)
	require.NoError(t, err)
	return der
}

// makeIDPExt was lifted out of Boulder
func makeIDPExt(issuingDistributionPoint string) (*pkix.Extension, error) {
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
					Bytes: []byte(issuingDistributionPoint),
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
