package idp

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
)

var idpOID = asn1.ObjectIdentifier{2, 5, 29, 28} // id-ce-issuingDistributionPoint

// idpASN1 represents the ASN.1 IssuingDistributionPoint
// SEQUENCE as defined in RFC 5280 Section 5.2.5. We only care about DistributionPointName.
type idpASN1 struct {
	DistributionPoint distributionPointName `asn1:"optional,tag:0"`
}

// distributionPointName represents the ASN.1 DistributionPointName CHOICE as
// defined in RFC 5280 Section 4.2.1.13. We only use one of the fields, so the
// others are omitted.
type distributionPointName struct {
	// Technically, FullName is of type GeneralNames, which is of type SEQUENCE OF
	// GeneralName. But GeneralName itself is of type CHOICE, and the asn1.Marshal
	// function doesn't support marshalling structs to CHOICEs, so we have to use
	// asn1.RawValue.
	FullName []asn1.RawValue `asn1:"optional,tag:0"`
}

// GetIDP returns the single URL contained within the issuingDistributionPoint
// extension, if present, or an error otherwise.
func Get(crl *x509.RevocationList) (string, error) {
	var url string
	for _, ext := range crl.Extensions {
		if ext.Id.Equal(idpOID) {
			if url != "" {
				return "", errors.New("multiple IssuingDistributionPoint extensions in CRL")
			}
			var val idpASN1
			rest, err := asn1.Unmarshal(ext.Value, &val)
			if err != nil {
				return "", fmt.Errorf("parsing IssuingDistributionPoint extension: %w", err)
			}
			if len(rest) != 0 {
				return "", fmt.Errorf("parsing IssuingDistributionPoint extension: got %d unexpected trailing bytes", len(rest))
			}

			if len(val.DistributionPoint.FullName) != 1 {
				return "", fmt.Errorf("incorrect number of IssuingDistributionPoint URLs: %d", len(val.DistributionPoint.FullName))
			}
			url = string(val.DistributionPoint.FullName[0].Bytes)
		}
	}
	if url == "" {
		return "", errors.New("no IssuingDistributionPoint extension found")
	}
	return url, nil
}
