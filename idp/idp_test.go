package idp

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestGet(t *testing.T) {
	crlPEM := `-----BEGIN X509 CRL-----
MIIB5zCB0AIBATANBgkqhkiG9w0BAQsFADAyMQswCQYDVQQGEwJVUzEWMBQGA1UE
ChMNTGV0J3MgRW5jcnlwdDELMAkGA1UEAxMCUjMXDTI1MDMwNTIyNDQ0MFoXDTI1
MDMxNDIyNDQzOVqgajBoMB8GA1UdIwQYMBaAFBQusxe3WFbLrlAJQOYfr52LFMLG
MBEGA1UdFAQKAggYKgmGvjobBTAyBgNVHRwBAf8EKDAmoCGgH4YdaHR0cDovL3Iz
LmMubGVuY3Iub3JnLzEwNS5jcmyBAf8wDQYJKoZIhvcNAQELBQADggEBAEiuzZV0
mH/ZYJCQ+0yH0GqkVeAS3sXNAbTh73P2sxehfjBD+c8/UtBX9QfUCdt/2BhgjnWU
oXBH0Egi9SFDaqEP/5cnRFZIMb3SIIW9O8ukW5RVYrSSH5cN8q0oA958ACnqfPE2
mGmEk8fTcOhKD0gint+NRZMuPs2MYfhPimUmR28vWyOSVm7Gnu62Roa625BK+vSs
D5gW7s9jgLTO/PTmZMIf3qD+5ZCZMbP1sgcgF5L3fvTgRawdwU33p3D3xPd55VK7
zfcmGyL+F1x+tWPEPeKm8l2Oya1dZK9z6J0tQIPz/IgQh0+zoHnbdAgfZ1MD86Te
3RXFZ/P2MpuSww8=
-----END X509 CRL-----
	`

	block, _ := pem.Decode([]byte(crlPEM))
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	want := "http://r3.c.lencr.org/105.crl"
	got, err := Get(crl)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("Get()=%s, want %s", got, want)
	}
}
