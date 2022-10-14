package db

import (
	"crypto/x509"
	"fmt"
	"time"
)

type Database struct {
}

func New() (*Database, error) {
	return nil, fmt.Errorf("not implemented")
}

// AddCert inserts the metadata for monitoring
func (db *Database) AddCert(certificate *x509.Certificate, revocationTime time.Time) error {
	// certificate.SerialNumber
	return nil
}
