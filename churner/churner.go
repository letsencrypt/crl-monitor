package churner

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"time"

	"github.com/mholt/acmez"
	"github.com/mholt/acmez/acme"

	"github.com/letsencrypt/crl-monitor/db"
)

type Churner struct {
	baseDomain  string
	acmeClient  acmez.Client
	acmeAccount acme.Account
	db          *db.Database
}

func New(baseDomain string, acmeClient acmez.Client, acmeAccount acme.Account, db *db.Database) (*Churner, error) {
	return &Churner{
		baseDomain:  baseDomain,
		acmeClient:  acmeClient,
		acmeAccount: acmeAccount,
		db:          db,
	}, nil
}

// Churn issues a certificate, revokes it, and stores the result in DynamoDB
func (c *Churner) Churn(ctx context.Context) error {

	// Generate either an ecdsa or rsa private key
	certPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	certificates, err := c.acmeClient.ObtainCertificate(ctx, c.acmeAccount, certPrivateKey, c.RandDomains())
	if err != nil {
		return err
	}

	// certificates contains all the possible cert chains.  We only care about
	// the cert, so we just take the first one and parse it.
	firstChain := certificates[0].ChainPEM
	block, _ := pem.Decode(firstChain)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	err = c.acmeClient.RevokeCertificate(ctx, c.acmeAccount, cert, c.acmeAccount.PrivateKey, acme.ReasonCessationOfOperation)
	if err != nil {
		return err
	}

	return c.db.AddCert(ctx, cert, time.Now())
}

func (c *Churner) RandDomains() []string {
	// TODO
	return []string{"4byfairdiceroll." + c.baseDomain}
}
