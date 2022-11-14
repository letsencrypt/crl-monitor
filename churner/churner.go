package churner

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez"
	"github.com/mholt/acmez/acme"
	"go.uber.org/zap"

	"github.com/letsencrypt/crl-monitor/db"
)

// The Churner creats and immediately revokes certificates. Certificates are
// issued using the configured ACME client using DNS01 challenges under the
// configured baseDomain. Serials and revocation time are stored in the db.
type Churner struct {
	baseDomain  string
	acmeClient  acmez.Client
	acmeAccount acme.Account
	db          *db.Database
}

// New returns a Churner with an ACME client configured.
// `baseDomain` should be a domain name that the `dnsProvider` can create/delete
// records for. The certs will be issued from the CA at `acmeDirectory`.
// The resulting serials are stored into `db`
func New(baseDomain string, acmeDirectory string, dnsProvider certmagic.ACMEDNSProvider, db *db.Database) (*Churner, error) {
	zapLogger, err := zap.NewProduction()
	if err != nil {
		return nil, err
	}

	acmeClient := acmez.Client{
		Client: &acme.Client{
			Directory: acmeDirectory,
			Logger:    zapLogger,
		},
		ChallengeSolvers: map[string]acmez.Solver{
			acme.ChallengeTypeDNS01: &certmagic.DNS01Solver{
				DNSProvider:      dnsProvider,
				PropagationDelay: 60 * time.Second, // Route53 docs say 60 seconds in normal conditions
			},
		},
	}

	return &Churner{
		baseDomain: baseDomain,
		acmeClient: acmeClient,
		db:         db,
	}, nil
}

// RegisterAccount sets up a new account.
// TODO: Store accounts to reuse.  For now we just make a new one each time.
func (c *Churner) RegisterAccount(ctx context.Context) error {
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("error generating account key: %v", err)
	}

	account, err := c.acmeClient.NewAccount(ctx, acme.Account{PrivateKey: accountKey, TermsOfServiceAgreed: true})
	if err != nil {
		return fmt.Errorf("error creating ACME account: %v", err)
	}

	c.acmeAccount = account
	return nil
}

// Churn issues a certificate, revokes it, and stores the result in DynamoDB
func (c *Churner) Churn(ctx context.Context) error {
	// Generate either an ecdsa or rsa private key
	certPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	certificates, err := c.acmeClient.ObtainCertificate(ctx, c.acmeAccount, certPrivateKey, randDomains(c.baseDomain))
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

// randDomains picks the domains to include on the certificate.
// We put a single domain which includes the current time and a random value.
func randDomains(baseDomain string) []string {
	randomSuffix := make([]byte, 2)
	_, err := rand.Read(randomSuffix)
	if err != nil {
		// Something has to go terribly wrong for this
		panic(fmt.Sprintf("random read failed: %v", err))
	}
	domain := fmt.Sprintf("r%dz%x.%s", time.Now().Unix(), randomSuffix, baseDomain)
	return []string{domain}
}
