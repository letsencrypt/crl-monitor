package churner

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"log/slog"
	mathrand "math/rand/v2"
	"os"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/route53"
	"github.com/mholt/acmez/v3"
	"github.com/mholt/acmez/v3/acme"

	"github.com/letsencrypt/boulder/crl/checker"
	"github.com/letsencrypt/crl-monitor/cmd"
	"github.com/letsencrypt/crl-monitor/db"
	"github.com/letsencrypt/crl-monitor/retryhttp"
)

const (
	BaseDomainEnv     cmd.EnvVar = "BASE_DOMAIN"
	ACMEDirectoryEnv  cmd.EnvVar = "ACME_DIRECTORY"
	DynamoTableEnv    cmd.EnvVar = "DYNAMO_TABLE"
	DynamoEndpointEnv cmd.EnvVar = "DYNAMO_ENDPOINT"
	RevokeDeadline    cmd.EnvVar = "REVOKE_DEADLINE"
)

// The Churner creats and immediately revokes certificates. Certificates are
// issued using the configured ACME client using DNS01 challenges under the
// configured baseDomain. Serials and revocation time are stored in the db.
type Churner struct {
	baseDomain  string
	acmeClient  acmez.Client
	acmeAccount acme.Account
	db          *db.Database
	cutoff      time.Time
}

// New returns a Churner with an ACME client configured.
// `baseDomain` should be a domain name that the `dnsProvider` can create/delete
// records for. The certs will be issued from the CA at `acmeDirectory`.
// The resulting serials are stored into `db`
func New(baseDomain string, acmeDirectory string, dnsProvider certmagic.DNSProvider, db *db.Database, cutoff time.Time) (*Churner, error) {
	slogger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	acmeClient := acmez.Client{
		Client: &acme.Client{
			Directory: acmeDirectory,
			Logger:    slogger,
		},
		ChallengeSolvers: map[string]acmez.Solver{
			acme.ChallengeTypeDNS01: &certmagic.DNS01Solver{
				DNSManager: certmagic.DNSManager{
					DNSProvider:      dnsProvider,
					PropagationDelay: 60 * time.Second, // Route53 docs say 60 seconds in normal conditions,
				},
			},
		},
	}

	return &Churner{
		baseDomain: baseDomain,
		acmeClient: acmeClient,
		db:         db,
		cutoff:     cutoff,
	}, nil
}

func NewFromEnv(ctx context.Context) (*Churner, error) {
	baseDomain := BaseDomainEnv.MustRead("Base domain to issue certificates under")
	acmeDirectory := ACMEDirectoryEnv.MustRead("ACME directory URL")
	dynamoTable := DynamoTableEnv.MustRead("DynamoDB table name")
	dynamoEndpoint, _ := DynamoEndpointEnv.LookupEnv()

	revokeDeadline, err := time.ParseDuration(RevokeDeadline.MustRead("Deadline for revoked certs to appear in CRL, as a duration before the current time"))
	if err != nil {
		log.Fatalf("Error parsing %s: %v", RevokeDeadline, err)
	}

	cutoff := time.Now().Add(-1 * revokeDeadline)

	database, err := db.New(ctx, dynamoTable, dynamoEndpoint)
	if err != nil {
		log.Fatalf("Error in database setup: %v", err)
	}

	dnsProvider := route53.Provider{}

	return New(baseDomain, acmeDirectory, &dnsProvider, database, cutoff)
}

// RegisterAccount sets up a new account.
// TODO: Store accounts to reuse.  For now we just make a new one each time.
func (c *Churner) RegisterAccount(ctx context.Context) error {
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating account key: %w", err)
	}

	account, err := c.acmeClient.NewAccount(ctx, acme.Account{PrivateKey: accountKey, TermsOfServiceAgreed: true})
	if err != nil {
		return fmt.Errorf("creating ACME account: %w", err)
	}

	c.acmeAccount = account

	// Account creation isn't immediately consistent across all DCs.
	// Sleep 2 seconds to avoid any potential problems.
	time.Sleep(2 * time.Second)
	return nil
}

func (c *Churner) retryObtain(ctx context.Context, certPrivateKey crypto.Signer, sans []string) ([]acme.Certificate, error) {
	csr, err := acmez.NewCSR(certPrivateKey, sans)
	if err != nil {
		return nil, err
	}
	params, err := acmez.OrderParametersFromCSR(c.acmeAccount, csr)
	if err != nil {
		return nil, err
	}
	var certificates []acme.Certificate
	for retry := 0; retry < 5; retry++ {
		certificates, err = c.acmeClient.ObtainCertificate(ctx, params)
		if err != nil {
			log.Printf("error obtaining certificate on retry %d: %v", retry, err)
			time.Sleep(time.Second)
			continue
		}
		return certificates, nil
	}
	return nil, err
}

// Churn issues a certificate, revokes it, and stores the result in DynamoDB
func (c *Churner) Churn(ctx context.Context) error {
	certPrivateKey, err := randomKey()
	if err != nil {
		return err
	}

	certificates, err := c.retryObtain(ctx, certPrivateKey, randDomains(c.baseDomain))
	if err != nil {
		return err
	}

	// certificates contains all the possible cert chains.  We don't
	// care about alternate chains, but we do care about getting
	// the parent of the certificate we just got, so we can validate its CRL.
	firstChain := certificates[0].ChainPEM
	block, remaining := pem.Decode(firstChain)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	block, _ = pem.Decode(remaining)
	issuer, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	// If the certificate has any CRLDistributionPoints, check that they can be fetched,
	// parsed, verified, and linted. We don't try to check for revocation at this stage
	// because it may be several hours before a new CRL is uploaded that reflects the
	// revocation we're about to do.
	for _, url := range cert.CRLDistributionPoints {
		body, err := retryhttp.Get(ctx, url)
		if err != nil {
			return fmt.Errorf("fetching CRL %q from CRLDistributionPoint of certificate %036x: %s",
				url, cert.SerialNumber, err)
		}
		crl, err := x509.ParseRevocationList(body)
		if err != nil {
			return fmt.Errorf("fetching CRL %q from CRLDistributionPoint of certificate %036x: %s",
				url, cert.SerialNumber, err)
		}
		err = checker.Validate(crl, issuer, 24*time.Hour)
		if err != nil {
			return err
		}
	}

	err = c.acmeClient.RevokeCertificate(ctx, c.acmeAccount, cert, c.acmeAccount.PrivateKey, acme.ReasonCessationOfOperation)
	if err != nil {
		return err
	}

	return c.db.AddCert(ctx, cert, time.Now())
}

// randomKey generates either an ecdsa or rsa private key
func randomKey() (crypto.Signer, error) {
	if mathrand.IntN(2) == 0 {
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	} else {
		return rsa.GenerateKey(rand.Reader, 2048)
	}
}

// randDomains picks the domains to include on the certificate.
// We put a single domain which includes the current time and a random value.
func randDomains(baseDomain string) []string {
	domain := fmt.Sprintf("r%dz%x.%s", time.Now().Unix(), mathrand.Uint32(), baseDomain)
	return []string{domain}
}

// CheckMissing looks if previously stored serials are still in the database, meaning they
// haven't been seen in a CRL.  CheckMissing returns all certs revoked before a cutoff time.
func (c *Churner) CheckMissing(ctx context.Context) ([]db.CertMetadata, error) {
	// TODO:  This calls GetAllCerts and filters client-side instead of using an efficient query.
	unseenCerts, err := c.db.GetAllCerts(ctx)
	if err != nil {
		return nil, fmt.Errorf("retrieving unseen certificates: %w", err)
	}

	var missed []db.CertMetadata
	for _, cert := range unseenCerts {
		// If the cert was revoked before the cutoff, we should have seen it
		if cert.RevocationTime.Before(c.cutoff) {
			missed = append(missed, cert)
		}
	}
	return missed, nil
}
