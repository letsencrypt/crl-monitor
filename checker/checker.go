package checker

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/crl/checker"

	"github.com/letsencrypt/crl-monitor/checker/earlyremoval"
	"github.com/letsencrypt/crl-monitor/checker/expiry"
	"github.com/letsencrypt/crl-monitor/cmd"
	"github.com/letsencrypt/crl-monitor/db"
	"github.com/letsencrypt/crl-monitor/idp"
	"github.com/letsencrypt/crl-monitor/storage"
)

const (
	BoulderBaseURL    cmd.EnvVar = "BOULDER_BASE_URL"
	BoulderMaxFetch   cmd.EnvVar = "BOULDER_MAX_FETCH"
	DynamoEndpointEnv cmd.EnvVar = "DYNAMO_ENDPOINT"
	DynamoTableEnv    cmd.EnvVar = "DYNAMO_TABLE"
	CRLAgeLimit       cmd.EnvVar = "CRL_AGE_LIMIT"
	IssuerPaths       cmd.EnvVar = "ISSUER_PATHS"
)

func nameID(issuer *x509.Certificate) string {
	h := crypto.SHA1.New()
	h.Write(issuer.RawSubject)
	s := h.Sum(nil)
	return fmt.Sprintf("%d", big.NewInt(0).SetBytes(s[:7]))
}

func New(database *db.Database, storage *storage.Storage, fetcher earlyremoval.Fetcher, maxFetch int, ageLimit time.Duration, issuers []*x509.Certificate) *Checker {
	issuerMap := make(map[string]*x509.Certificate, len(issuers))
	for _, issuer := range issuers {
		issuerMap[nameID(issuer)] = issuer
	}

	return &Checker{
		db:       database,
		storage:  storage,
		fetcher:  fetcher,
		maxFetch: maxFetch,
		ageLimit: ageLimit,
		issuers:  issuerMap,
	}
}

func NewFromEnv(ctx context.Context) (*Checker, error) {
	boulderBaseURL := BoulderBaseURL.MustRead("Boulder endpoint to fetch certificates from")
	dynamoTable := DynamoTableEnv.MustRead("DynamoDB table name")
	dynamoEndpoint, _ := DynamoEndpointEnv.LookupEnv()
	crlAgeLimit, hasAgeLimit := CRLAgeLimit.LookupEnv()
	issuerPaths := IssuerPaths.MustRead("Colon (:) separated list of paths to PEM-formatted CRL issuer certificates")

	maxFetch := 0
	maxFetchString, hasMaxFetch := BoulderMaxFetch.LookupEnv()
	if hasMaxFetch {
		var err error
		maxFetch, err = strconv.Atoi(maxFetchString)
		if err != nil {
			return nil, fmt.Errorf("parsing %s as int (%s): %v", BoulderMaxFetch, maxFetchString, err)
		}
	}

	database, err := db.New(ctx, dynamoTable, dynamoEndpoint)
	if err != nil {
		return nil, fmt.Errorf("database setup: %w", err)
	}

	baf := expiry.BoulderAPIFetcher{
		Client:  http.DefaultClient,
		BaseURL: boulderBaseURL,
	}

	ageLimitDuration := 24 * time.Hour
	if hasAgeLimit {
		ageLimitDuration, err = time.ParseDuration(crlAgeLimit)
		if err != nil {
			return nil, fmt.Errorf("parsing CRL age limit: %w", err)
		}
	}

	var issuers []*x509.Certificate
	for _, issuer := range strings.Split(issuerPaths, ":") {
		issuer, err := core.LoadCert(issuer)
		if err != nil {
			log.Fatalf("error loading issuer certificate: %v", err)
		}
		log.Printf("Loaded issuer CN=%s", issuer.Subject.CommonName)
		issuers = append(issuers, issuer)
	}

	return New(database, storage.New(ctx), &baf, maxFetch, ageLimitDuration, issuers), nil
}

// The Checker handles fetching and linting CRLs.
// Use New to obtain one.
type Checker struct {
	db       *db.Database
	storage  *storage.Storage
	fetcher  earlyremoval.Fetcher
	maxFetch int
	ageLimit time.Duration
	issuers  map[string]*x509.Certificate
}

// Check fetches a CRL and its previous version.  It runs lints on the CRL, checks for early removal, and removes any
// certificates we're waiting for out of the database.
func (c *Checker) Check(ctx context.Context, bucket, object string, startingVersion *string) error {
	// Read the current CRL shard
	crlDER, version, err := c.storage.Fetch(ctx, bucket, object, startingVersion)
	if err != nil {
		return err
	}

	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		return fmt.Errorf("error parsing current crl: %v", err)
	}
	log.Printf("loaded CRL number %d (len %d) from %s version %s", crl.Number, len(crl.RevokedCertificateEntries), object, version)

	issuer, err := c.issuerForObject(object)
	if err != nil {
		return err
	}

	err = checker.Validate(crl, issuer, c.ageLimit)
	if err != nil {
		return fmt.Errorf("crl failed linting: %v", err)
	}
	log.Printf("crl %d successfully linted", crl.Number)

	_, err = idp.Get(crl)
	if err != nil {
		return err
	}

	// And the previous:
	prevVersion, err := c.storage.Previous(ctx, bucket, object, version)
	if err != nil {
		return err
	}

	prevDER, _, err := c.storage.Fetch(ctx, bucket, object, &prevVersion)
	if err != nil {
		return err
	}

	prev, err := x509.ParseRevocationList(prevDER)
	if err != nil {
		return fmt.Errorf("error parsing previous crl: %v", err)
	}
	log.Printf("loaded previous CRL number %d (len %d) from version %s", prev.Number, len(prev.RevokedCertificateEntries), prevVersion)

	earlyRemoved, err := earlyremoval.Check(ctx, c.fetcher, c.maxFetch, prev, crl)
	if err != nil {
		return fmt.Errorf("failed to check for early removal: %v", err)
	}

	if len(earlyRemoved) != 0 {
		sample := earlyRemoved
		if len(sample) > 50 {
			sample = sample[:50]
		}

		// Certificates removed early!  This is very bad.
		return fmt.Errorf("early removal of %d certificates detected! First %d: %v", len(earlyRemoved), len(sample), sample)
	}

	return c.lookForSeenCerts(ctx, crl)
}

// lookForSeenCerts removes any certs in this CRL from the database, as they've now appeared in a CRL.
// We expect the database to be much smaller than CRLs, so we load the entire database into memory.
func (c *Checker) lookForSeenCerts(ctx context.Context, crl *x509.RevocationList) error {
	unseenCerts, err := c.db.GetAllCerts(ctx)
	if err != nil {
		return fmt.Errorf("failed to read from db: %v", err)
	}
	var seenSerials [][]byte
	var errs []error
	for _, seen := range crl.RevokedCertificateEntries {
		if metadata, ok := unseenCerts[db.NewCertKey(seen.SerialNumber).SerialString()]; ok {
			idp, err := idp.Get(crl)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if metadata.CRLDistributionPoint != "" && metadata.CRLDistributionPoint != idp {
				errs = append(errs, fmt.Errorf("cert %x on CRL %q has non-matching CRLDistributionPoint %q",
					seen.SerialNumber, idp, metadata.CRLDistributionPoint))
				continue
			}
			seenSerials = append(seenSerials, metadata.SerialNumber)
		}
	}

	err = c.db.DeleteSerials(ctx, seenSerials)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to delete from db: %v", err))
	}
	return errors.Join(errs...)
}

// issuerForObject takes an s3 object path, extracts the issuer prefix, and returns the right x509.Certificate
func (c *Checker) issuerForObject(object string) (*x509.Certificate, error) {
	prefix, _, found := strings.Cut(object, "/")
	if !found {
		return nil, fmt.Errorf("object path did not contain /: %s", object)
	}

	issuer, ok := c.issuers[prefix]
	if !ok {
		return nil, fmt.Errorf("unable to find an issuer for object prefix %s", prefix)
	}

	return issuer, nil
}
