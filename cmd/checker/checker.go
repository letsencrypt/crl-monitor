package main

import (
	"context"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"

	"github.com/letsencrypt/boulder/issuance"
	"github.com/letsencrypt/crl-monitor/checker"
	"github.com/letsencrypt/crl-monitor/checker/expiry"
	"github.com/letsencrypt/crl-monitor/cmd"
	"github.com/letsencrypt/crl-monitor/db"
	"github.com/letsencrypt/crl-monitor/storage"
)

const (
	BoulderBaseURL    cmd.EnvVar = "BOULDER_BASE_URL"
	DynamoEndpointEnv cmd.EnvVar = "DYNAMO_ENDPOINT"
	DynamoTableEnv    cmd.EnvVar = "DYNAMO_TABLE"
	IssuerPaths       cmd.EnvVar = "ISSUER_PATHS"
	S3CRLBucket       cmd.EnvVar = "S3_CRL_BUCKET"
	S3CRLObject       cmd.EnvVar = "S3_CRL_OBJECT"
	S3CRLVersion      cmd.EnvVar = "S3_CRL_VERSION"
	CRLAgeLimit       cmd.EnvVar = "CRL_AGE_LIMIT"
)

func main() {
	boulderBaseURL := BoulderBaseURL.MustRead("Boulder endpoint to fetch certificates from")
	bucket := S3CRLBucket.MustRead("S3 CRL bucket name")
	issuerPaths := IssuerPaths.MustRead("Colon (:) separated list of paths to PEM-formatted CRL issuer certificates")
	dynamoTable := DynamoTableEnv.MustRead("DynamoDB table name")
	dynamoEndpoint, customEndpoint := DynamoEndpointEnv.LookupEnv()
	object := S3CRLObject.MustRead("S3 Object path to CRL file")
	version, hasVersion := S3CRLVersion.LookupEnv()
	crlAgeLimit, hasAgeLimit := CRLAgeLimit.LookupEnv()

	ctx := context.Background()

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatalf("error creating AWS config: %v", err)
	}

	if customEndpoint {
		cfg.EndpointResolverWithOptions = aws.EndpointResolverWithOptionsFunc(db.StaticResolver(dynamoEndpoint))
	}

	database, err := db.New(dynamoTable, &cfg)
	if err != nil {
		log.Fatalf("error in database setup: %v", err)
	}

	baf := expiry.BoulderAPIFetcher{
		Client:  http.DefaultClient,
		BaseURL: boulderBaseURL,
	}

	ageLimitDuration := 24 * time.Hour
	if hasAgeLimit {
		ageLimitDuration, err = time.ParseDuration(crlAgeLimit)
		if err != nil {
			log.Fatalf("Could not parse CRL age limit: %v", err)
		}
	}

	var issuers []*issuance.Certificate
	for _, issuer := range strings.Split(issuerPaths, ":") {
		issuer, err := issuance.LoadCertificate(issuer)
		if err != nil {
			log.Fatalf("error loading issuer certificate: %v", err)
		}
		issuers = append(issuers, issuer)
	}

	c := checker.New(database, storage.New(cfg), &baf, ageLimitDuration, issuers)

	// The version is optional.
	var optionalVersion *string
	if hasVersion {
		optionalVersion = &version
	}

	err = c.Check(ctx, bucket, object, optionalVersion)
	if err != nil {
		log.Printf("error checking CRL %s: %v", object, err)
	}
}
