package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
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
	IssuerPath        cmd.EnvVar = "ISSUER_PATH"
	S3CRLBucket       cmd.EnvVar = "S3_CRL_BUCKET"
	ShardNumber       cmd.EnvVar = "SHARD_NUMBER"
	ShardVersion      cmd.EnvVar = "SHARD_VERSION"
	CRLAgeLimit       cmd.EnvVar = "CRL_AGE_LIMIT"
)

func main() {
	boulderBaseURL := BoulderBaseURL.MustRead("Boulder endpoint to fetch certificates from")
	bucket := S3CRLBucket.MustRead("S3 CRL bucket name")
	issuerPath := IssuerPath.MustRead("Path to PEM-formatted CRL issuer certificate")
	dynamoTable := DynamoTableEnv.MustRead("DynamoDB table name")
	dynamoEndpoint, customEndpoint := DynamoEndpointEnv.LookupEnv()
	shard := ShardNumber.MustRead("CRL Shard number")
	shardVersion, hasVersion := ShardVersion.LookupEnv()
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

	c := checker.New(database, storage.New(cfg), &baf, ageLimitDuration)

	issuer, err := issuance.LoadCertificate(issuerPath)
	if err != nil {
		log.Fatalf("error loading issuer certificate: %v", err)
	}

	// The version is optional.
	var optionalVersion *string
	if hasVersion {
		optionalVersion = &shardVersion
	}

	err = c.Check(ctx, issuer, bucket, fmt.Sprintf("%d/%s.crl", issuer.NameID(), shard), optionalVersion)
	if err != nil {
		log.Printf("error checking CRL %s: %v", shard, err)
	}
}
