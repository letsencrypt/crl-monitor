package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/libdns/route53"

	"github.com/letsencrypt/crl-monitor/churner"
	"github.com/letsencrypt/crl-monitor/cmd"
	"github.com/letsencrypt/crl-monitor/db"
)

const (
	BaseDomainEnv     cmd.EnvVar = "BASE_DOMAIN"
	ACMEDirectoryEnv  cmd.EnvVar = "ACME_DIRECTORY"
	DynamoTableEnv    cmd.EnvVar = "DYNAMO_TABLE"
	DynamoEndpointEnv cmd.EnvVar = "DYNAMO_ENDPOINT"
	RevokeDeadline    cmd.EnvVar = "REVOKE_DEADLINE"
)

func main() {
	baseDomain := BaseDomainEnv.MustRead("Base domain to issue certificates under")
	acmeDirectory := ACMEDirectoryEnv.MustRead("ACME directory URL")
	dynamoTable := DynamoTableEnv.MustRead("DynamoDB table name")
	dynamoEndpoint, customEndpoint := DynamoEndpointEnv.LookupEnv()
	revokeDeadline, err := time.ParseDuration(RevokeDeadline.MustRead("Deadline for revoked certs to appear in CRL"))
	if err != nil {
		log.Fatalf("error parsing %s: %v", RevokeDeadline, err)
	}

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

	dnsProvider := route53.Provider{}

	c, err := churner.New(baseDomain, acmeDirectory, &dnsProvider, database)
	if err != nil {
		log.Fatalf("Error in setup: %v", err)
	}

	missing, err := c.CheckMissing(ctx, time.Now().Add(-1*revokeDeadline))
	if err != nil {
		log.Fatalf("Error checking for missing certs: %v", err)
	}
	if len(missing) != 0 {
		log.Printf("Certificates missing in CRL after %s:", revokeDeadline)
		for _, missed := range missing {
			log.Printf("cert serial %x revoked at %s (%s ago)", missed.SerialNumber, missed.RevocationTime, time.Since(missed.RevocationTime))
		}
		os.Exit(1)
	}

	err = c.RegisterAccount(ctx)
	if err != nil {
		log.Fatalf("Error in registering acme account: %v", err)
	}

	err = c.Churn(ctx)
	if err != nil {
		log.Fatalf("Error in churning: %v", err)
	}
}
