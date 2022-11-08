package main

import (
	"context"
	"log"

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
)

func main() {
	baseDomain := BaseDomainEnv.MustRead("Base domain to issue certificates under")
	acmeDirectory := ACMEDirectoryEnv.MustRead("ACME directory URL")
	dynamoTable := DynamoTableEnv.MustRead("DynamoDB table name")
	dynamoEndpoint, customEndpoint := DynamoEndpointEnv.LookupEnv()

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

	err = c.RegisterAccount(ctx)
	if err != nil {
		log.Fatalf("Error in registering acme account: %v", err)
	}

	err = c.Churn(ctx)
	if err != nil {
		log.Fatalf("Error in churning: %v", err)
	}
}
