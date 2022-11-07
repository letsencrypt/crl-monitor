package main

import (
	"context"
	"flag"
	"log"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/libdns/route53"

	"github.com/letsencrypt/crl-monitor/churner"
	"github.com/letsencrypt/crl-monitor/db"
)

func main() {
	baseDomain := flag.String("base-domain", "aws.radiantlock.org", "Base domain to issue certificates under")
	acmeDirectory := flag.String("acme-directory", "", "ACME directory url")
	tableName := flag.String("dynamo-table", "", "DynamoDB Table name")

	flag.Parse()

	ctx := context.Background()

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatalf("error creating AWS config: %v", err)
	}

	database, err := db.New(*tableName, &cfg)
	if err != nil {
		log.Fatalf("error in database setup: %v", err)
	}

	dnsProvider := &route53.Provider{}

	c, err := churner.New(*baseDomain, *acmeDirectory, dnsProvider, database)
	if err != nil {
		log.Fatalf("Error in setup: %v", err)
	}

	err = c.Churn(ctx)
	if err != nil {
		log.Fatalf("Error in churning: %v", err)
	}
}
