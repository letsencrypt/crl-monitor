package main

import (
	"context"
	"log"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/letsencrypt/crl-monitor/ccadb"
)

func main() {
	ctx := context.Background()

	c, err := ccadb.NewFromEnv()
	if err != nil {
		log.Fatalf("Error creating Checker: %v", err)
	}

	lambda.StartWithOptions(c.Check, lambda.WithContext(ctx))
}
