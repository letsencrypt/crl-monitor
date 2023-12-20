package main

import (
	"context"
	"log"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"go.uber.org/multierr"

	"github.com/letsencrypt/crl-monitor/checker"
)

func HandleRequest(c *checker.Checker) func(ctx context.Context, event events.S3Event) error {
	return func(ctx context.Context, event events.S3Event) error {
		var err error
		for _, record := range event.Records {
			record := record
			err = multierr.Append(err, c.Check(ctx, record.S3.Bucket.Name, record.S3.Object.Key, &record.S3.Object.VersionID))
		}
		return err
	}
}

func main() {
	ctx := context.Background()

	c, err := checker.NewFromEnv(ctx)
	if err != nil {
		log.Fatalf("Error creating Checker: %v", err)
	}

	lambda.StartWithOptions(HandleRequest(c), lambda.WithContext(ctx))
}
