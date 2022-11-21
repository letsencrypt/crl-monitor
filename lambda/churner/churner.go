package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-lambda-go/lambda"

	"github.com/letsencrypt/crl-monitor/churner"
)

func HandleRequest(c *churner.Churner) func(context.Context) error {
	return func(ctx context.Context) error {
		err := c.RegisterAccount(ctx)
		if err != nil {
			return fmt.Errorf("registering acme account: %w", err)
		}

		err = c.Churn(ctx)
		if err != nil {
			return fmt.Errorf("churning: %w", err)
		}

		missing, err := c.CheckMissing(ctx)
		if err != nil {
			return fmt.Errorf("checking for missing certs: %w", err)
		}
		if len(missing) != 0 {
			log.Print("Certificates didn't appear in CRL in time:")
			for _, missed := range missing {
				log.Printf("Cert serial %x revoked at %s (%s ago)", missed.SerialNumber, missed.RevocationTime, time.Since(missed.RevocationTime))
			}
			return fmt.Errorf("missing %d certificates from CRL", len(missing))
		}

		return nil
	}
}

func main() {
	ctx := context.Background()

	c, err := churner.NewFromEnv(ctx)
	if err != nil {
		log.Fatalf("Error in setup: %v", err)
	}

	lambda.Start(HandleRequest(c))
}
