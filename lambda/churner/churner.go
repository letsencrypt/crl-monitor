package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-lambda-go/lambda"

	"github.com/letsencrypt/crl-monitor/churner"
)

// HandleRequest returns lambda handler responsible for both of Churner's
// tasks: issuing and revoking certificates, and checking to ensure that
// no certificates in the database are too old (i.e. that they've shown up
// on at least one CRL and been removed from the db by the Checker).
func HandleRequest(c *churner.Churner) func(context.Context) error {
	return func(ctx context.Context) error {
		// Part 1: Issue a certificate, immediately revoke it, and
		// insert a database entry indicating when it was issued and revoked.
		err := c.RegisterAccount(ctx)
		if err != nil {
			return fmt.Errorf("registering acme account: %w", err)
		}

		err = c.Churn(ctx)
		if err != nil {
			return fmt.Errorf("churning: %w", err)
		}

		// Part 2: Load all certificates from the database (most likely
		// including the one that was just issued), and check to make sure
		// that any certs found there are recent enough that we're not
		// worried about them not having appeared on a CRL yet.
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
		log.Fatalf("Error creating Churner: %v", err)
	}

	lambda.StartWithOptions(HandleRequest(c), lambda.WithContext(ctx))
}
