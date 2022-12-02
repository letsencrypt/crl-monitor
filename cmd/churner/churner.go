package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/letsencrypt/crl-monitor/churner"
)

func main() {
	ctx := context.Background()

	c, err := churner.NewFromEnv(ctx)
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

	missing, err := c.CheckMissing(ctx)
	if err != nil {
		log.Fatalf("Error checking for missing certs: %v", err)
	}
	if len(missing) != 0 {
		log.Print("Certificates didn't appear in CRL in time:")
		for _, missed := range missing {
			log.Printf("Cert serial %x revoked at %s (%s ago)", missed.SerialNumber, missed.RevocationTime, time.Since(missed.RevocationTime))
		}
		os.Exit(1)
	}

}
