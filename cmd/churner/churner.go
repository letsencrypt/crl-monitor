package main

import (
	"context"
	"log"

	"github.com/letsencrypt/crl-monitor/churner"
)

func main() {
	ctx := context.Background()

	c, err := churner.New("localhost")
	if err != nil {
		log.Fatalf("Error in setup: %v", err)
	}

	err = c.Churn(ctx)
	if err != nil {
		log.Fatalf("Error in churning: %v", err)
	}
}
