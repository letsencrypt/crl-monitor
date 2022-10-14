package main

import (
	"log"

	"github.com/letsencrypt/crl-monitor/churner"
)

func main() {
	c, err := churner.New("localhost")
	if err != nil {
		log.Fatalf("Error in setup: %v", err)
	}

	err = c.Churn()
	if err != nil {
		log.Fatalf("Error in churning: %v", err)
	}
}
