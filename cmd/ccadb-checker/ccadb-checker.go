package main

import (
	"context"
	"log"

	"github.com/letsencrypt/crl-monitor/ccadb"
)

func main() {
	checker, err := ccadb.NewFromEnv()
	if err != nil {
		log.Fatal(err)
	}

	err = checker.Check(context.Background())
	if err != nil {
		log.Fatal(err)
	}
}
