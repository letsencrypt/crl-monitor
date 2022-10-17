package main

import (
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/letsencrypt/crl-monitor/checker"
	"github.com/letsencrypt/crl-monitor/db"
)

func main() {
	fmt.Println("Checker!")
	cfg := aws.NewConfig()
	database, err := db.New(cfg)
	if err != nil {
		log.Fatalf("error opening DB: %v", err)
	}
	c := checker.New(database)
	err = c.Check(context.Background(), checker.VersionedCRLShard{})
	if err != nil {
		log.Fatalf("error checking CRLs: %v", err)
	}
}
