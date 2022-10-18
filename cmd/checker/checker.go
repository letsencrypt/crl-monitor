package main

import (
	"context"
	"flag"
	"log"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"

	"github.com/letsencrypt/crl-monitor/checker"
	"github.com/letsencrypt/crl-monitor/db/mock"
	"github.com/letsencrypt/crl-monitor/storage"
)

func main() {
	bucket := flag.String("bucket", "le-crl-stg", "S3 Bucket Name")
	crl := flag.String("crl", "4169287449788112/4.crl", "CRL object in the bucket")
	// TODO: We want an optional version flag
	//version := flag.String("version", "AaEXGhkxA4sL43bsnp23dG3vhT5TDyF3", "Object version")

	flag.Parse()

	ctx := context.Background()

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatalf("error creating AWS config: %v", err)
	}

	mockedDB := mock.NewMockedDB(&testing.T{})
	c := checker.New( /*db.New(cfg)*/ mockedDB, storage.New(cfg))

	err = c.Check(context.Background(), *bucket, *crl)
	if err != nil {
		log.Fatalf("error checking CRLs: %v", err)
	}
}
