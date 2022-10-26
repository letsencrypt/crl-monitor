package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"

	"github.com/letsencrypt/boulder/issuance"
	"github.com/letsencrypt/crl-monitor/checker"
	"github.com/letsencrypt/crl-monitor/db/mock"
	"github.com/letsencrypt/crl-monitor/storage"
)

func main() {
	bucket := flag.String("bucket", "le-crl-stg", "S3 Bucket Name")
	issuerPath := flag.String("issuer", "int-r3-by-x1.pem", "PEM-formatted CRL issuer certificate")

	flag.Parse()

	ctx := context.Background()

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatalf("error creating AWS config: %v", err)
	}

	mockedDB := mock.NewMockedDB(&testing.T{})
	c := checker.New( /*db.New(cfg)*/ mockedDB, storage.New(cfg))

	issuer, err := issuance.LoadCertificate(*issuerPath)
	if err != nil {
		log.Fatalf("error loading issuer certificate: %v", err)
	}

	success := true
	for crl := 0; crl < 128; crl++ {
		log.Printf("checking crl %d", crl)
		err = c.Check(context.Background(), issuer, *bucket, fmt.Sprintf("%d/%d.crl", issuer.NameID(), crl))
		if err != nil {
			log.Printf("error checking CRL %d: %v", crl, err)
			success = false
		}
	}
	if !success {
		log.Fatalf("Some CRLs had errors")
	}
}
