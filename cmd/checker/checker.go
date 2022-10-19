package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"

	"github.com/letsencrypt/crl-monitor/checker"
	"github.com/letsencrypt/crl-monitor/db/mock"
	"github.com/letsencrypt/crl-monitor/storage"
)

func main() {
	bucket := flag.String("bucket", "le-crl-stg", "S3 Bucket Name")
	authority := flag.String("authority", "4169287449788112", "Which authority to check")

	flag.Parse()

	ctx := context.Background()

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatalf("error creating AWS config: %v", err)
	}

	mockedDB := mock.NewMockedDB(&testing.T{})
	c := checker.New( /*db.New(cfg)*/ mockedDB, storage.New(cfg))

	for crl := 0; crl < 128; crl++ {
		log.Printf("checking crl %d", crl)
		err = c.Check(context.Background(), *bucket, fmt.Sprintf("%s/%d.crl", *authority, crl))
		if err != nil {
			log.Fatalf("error checking CRL %d: %v", crl, err)
		}
	}
}
