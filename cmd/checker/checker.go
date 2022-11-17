package main

import (
	"context"
	"log"

	"github.com/letsencrypt/crl-monitor/checker"
	"github.com/letsencrypt/crl-monitor/cmd"
)

const (
	S3CRLBucket  cmd.EnvVar = "S3_CRL_BUCKET"
	S3CRLObject  cmd.EnvVar = "S3_OBJECT"
	ShardVersion cmd.EnvVar = "SHARD_VERSION"
)

func main() {
	bucket := S3CRLBucket.MustRead("S3 CRL bucket name")
	object := S3CRLObject.MustRead("S3 Object path to CRL file")
	version, hasVersion := ShardVersion.LookupEnv()

	ctx := context.Background()

	c, err := checker.NewFromEnv(ctx)
	if err != nil {
		log.Fatalf("error creating checker: %v", err)
	}

	// The version is optional, so we pass it as a possibly-nil string pointer.
	var optionalVersion *string
	if hasVersion {
		optionalVersion = &version
	}

	err = c.Check(ctx, bucket, object, optionalVersion)
	if err != nil {
		log.Printf("error checking CRL %s: %v", object, err)
	}
}
