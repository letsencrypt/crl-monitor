//go:build integration

package db_test

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stretchr/testify/require"

	"github.com/letsencrypt/crl-monitor/db"
)

// TestIntegrationDynamoDB runs smoketest against a local DynamoDB.  The main
// goal of this test is to ensure that the in-process mock behaves similarly to
// the real dynamoDB, which is why we run the same smoketest against both.
// That means developers don't need to always be running the local DynamoDB to
// run most tests outside the db package.
func TestIntegrationDynamoDB(t *testing.T) {
	cfg := aws.NewConfig()
	cfg.EndpointResolverWithOptions = aws.EndpointResolverWithOptionsFunc(db.StaticResolver("http://localhost:8000"))
	cfg.Credentials = aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "Bogus", SecretAccessKey: "Bogus"}, nil
	})
	handle, err := db.New("unseen-certificates", cfg)
	require.NoError(t, err)

	smoketest(t, handle)
}
