//go:build integration

package db_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/stretchr/testify/require"

	"github.com/letsencrypt/crl-monitor/db"
)

func localResolver(service, region string, opts ...interface{}) (aws.Endpoint, error) {
	if service != dynamodb.ServiceID {
		return aws.Endpoint{}, fmt.Errorf("unsupported service %s", service)
	}
	return aws.Endpoint{
		PartitionID: "aws",
		URL:         "http://localhost:8000/",
	}, nil
}

// makeTable sets up the table in the integration test DB.
// In the real Dynamo, we provision the table with Terraform
func makeTable(t *testing.T, handle *db.Database) {
	_, err := handle.Dynamo.(*dynamodb.Client).CreateTable(context.Background(), &dynamodb.CreateTableInput{
		AttributeDefinitions: []types.AttributeDefinition{{
			AttributeName: aws.String("SN"),
			AttributeType: types.ScalarAttributeTypeB,
		}},
		KeySchema: []types.KeySchemaElement{{
			AttributeName: aws.String("SN"),
			KeyType:       types.KeyTypeHash,
		}},
		TableName: aws.String(handle.Table),
		ProvisionedThroughput: &types.ProvisionedThroughput{
			ReadCapacityUnits:  aws.Int64(10),
			WriteCapacityUnits: aws.Int64(10),
		},
	})
	require.NoError(t, err)
}

// TestIntegrationDynamoDB runs smoketest against a local DynamoDB.  The main
// goal of this test is to ensure that the in-process mock behaves similarly to
// the real dynamoDB, which is why we run the same smoketest against both.
// That means developers don't need to always be running the local DynamoDB to
// run most tests outside the db package.
func TestIntegrationDynamoDB(t *testing.T) {
	cfg := aws.NewConfig()
	cfg.EndpointResolverWithOptions = aws.EndpointResolverWithOptionsFunc(localResolver)
	cfg.Credentials = aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "Bogus", SecretAccessKey: "Bogus"}, nil
	})
	handle, err := db.New(cfg)
	require.NoError(t, err)

	makeTable(t, handle)
	smoketest(t, handle)
}
