package mock

import (
	"bytes"
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/stretchr/testify/require"

	"github.com/letsencrypt/crl-monitor/db"
)

const Table = "table"

// NewMockedDB returns an in-memory Database using a mocked DynamoDB
// It is meant only for use in tests.
func NewMockedDB(t *testing.T) *db.Database {
	return &db.Database{
		Table:  Table,
		Dynamo: &dynamoMock{t: t},
	}
}

type dynamoMock struct {
	t *testing.T

	data []map[string]types.AttributeValue
}

func has(key map[string]types.AttributeValue, item map[string]types.AttributeValue) bool {
	for k, v := range key {
		if !bytes.Equal(item[k].(*types.AttributeValueMemberB).Value, v.(*types.AttributeValueMemberB).Value) {
			return false
		}
	}
	return true
}

func (d *dynamoMock) BatchWriteItem(ctx context.Context, input *dynamodb.BatchWriteItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.BatchWriteItemOutput, error) {
	require.Empty(d.t, opts, "Options not supported")
	require.NotNil(d.t, input)

	for _, item := range input.RequestItems[Table] {
		require.Nil(d.t, item.PutRequest, "Only delete requests supported")
		require.NotNil(d.t, item.DeleteRequest)

		key := item.DeleteRequest.Key

		var filtered []map[string]types.AttributeValue
		for _, i := range d.data {
			if !has(key, i) {
				filtered = append(filtered, i)
			}
		}
		d.data = filtered
	}
	return &dynamodb.BatchWriteItemOutput{}, nil
}

func (d *dynamoMock) PutItem(ctx context.Context, input *dynamodb.PutItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	require.Empty(d.t, opts, "Options not supported")
	require.NotNil(d.t, input)
	d.data = append(d.data, input.Item)
	return &dynamodb.PutItemOutput{}, nil
}

func (d *dynamoMock) Scan(ctx context.Context, input *dynamodb.ScanInput, opts ...func(*dynamodb.Options)) (*dynamodb.ScanOutput, error) {
	require.Empty(d.t, opts, "Options not supported")
	require.NotNil(d.t, input)
	return &dynamodb.ScanOutput{Items: d.data}, nil
}
