package db

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// ddb is fulfilled by a dynamodb.Client and is used for mocking in tests.
type ddb interface {
	BatchWriteItem(context.Context, *dynamodb.BatchWriteItemInput, ...func(*dynamodb.Options)) (*dynamodb.BatchWriteItemOutput, error)
	PutItem(context.Context, *dynamodb.PutItemInput, ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	Scan(context.Context, *dynamodb.ScanInput, ...func(*dynamodb.Options)) (*dynamodb.ScanOutput, error)
}

type Database struct {
	Table  string
	Dynamo ddb
}

func New(cfg *aws.Config) (*Database, error) {
	return &Database{
		Table:  "unseen-certificates",
		Dynamo: dynamodb.NewFromConfig(*cfg),
	}, nil
}

type CertMetadata struct {
	CertKey
	RevocationTime time.Time `dynamodbav:"RT,unixtime"`
}

type CertKey struct {
	SerialNumber []byte `dynamodbav:"SN"`
}

// AddCert inserts the metadata for monitoring
func (db *Database) AddCert(ctx context.Context, certificate *x509.Certificate, revocationTime time.Time) error {
	item, err := attributevalue.MarshalMap(CertMetadata{
		CertKey:        CertKey{certificate.SerialNumber.Bytes()},
		RevocationTime: revocationTime,
	})
	if err != nil {
		return err
	}

	_, err = db.Dynamo.PutItem(ctx, &dynamodb.PutItemInput{
		Item:      item,
		TableName: &db.Table,
	})
	if err != nil {
		return err
	}

	return nil
}

// GetAllCerts returns all the certificates in the DynamoDB.  This set is
// intended to be much smaller than the set of certificates in a CRL, so it's
// more efficient to just load the entire set instead of conditional querying.
// TODO:  This could be even more efficient if we knew what shard a cert would
// TODO:  be in, so that we can only query certs for this shard.
func (db *Database) GetAllCerts(ctx context.Context) ([]CertMetadata, error) {
	resp, err := db.Dynamo.Scan(ctx, &dynamodb.ScanInput{
		TableName: &db.Table,
		Select:    types.SelectAllAttributes,
	})
	if err != nil {
		return nil, err
	}

	var certs []CertMetadata
	err = attributevalue.UnmarshalListOfMaps(resp.Items, &certs)
	if err != nil {
		return nil, err
	}

	return certs, nil
}

// DeleteSerials takes a list of serials that we've seen in the CRL and thus
// no longer need to keep an eye out for.
func (db *Database) DeleteSerials(ctx context.Context, serialNumbers [][]byte) error {
	var deletes []types.WriteRequest
	for _, serial := range serialNumbers {
		key, err := attributevalue.MarshalMap(CertKey{SerialNumber: serial})
		if err != nil {
			return err
		}
		deletes = append(deletes, types.WriteRequest{
			DeleteRequest: &types.DeleteRequest{
				Key: key,
			},
		})
	}

	_, err := db.Dynamo.BatchWriteItem(ctx, &dynamodb.BatchWriteItemInput{
		RequestItems: map[string][]types.WriteRequest{db.Table: deletes},
	})
	if err != nil {
		return err
	}
	return nil
}
