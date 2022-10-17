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

type Database struct {
	table  string
	dynamo *dynamodb.Client
}

func New(cfg *aws.Config) (*Database, error) {
	return &Database{
		dynamo: dynamodb.NewFromConfig(*cfg),
	}, nil
}

type CertMetadata struct {
	SerialNumber   []byte    `dynamodbav:"SN"`
	RevocationTime time.Time `dynamodbav:"RT,unixtime"`
}

// AddCert inserts the metadata for monitoring
func (db *Database) AddCert(ctx context.Context, certificate *x509.Certificate, revocationTime time.Time) error {
	item, err := attributevalue.MarshalMap(CertMetadata{
		SerialNumber:   certificate.SerialNumber.Bytes(),
		RevocationTime: revocationTime,
	})
	if err != nil {
		return err
	}

	_, err = db.dynamo.PutItem(ctx, &dynamodb.PutItemInput{
		Item:      item,
		TableName: &db.table,
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
	resp, err := db.dynamo.Query(ctx, &dynamodb.QueryInput{
		TableName: &db.table,
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
