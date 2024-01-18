package db

import (
	"context"
	"crypto/x509"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
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

func New(ctx context.Context, table, dynamoEndpoint string) (*Database, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatalf("Error creating AWS config: %v", err)
	}

	return &Database{
		Table: table,
		Dynamo: dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) {
			if dynamoEndpoint == "" {
				o.BaseEndpoint = aws.String(dynamoEndpoint)
			}
		}),
	}, nil
}

// CertMetadata is the entire set of attributes stored in Dynamo.
// That is the CertKey plus the revocation time today.
type CertMetadata struct {
	CertKey
	RevocationTime time.Time `dynamodbav:"RT,unixtime"`
}

// CertKey is the DynamoDB primary key, which is the serial number.
type CertKey struct {
	SerialNumber []byte `dynamodbav:"SN"`
}

func NewCertKey(sn *big.Int) CertKey {
	return CertKey{SerialNumber: sn.Bytes()}
}

// SerialString returns a consistent string representation of a SerialNumber
// It is intended for use as a map key, and is equivalent to boulder's SerialToString
func (ck CertKey) SerialString() string {
	return fmt.Sprintf("%036x", ck.SerialNumber)
}

// AddCert inserts the metadata for monitoring
func (db *Database) AddCert(ctx context.Context, certificate *x509.Certificate, revocationTime time.Time) error {
	item, err := attributevalue.MarshalMap(CertMetadata{
		CertKey:        NewCertKey(certificate.SerialNumber),
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
// The map key is the serial's CertKey.SerialString.
// TODO: This could be more efficient if it was a query over issuer or shard
// TODO: However, the dataset is small enough to not matter much.
func (db *Database) GetAllCerts(ctx context.Context) (map[string]CertMetadata, error) {
	resp, err := db.Dynamo.Scan(ctx, &dynamodb.ScanInput{
		TableName: &db.Table,
		Select:    types.SelectAllAttributes,
	})
	if err != nil {
		return nil, err
	}

	var certList []CertMetadata
	err = attributevalue.UnmarshalListOfMaps(resp.Items, &certList)
	if err != nil {
		return nil, err
	}

	certs := make(map[string]CertMetadata, len(certList))
	for _, cert := range certList {
		certs[cert.CertKey.SerialString()] = cert
	}
	return certs, nil
}

// DeleteSerials takes a list of serials that we've seen in the CRL and thus
// no longer need to keep an eye out for.
func (db *Database) DeleteSerials(ctx context.Context, serialNumbers [][]byte) error {
	if len(serialNumbers) == 0 {
		return nil
	}
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

// StaticResolver is used in test and dev to use the local dynamodb
func StaticResolver(url string) func(service, region string, opts ...interface{}) (aws.Endpoint, error) {
	return func(service, region string, opts ...interface{}) (aws.Endpoint, error) {
		if service != dynamodb.ServiceID {
			return aws.Endpoint{}, &aws.EndpointNotFoundError{}
		}
		return aws.Endpoint{
			PartitionID: "aws",
			URL:         url,
		}, nil
	}
}
