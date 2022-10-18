package storage

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type Storage struct {
	s3Client *s3.Client
}

func New(awsConfig aws.Config) *Storage {
	s3Client := s3.NewFromConfig(awsConfig)
	return &Storage{s3Client: s3Client}
}

// Fetch gets a CRL from storage at a particular version
func (s *Storage) Fetch(ctx context.Context, bucket, object string, version *string) (*x509.RevocationList, string, error) {
	resp, err := s.s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket:    &bucket,
		Key:       &object,
		VersionId: version,
	})
	if err != nil {
		return nil, "", fmt.Errorf("error retrieving CRL %s %s version %s: %w", bucket, object, version, err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("error reading CRL %s %s version %v: %w", bucket, object, version, err)
	}

	fmt.Printf("Fetched %s/%s version %v: len %d\n", bucket, object, version, len(body))

	parsed, err := x509.ParseRevocationList(body)
	fmt.Printf("   CRL %d with %d entries\n", parsed.Number, len(parsed.RevokedCertificates))

	return parsed, *resp.VersionId, err
}

// Previous returns the previous version of a CRL shard, which can then be fetched.
func (s *Storage) Previous(ctx context.Context, bucket, object, version string) (string, error) {

	resp, err := s.s3Client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
		Bucket: &bucket,
		Prefix: &object,
	})
	if err != nil {
		return "", err
	}

	var prevVersion *string
	found := false
	for _, v := range resp.Versions {
		if found {
			prevVersion = v.VersionId
			break
		}

		if v.VersionId != nil && *v.VersionId == version {
			// This is the version of interest; select the next one
			found = true
		}
	}

	if (!found || prevVersion == nil) && resp.IsTruncated {
		return "", fmt.Errorf("too many versions and pagination not implemented! %s %s %s", bucket, object, version)
	}

	if !found {
		return "", fmt.Errorf("current version wasn't found in non-truncated response")
	}

	if prevVersion == nil {
		return "", fmt.Errorf("current version found but no previous version")
	}

	fmt.Printf("%s/%s Version %s Previous: %s\n", bucket, object, version, *prevVersion)

	return *prevVersion, nil
}
