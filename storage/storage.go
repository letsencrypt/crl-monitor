package storage

import (
	"context"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// s3client is fulfilled by s3.Client and is used for mocking in tests
type s3client interface {
	GetObject(ctx context.Context, input *s3.GetObjectInput, opts ...func(options *s3.Options)) (*s3.GetObjectOutput, error)
	ListObjectVersions(ctx context.Context, input *s3.ListObjectVersionsInput, opts ...func(options *s3.Options)) (*s3.ListObjectVersionsOutput, error)
}

type Storage struct {
	S3Client s3client
}

func New(awsConfig aws.Config) *Storage {
	s3Client := s3.NewFromConfig(awsConfig)
	return &Storage{S3Client: s3Client}
}

// Fetch gets a CRL from storage at a particular version
// The bucket and object names are required.
// If version is nil, the current version is returned.
// Returns the retrieved DER CRL bytes and what VersionID it was.
func (s *Storage) Fetch(ctx context.Context, bucket, object string, version *string) ([]byte, string, error) {
	resp, err := s.S3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket:    &bucket,
		Key:       &object,
		VersionId: version,
	})
	if err != nil {
		return nil, "", fmt.Errorf("error retrieving CRL %s %s version %v: %w", bucket, object, version, err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("error reading CRL %s %s version %v: %w", bucket, object, version, err)
	}

	return body, *resp.VersionId, err
}

// Previous returns the previous version of a CRL shard, which can then be fetched.
func (s *Storage) Previous(ctx context.Context, bucket, object, version string) (string, error) {
	resp, err := s.S3Client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
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

	if (!found || prevVersion == nil) && resp.IsTruncated != nil && *resp.IsTruncated {
		return "", fmt.Errorf("too many versions and pagination not implemented! %s %s %s", bucket, object, version)
	}

	if !found {
		return "", fmt.Errorf("current version wasn't found in non-truncated response")
	}

	if prevVersion == nil {
		return "", fmt.Errorf("current version found but no previous version")
	}

	return *prevVersion, nil
}
