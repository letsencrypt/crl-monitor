package storage

import (
	"context"
	"fmt"
	"io"
	"log"

	"github.com/aws/aws-sdk-go-v2/config"
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

// The parameters used to fetch a unique item from storage.
type Key struct {
	Bucket, Object string
	Version        *string
}

func New(ctx context.Context) *Storage {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatalf("Error creating AWS config: %v", err)
	}

	s3Client := s3.NewFromConfig(cfg)
	return &Storage{S3Client: s3Client}
}

// Fetch gets a CRL from storage at a particular version
// The bucket and object names are required.
// If version is nil, the current version is returned.
// Returns the retrieved DER CRL bytes and what VersionID it was.
func (s *Storage) Fetch(ctx context.Context, key Key) ([]byte, string, error) {
	resp, err := s.S3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket:    &key.Bucket,
		Key:       &key.Object,
		VersionId: key.Version,
	})
	if err != nil {
		return nil, "", fmt.Errorf("retrieving CRL %s %s version %v: %w", key.Bucket, key.Object, key.Version, err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("reading CRL %s %s version %v: %w", key.Bucket, key.Object, key.Version, err)
	}

	return body, *resp.VersionId, err
}

// Previous returns the previous version of a CRL shard, which can then be fetched.
func (s *Storage) Previous(ctx context.Context, key Key) (string, error) {
	if key.Version == nil {
		return "", fmt.Errorf("Previous called with no Version")
	}
	resp, err := s.S3Client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
		Bucket: &key.Bucket,
		Prefix: &key.Object,
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

		if v.VersionId != nil && *v.VersionId == *key.Version {
			// This is the version of interest; select the next one
			found = true
		}
	}

	if (!found || prevVersion == nil) && resp.IsTruncated != nil && *resp.IsTruncated {
		return "", fmt.Errorf("too many versions and pagination not implemented! %+v", key)
	}

	if !found {
		return "", fmt.Errorf("current version wasn't found in non-truncated response")
	}

	if prevVersion == nil {
		return "", fmt.Errorf("current version found but no previous version")
	}

	return *prevVersion, nil
}
