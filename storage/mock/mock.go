package mock

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/require"

	"github.com/letsencrypt/crl-monitor/storage"
)

// MockObject is a single version of an object
type MockObject struct {
	VersionID string
	Data      []byte
}

// New mock storage.  Takes a bucket and mock data.
// The data is a map of object name -> list of versions
func New(t *testing.T, bucket string, mockData map[string][]MockObject) *storage.Storage {
	return &storage.Storage{S3Client: &s3mock{t: t, bucket: bucket, mockData: mockData}}
}

type s3mock struct {
	t        *testing.T
	bucket   string
	mockData map[string][]MockObject
}

func (s *s3mock) GetObject(ctx context.Context, input *s3.GetObjectInput, opts ...func(options *s3.Options)) (*s3.GetObjectOutput, error) {
	require.Empty(s.t, opts, "options not supported")
	require.NotNil(s.t, input)
	require.NotNil(s.t, input.Bucket)
	require.Equal(s.t, s.bucket, *input.Bucket)
	require.NotNil(s.t, input.Key)

	object, ok := s.mockData[*input.Key]
	require.True(s.t, ok, "object not found: %s", *input.Key)

	versionID := input.VersionId
	if input.VersionId == nil {
		versionID = aws.String(object[0].VersionID)
	}

	for _, version := range object {
		if version.VersionID == *versionID {
			return &s3.GetObjectOutput{
				Body:      io.NopCloser(bytes.NewReader(version.Data)),
				VersionId: versionID,
			}, nil
		}
	}

	return nil, fmt.Errorf("object version not found: %s %s", *input.Key, *versionID)
}

func (s *s3mock) ListObjectVersions(ctx context.Context, input *s3.ListObjectVersionsInput, opts ...func(options *s3.Options)) (*s3.ListObjectVersionsOutput, error) {
	require.Empty(s.t, opts, "options not supported")
	require.NotNil(s.t, input)
	require.NotNil(s.t, input.Bucket)
	require.Equal(s.t, s.bucket, *input.Bucket)
	require.NotNil(s.t, input.Prefix)

	object, ok := s.mockData[*input.Prefix]
	require.True(s.t, ok, "object not found: %s", *input.Prefix)

	resp := &s3.ListObjectVersionsOutput{}
	for _, version := range object {
		resp.Versions = append(resp.Versions, types.ObjectVersion{VersionId: aws.String(version.VersionID)})
	}

	return resp, nil
}
