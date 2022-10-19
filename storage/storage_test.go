package storage_test

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stretchr/testify/require"

	"github.com/letsencrypt/crl-monitor/storage/mock"
)

func TestStorage(t *testing.T) {
	storage := mock.New(t, "somebucket", map[string][]mock.MockObject{
		"123/0.crl": {
			{VersionID: "111", Data: []byte{0xaa, 0xbb}},
			{VersionID: "222", Data: []byte{0xcc, 0xdd}},
			{VersionID: "333", Data: []byte{0xee, 0xff}},
			{VersionID: "444", Data: []byte{0xab, 0xcd}},
		},
		"456/2.crl": {
			{VersionID: "singleton", Data: []byte{0x45, 0x02}},
		},
	})

	for _, tt := range []struct {
		name        string
		object      string
		version     *string
		expectedVer string
		expectedCRL []byte
	}{
		{
			name:        "nil version 1",
			object:      "123/0.crl",
			version:     nil,
			expectedVer: "111",
			expectedCRL: []byte{0xaa, 0xbb},
		}, {
			name:   "nil version 2",
			object: "456/2.crl", version: nil,
			expectedVer: "singleton",
			expectedCRL: []byte{0x45, 0x02},
		}, {
			name:        "first version",
			object:      "123/0.crl",
			version:     aws.String("111"),
			expectedVer: "111",
			expectedCRL: []byte{0xaa, 0xbb},
		}, {
			name:        "singleton version",
			object:      "456/2.crl",
			version:     aws.String("singleton"),
			expectedVer: "singleton",
			expectedCRL: []byte{0x45, 0x02},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			crl, version, err := storage.Fetch(context.Background(), "somebucket", tt.object, tt.version)
			require.NoError(t, err)
			require.Equal(t, tt.expectedVer, version)
			require.Equal(t, tt.expectedCRL, crl)
		})
	}

	for _, tt := range []struct {
		name        string
		object      string
		version     string
		expectedVer string
	}{
		{
			name:        "middle version",
			object:      "123/0.crl",
			version:     "222",
			expectedVer: "333",
		}, {
			name:        "first version",
			object:      "123/0.crl",
			version:     "111",
			expectedVer: "222",
		}, {
			name:        "last version",
			object:      "123/0.crl",
			version:     "333",
			expectedVer: "444",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			version, err := storage.Previous(context.Background(), "somebucket", tt.object, tt.version)
			require.NoError(t, err)
			require.Equal(t, tt.expectedVer, version)
		})
	}

	for _, tt := range []struct {
		name        string
		object      string
		version     string
		expectedVer string
	}{
		{
			name:    "no previous",
			object:  "123/0.crl",
			version: "444",
		}, {
			name:    "singleton",
			object:  "456/2.crl",
			version: "singleton",
		}, {
			name:    "not a real version",
			object:  "123/0.crl",
			version: "moo-cow",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			version, err := storage.Previous(context.Background(), "somebucket", tt.object, tt.version)
			require.Error(t, err)
			require.Equal(t, "", version)
		})
	}
}
