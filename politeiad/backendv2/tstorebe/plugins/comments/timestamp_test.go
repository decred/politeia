// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package comments

import (
	"encoding/hex"
	"testing"
)

func TestGetTimestampKey(t *testing.T) {
	token := "45154fb45664714b"

	// Setup tests
	tests := []struct {
		name        string
		commentID   uint32
		token       string
		shouldError bool
		cacheKey    string
	}{
		{
			name:        "success case",
			commentID:   8,
			token:       token,
			shouldError: false,
			cacheKey:    "timestamp-45154fb-8",
		},
		{
			name:        "invalid token",
			commentID:   1,
			token:       "",
			shouldError: true,
			cacheKey:    "",
		},
	}

	// Run tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Convert token to []byte if set
			var (
				tokenb []byte
				err    error
			)
			if tc.token != "" {
				tokenb, err = hex.DecodeString(tc.token)
				if err != nil {
					t.Fatal(err)
				}
			}
			cacheKey, err := getTimestampKey(tokenb, tc.commentID)
			switch {
			case tc.shouldError && err == nil:
				// Wanted an error but didn't get one
				t.Errorf("want error got nil")
				return

			case !tc.shouldError && err != nil:
				// Wanted success but got an error
				t.Errorf("want error nil, got '%v'", err)
				return

			case !tc.shouldError && err == nil:
				// Verify result
				if cacheKey != tc.cacheKey {
					// Expected key was not found, error
					t.Errorf("unexpected cache key; want: %v, got: %v", tc.cacheKey,
						cacheKey)
				}
				return
			}
		})
	}
}

func TestParseTimestampKey(t *testing.T) {
	// Setup tests
	tests := []struct {
		name        string
		cacheKey    string
		shouldError bool
		commentID   uint32
	}{
		{
			name:        "success case",
			cacheKey:    "timestamp-45154fb-8",
			shouldError: false,
			commentID:   8,
		},
		{
			name:        "invalid key",
			cacheKey:    "--",
			shouldError: true,
			commentID:   0,
		},
	}

	// Run tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cid, err := parseTimestampKey(tc.cacheKey)
			switch {
			case tc.shouldError && err == nil:
				// Wanted an error but didn't get one
				t.Errorf("want error got nil")
				return

			case !tc.shouldError && err != nil:
				// Wanted success but got an error
				t.Errorf("want error nil, got '%v'", err)
				return

			case !tc.shouldError && err == nil:
				// Verify result
				if cid != tc.commentID {
					// Expected key was not found, error
					t.Errorf("unexpected comment ID; want: %v, got: %v", tc.commentID,
						cid)
				}
				return
			}
		})
	}
}
