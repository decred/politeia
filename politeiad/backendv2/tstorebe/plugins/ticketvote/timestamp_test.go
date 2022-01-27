// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import (
	"encoding/hex"
	"testing"
)

func TestGetVoteTimestampKey(t *testing.T) {
	token := "45154fb45664714b"

	// Setup tests
	tests := []struct {
		name        string
		token       string
		page        uint32
		index       uint32
		shouldError bool
		cacheKey    string
	}{
		{
			name:        "success case 1",
			token:       token,
			page:        1,
			index:       0,
			shouldError: false,
			cacheKey:    "timestamp-vote-45154fb-1-0",
		},
		{
			name:        "success case 2",
			token:       token,
			page:        3,
			index:       9,
			shouldError: false,
			cacheKey:    "timestamp-vote-45154fb-3-9",
		},
		{
			name:        "invalid token",
			token:       "",
			page:        1,
			index:       9,
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
			cacheKey, err := getVoteTimestampKey(tokenb, tc.page, tc.index)
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

func TestGetAuthTimestampKey(t *testing.T) {
	token := "45154fb45664714b"

	// Setup tests
	tests := []struct {
		name        string
		token       string
		index       uint32
		shouldError bool
		cacheKey    string
	}{
		{
			name:        "success case 1",
			token:       token,
			index:       0,
			shouldError: false,
			cacheKey:    "timestamp-auth-45154fb-0",
		},
		{
			name:        "success case 2",
			token:       token,
			index:       255,
			shouldError: false,
			cacheKey:    "timestamp-auth-45154fb-255",
		},
		{
			name:        "invalid token",
			token:       "",
			index:       9,
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
			cacheKey, err := getAuthTimestampKey(tokenb, tc.index)
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

func TestGetDetailsTimestampKey(t *testing.T) {
	token := "45154fb45664714b"

	// Setup tests
	tests := []struct {
		name        string
		token       string
		shouldError bool
		cacheKey    string
	}{
		{
			name:        "success case 1",
			token:       token,
			shouldError: false,
			cacheKey:    "timestamp-details-45154fb",
		},
		{
			name:        "invalid token",
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
			cacheKey, err := getDetailsTimestampKey(tokenb)
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

func TestParseVoteTimestampKey(t *testing.T) {
	// Setup tests
	tests := []struct {
		name        string
		cacheKey    string
		shouldError bool
		index       uint32
	}{
		{
			name:        "success case",
			cacheKey:    "timestamp-vote-45154fb-1-8",
			shouldError: false,
			index:       8,
		},
		{
			name:        "invalid key",
			cacheKey:    "--",
			shouldError: true,
			index:       0,
		},
	}

	// Run tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			index, err := parseVoteTimestampKey(tc.cacheKey)
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
				if index != tc.index {
					// Expected key was not found, error
					t.Errorf("unexpected index; want: %v, got: %v", tc.index, index)
				}
				return
			}
		})
	}
}

func TestParseAuthTimestampKey(t *testing.T) {
	// Setup tests
	tests := []struct {
		name        string
		cacheKey    string
		shouldError bool
		index       uint32
	}{
		{
			name:        "success case",
			cacheKey:    "timestamp-auth-45154fb-109",
			shouldError: false,
			index:       109,
		},
		{
			name:        "invalid key",
			cacheKey:    "---",
			shouldError: true,
			index:       0,
		},
	}

	// Run tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			index, err := parseAuthTimestampKey(tc.cacheKey)
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
				if index != tc.index {
					// Expected key was not found, error
					t.Errorf("unexpected index; want: %v, got: %v", tc.index, index)
				}
				return
			}
		})
	}
}
