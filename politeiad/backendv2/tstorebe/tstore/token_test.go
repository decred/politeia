// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tstore

import (
	"testing"
)

func TestShortTokenKey(t *testing.T) {
	// Setup test data
	var (
		fullTokenHex  = "58d9f4664777775d"
		shortTokenHex = "58d9f46"
		key           = shortTokenKeyPrefix + shortTokenHex
	)
	fullToken, err := tokenDecode(fullTokenHex)
	if err != nil {
		t.Fatal(err)
	}
	shortToken, err := tokenDecode(shortTokenHex)
	if err != nil {
		t.Fatal(err)
	}

	// Setup tests
	var tests = []struct {
		name   string
		input  []byte
		output string
	}{
		{
			"short token input",
			shortToken,
			key,
		},
		{
			"full token input",
			fullToken,
			key,
		},
	}

	// Run tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			k, err := shortTokenKey(tc.input)
			if err != nil {
				t.Error(err)
			}
			if k != tc.output {
				t.Errorf("got %v, want %v", k, tc.output)
			}
		})
	}
}
