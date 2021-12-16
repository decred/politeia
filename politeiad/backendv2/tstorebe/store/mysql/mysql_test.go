// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mysql

import (
	"testing"

	"github.com/decred/politeia/unittest"
)

func TestBuildSelectStatements(t *testing.T) {
	var (
		// sizeLimit is the max number of placeholders
		// that the function will include in a single
		// select statement.
		sizeLimit = 2

		// Test keys
		key1 = "key1"
		key2 = "key2"
		key3 = "key3"
		key4 = "key4"
	)
	var tests = []struct {
		name       string
		keys       []string
		statements []selectStatement
	}{
		{
			"one statement under the size limit",
			[]string{key1},
			[]selectStatement{
				{
					Query: buildSelectQuery(1),
					Args:  []interface{}{key1},
				},
			},
		},
		{
			"one statement at the size limit",
			[]string{key1, key2},
			[]selectStatement{
				{
					Query: buildSelectQuery(2),
					Args:  []interface{}{key1, key2},
				},
			},
		},
		{
			"second statement under the size limit",
			[]string{key1, key2, key3},
			[]selectStatement{
				{
					Query: buildSelectQuery(2),
					Args:  []interface{}{key1, key2},
				},
				{
					Query: buildSelectQuery(1),
					Args:  []interface{}{key3},
				},
			},
		},
		{
			"second statement at the size limit",
			[]string{key1, key2, key3, key4},
			[]selectStatement{
				{
					Query: buildSelectQuery(2),
					Args:  []interface{}{key1, key2},
				},
				{
					Query: buildSelectQuery(2),
					Args:  []interface{}{key3, key4},
				},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Run the test
			statements := buildSelectStatements(tc.keys, sizeLimit)

			// Verify the output
			diff := unittest.DeepEqual(statements, tc.statements)
			if diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestBuildPlaceholders(t *testing.T) {
	var tests = []struct {
		placeholders int
		output       string
	}{
		{0, "()"},
		{1, "(?)"},
		{3, "(?,?,?)"},
	}
	for _, tc := range tests {
		t.Run("", func(t *testing.T) {
			output := buildPlaceholders(tc.placeholders)
			if output != tc.output {
				t.Errorf("got %v, want %v", output, tc.output)
			}
		})
	}
}
