// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mysql

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/decred/politeia/unittest"
	"github.com/decred/politeia/util"
)

// newTestMySQL returns a new mysql structure that has been setup for testing.
func newTestMySQL(t *testing.T) (*mysql, func()) {
	t.Helper()

	// Setup the mock sql database
	opt := sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual)
	db, mock, err := sqlmock.New(opt)
	if err != nil {
		t.Fatal(err)
	}
	cleanup := func() {
		defer db.Close()
	}

	// Setup the mysql struct
	s := &mysql{
		db:      db,
		testing: true,
		mock:    mock,
	}

	// Derive a test encryption key
	password := "passwordsosikrit"
	s.argon2idKey(password, util.NewArgon2Params())

	return s, cleanup
}

func TestGet(t *testing.T) {
	// Setup the mysql test struct
	s, cleanup := newTestMySQL(t)
	defer cleanup()

	// Test the single query code path
	t.Run("single query", func(t *testing.T) {
		testGetSingleQuery(t, s)
	})

	// Test the multiple query code path
	t.Run("multi query", func(t *testing.T) {
		testGetMultiQuery(t, s)
	})
}

// testGetSingleQuery tests the mysql Get() method when the number of records
// being retrieved can be fit into a single MySQL SELECT statement.
func testGetSingleQuery(t *testing.T, s *mysql) {
	var (
		// Test params
		key1   = "key1"
		key2   = "key2"
		value1 = []byte("value1")
		value2 = []byte("value2")

		// rows contains the rows that will be returned
		// from the mocked sql query.
		rows = sqlmock.NewRows([]string{"k", "v"}).
			AddRow(key1, value1).
			AddRow(key2, value2)
	)

	// Setup the sql expectations
	s.mock.ExpectQuery("SELECT k, v FROM kv WHERE k IN (?,?);").
		WithArgs(key1, key2).
		WillReturnRows(rows).
		RowsWillBeClosed()

	// Run the test
	blobs, err := s.Get([]string{key1, key2})
	if err != nil {
		t.Error(err)
	}

	// Verify the sql expectations
	err = s.mock.ExpectationsWereMet()
	if err != nil {
		t.Error(err)
	}

	// Verify the returned value
	if len(blobs) != 2 {
		t.Errorf("got %v blobs, want 2", len(blobs))
	}
	v1 := blobs[key1]
	if !bytes.Equal(v1, value1) {
		t.Errorf("got '%s' for value 1; want '%s'", v1, value1)
	}
	v2 := blobs[key2]
	if !bytes.Equal(v2, value2) {
		t.Errorf("got '%s' for value 2; want '%s'", v2, value2)
	}
}

// testGetMultiQuery tests the mysql Get() method when the number of records
// being retrieved cannot fit into a single MySQL SELECT statement and must
// be broken up into multiple SELECT statements.
func testGetMultiQuery(t *testing.T, s *mysql) {
	// Prepare the test data. The maximum number of records
	// that can be returned in a single SELECT statement is
	// limited by the maxPlaceholders variable. We multiply
	// this by 2 in order to ensure that multiple queries
	// are required.
	var (
		keysCount = maxPlaceholders * 2
		keys      = make([]string, 0, keysCount)

		// These variables contain the rows that will be
		// returned from each mocked sql query.
		rows1 = sqlmock.NewRows([]string{"k", "v"})
		rows2 = sqlmock.NewRows([]string{"k", "v"})
	)
	for i := 0; i < keysCount; i++ {
		key := fmt.Sprintf("key%v", i)
		value := []byte(fmt.Sprintf("value%v", i))
		keys = append(keys, key)

		if i < keysCount/2 {
			// Add to the first query results
			rows1.AddRow(key, value)
		} else {
			// Add to the second query results
			rows2.AddRow(key, value)
		}
	}

	// Setup the sql expectations for both queries
	query := buildSelectQuery(keysCount / 2)
	s.mock.ExpectQuery(query).
		WillReturnRows(rows1).
		RowsWillBeClosed()
	s.mock.ExpectQuery(query).
		WillReturnRows(rows2).
		RowsWillBeClosed()

	// Run the test
	blobs, err := s.Get(keys)
	if err != nil {
		t.Errorf("multi query get failed; skipped printing " +
			"the error for readability")
	}

	// Verify the sql expectations
	err = s.mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("multi query sql expectations were not ; " +
			"met; skipped printing the error for readability")
	}

	// Verify the returned values contain entries from both
	// queries.
	var (
		idx1 = keysCount/2 - 1
		idx2 = keysCount/2 + 2

		key1 = fmt.Sprintf("key%v", idx1)
		key2 = fmt.Sprintf("key%v", idx2)

		value1 = []byte(fmt.Sprintf("value%v", idx1))
		value2 = []byte(fmt.Sprintf("value%v", idx2))
	)
	if len(blobs) != keysCount {
		t.Errorf("got %v blobs, want %v", len(blobs), keysCount)
	}
	v1 := blobs[key1]
	if !bytes.Equal(v1, value1) {
		t.Errorf("got '%s' for value 1; want '%s'", v1, value1)
	}
	v2 := blobs[key2]
	if !bytes.Equal(v2, value2) {
		t.Errorf("got '%s' for value 2; want '%s'", v2, value2)
	}
}

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
		name := fmt.Sprintf("%v placeholders", tc.placeholders)
		t.Run(name, func(t *testing.T) {
			output := buildPlaceholders(tc.placeholders)
			if output != tc.output {
				t.Errorf("got %v, want %v", output, tc.output)
			}
		})
	}
}
