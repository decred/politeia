// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"sync"
)

// nonce returns a new nonce value. This function guarantees that the returned
// nonce will be unique for every invocation.
//
// This function must be called using a transaction.
func (s *mysql) nonce(ctx context.Context, tx *sql.Tx) (int64, error) {
	// Create and retrieve new nonce value in an atomic database
	// transaction.
	_, err := tx.ExecContext(ctx, "INSERT INTO nonce () VALUES ();")
	if err != nil {
		return 0, fmt.Errorf("insert: %v", err)
	}
	rows, err := tx.QueryContext(ctx, "SELECT LAST_INSERT_ID();")
	if err != nil {
		return 0, fmt.Errorf("query: %v", err)
	}
	defer rows.Close()

	var nonce int64
	for rows.Next() {
		if nonce > 0 {
			// There should only ever be one row returned. Something is
			// wrong if we've already scanned the nonce and its still
			// scanning rows.
			return 0, fmt.Errorf("multiple rows returned for nonce")
		}
		err = rows.Scan(&nonce)
		if err != nil {
			return 0, fmt.Errorf("scan: %v", err)
		}
	}
	err = rows.Err()
	if err != nil {
		return 0, fmt.Errorf("next: %v", err)
	}
	if nonce == 0 {
		return 0, fmt.Errorf("invalid 0 nonce")
	}

	return nonce, nil
}

// testNonce is used to verify that nonce races do not occur. This function is
// meant to be run against an actual MySQL/MariaDB instance, not as a unit
// test.
func (s *mysql) testNonce(ctx context.Context, tx *sql.Tx) error {
	// Get nonce
	nonce, err := s.nonce(ctx, tx)
	if err != nil {
		return fmt.Errorf("nonce: %v", err)
	}

	// Save an empty blob to the kv store using the nonce as the key.
	// If a nonce is reused it will cause an error since the key must
	// be unique.
	k := strconv.FormatInt(nonce, 10)
	_, err = tx.ExecContext(ctx,
		"INSERT INTO kv (k, v) VALUES (?, ?);", k, []byte{})
	if err != nil {
		return fmt.Errorf("exec put: %v", err)
	}

	return nil
}

// testNonceIsUnique verifies that nonce races do not occur. This function
// is meant to be run against an actual MySQL/MariaDB instance, not as a unit
// test.
func (s *mysql) testNonceIsUnique() {
	log.Infof("Starting nonce concurrency test")

	// Run test
	var (
		wg      sync.WaitGroup
		threads = 1000
	)
	for i := 0; i < threads; i++ {
		// Increment the wait group counter
		wg.Add(1)

		go func() {
			// Decrement wait group counter on exit
			defer wg.Done()

			ctx, cancel := ctxWithTimeout()
			defer cancel()

			// Start transaction
			opts := &sql.TxOptions{
				Isolation: sql.LevelDefault,
			}
			tx, err := s.db.BeginTx(ctx, opts)
			if err != nil {
				log.Errorf("begin tx: %v", err)
				return
			}

			// Run nonce test
			err = s.testNonce(ctx, tx)
			if err != nil {
				// Attempt to roll back the transaction
				if err2 := tx.Rollback(); err2 != nil {
					// We're in trouble!
					log.Errorf("testNonce: %v, unable to rollback: %v", err, err2)
					return
				}
				log.Errorf("testNonce: %v", err)
				return
			}

			// Commit transaction
			err = tx.Commit()
			if err != nil {
				log.Errorf("commit tx: %v", err)
				return
			}
		}()
	}

	log.Infof("Waiting for nonce concurrency test to complete...")

	// Wait for all tests to complete
	wg.Wait()

	log.Infof("Nonce concurrency test complete")
}
