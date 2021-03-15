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

// testNonce is used to verify that nonce races do not occur. This function
// is meant to be run against an actual MySQL/MariaDB instance, not as a unit
// test.
func (s *mysql) testNonce(ctx context.Context, tx *sql.Tx) error {
	// Create a new nonce value
	err := s.insertNonce(ctx, tx)
	if err != nil {
		return fmt.Errorf("insert nonce: %v", err)
	}

	// Get the nonce value that was just created
	nonce, err := s.queryNonce(ctx, tx)
	if err != nil {
		return fmt.Errorf("query nonce: %v", err)
	}

	// Save a empty blob to the kv store using the nonce as the key.
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
func (s *mysql) testNonceIsUnique() error {
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

			// Save blobs
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

	log.Infof("Nonce concurrency test success!")

	return nil
}
