// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package localdb

import (
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
	"github.com/syndtr/goleveldb/leveldb"
)

// tx implements the store Tx interface using leveldb.
type tx struct {
	localdb *localdb
	batch   *leveldb.Batch
}

// Put saves a key-value pair to the store.
//
// This function satisfies the store Tx interface.
func (s *tx) Put(blobs map[string][]byte, encrypt bool) error {
	return nil
}

// Del deletes an entry from the store.
//
// This function satisfies the store Tx interface.
func (s *tx) Del(keys []string) error {

	log.Debugf("Tx deleted blobs (%v)", len(keys))

	return nil
}

// Get retrieves entries from the store. An entry will not exist in the
// returned map if for any blobs that are not found. It is the responsibility
// of the caller to ensure a blob was returned for all provided keys.
//
// This function satisfies the store Tx interface.
func (s *tx) Get(keys []string) (map[string][]byte, error) {
	return nil, nil
}

// Rollback aborts the transaction.
//
// This function satisfies the store Tx interface.
func (s *tx) Rollback() error {
	// The only thing that needs to happen on rollback is the lock
	// being released. There are no leveldb resources that need to
	// be released.
	s.localdb.Unlock()

	log.Debugf("Tx rolled back")

	return nil
}

// Commit commits the transaction.
//
// This function satisfies the store Tx interface.
func (s *tx) Commit() error {
	// Write the transaction operations to disk
	err := s.localdb.db.Write(s.batch, nil)
	if err != nil {
		return err
	}

	// Release the lock that was held on tx creation
	s.localdb.Unlock()

	log.Debugf("Tx committed")

	return nil
}

// Tx returns a new database transaction as well as the cancel function that
// releases all resources associated with it.
//
// This function satisfies the store BlobKV interface.
func (l *localdb) Tx() (store.Tx, func(), error) {
	tx := &tx{
		localdb: l,
		batch:   new(leveldb.Batch),
	}

	// There is no way to perform a transaction on leveldb so we must
	// hold the lock for the duration of the tx. A batch of operations
	// are created then written to disk on tx commit. The lock is
	// released in one of three ways:
	// 1. The tx is committed.
	// 2. The tx is rolled backed.
	// 3. The cancel function is invoked.
	l.Lock()

	// Setup cancel function
	cancel := func() {
		// The only thing that needs to happen on cancelation is the
		// lock being released. There are no leveldb resources that need
		// to be released.
		l.Unlock()
	}

	return tx, cancel, nil
}
