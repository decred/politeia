// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package localdb

import (
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
	"github.com/syndtr/goleveldb/leveldb"
)

var (
	_ store.Tx = (*tx)(nil)
)

// tx implements the store Tx interface using leveldb.
//
// leveldb does not support transactions, but we are able to implement our own
// transaction by locking against concurrent access on transaction
// initialization then using leveldb's atomic batch writes to put/del data when
// the caller commits the transaction. The lock is not released until the
// transaction is committed, rolled back, or canceled.
type tx struct {
	localdb *localdb
	batch   *leveldb.Batch

	// The cancel function starts off as a function that releases the
	// localdb lock when invoked. This allows the caller to defer
	// invocation of it in order to handle any unexpected errors. Once
	// the tx has been committed or rolled back this cancel function is
	// replaced with an empty function where any future invocations do
	// nothing. This prevents deferred invocations from trying to
	// unlock a mutex that is already unlocked and causing a panic.
	cancel func()
}

// newTx returns a new localdb tx and the cancel function that releases all
// resources associated with the tx.
func newTx(localdb *localdb) (*tx, func()) {
	// There is no way to perform a transaction on leveldb so we must
	// hold the lock for the duration of the tx. A batch of operations
	// are created then written to disk on tx commit. The lock is
	// released in one of three ways:
	// 1. The tx is committed.
	// 2. The tx is rolled backed.
	// 3. The cancel function is invoked.
	localdb.Lock()

	// Setup transaction
	t := &tx{
		localdb: localdb,
		batch:   new(leveldb.Batch),
		cancel: func() {
			// The only thing that needs to happen on cancelation is the
			// lock being released. There are no leveldb resources that
			// need to be released.
			localdb.Unlock()
		},
	}

	return t, func() {
		// The cancel function uses the tx.cancel() method instead of
		// just returning a closure that unlocks the mutex so that the
		// tx.cancel() method can be replaced with a empty function once
		// the tx has been committed or rolled back. The point of the
		// cancel function is to allow the caller to defer its invocation
		// in order to handle unexpected errors. Once the tx has been
		// committed or rolled back the tx.cancel() method is replaced
		// with an empty function where any future invocations do
		// nothing. This prevents deferred invocations from trying to
		// unlock a mutex that is already unlocked and causing a panic.
		t.cancel()
	}
}

// Insert inserts a new entry into the key-value store for each of the provided
// key-value pairs.
//
// An ErrDuplicateKey is returned if a provided key already exists in the
// key-value store.
//
// This function satisfies the store Tx interface.
func (t *tx) Insert(blobs map[string][]byte, encrypt bool) error {
	log.Tracef("Tx Insert: %v blobs", len(blobs))

	return t.localdb.insert(blobs, encrypt, t.batch)
}

// Update updates the provided key-value pairs in the store.
//
// An ErrNotFound is returned if the caller attempts to update an entry that
// does not exist.
//
// This function satisfies the store Tx interface.
func (t *tx) Update(blobs map[string][]byte, encrypt bool) error {
	log.Tracef("Tx Update: %v blobs", len(blobs))

	return t.localdb.update(blobs, encrypt, t.batch)
}

// Del deletes the provided blobs from the store.
//
// Keys that do not correspond to blob entries are ignored. An error IS NOT
// returned.
//
// This function satisfies the store Tx interface.
func (t *tx) Del(keys []string) error {
	log.Tracef("Tx Del: %v", keys)

	return t.localdb.del(keys, t.batch)
}

// Get returns the blob for the provided key.
//
// An ErrNotFound error is returned if the key does not correspond to an entry.
//
// This function satisfies the store Tx interface.
func (t *tx) Get(key string) ([]byte, error) {
	log.Tracef("Tx Get: %v", key)

	blobs, err := t.localdb.getBatch([]string{key})
	if err != nil {
		return nil, err
	}
	b, ok := blobs[key]
	if !ok {
		return nil, store.ErrNotFound
	}

	return b, nil
}

// GetBatch returns the blobs for the provided keys.
//
// An entry will not exist in the returned map if for any blobs that are not
// found. It is the responsibility of the caller to ensure a blob was returned
// for all provided keys. An error is not returned.
//
// This function satisfies the store Tx interface.
func (t *tx) GetBatch(keys []string) (map[string][]byte, error) {
	log.Tracef("Tx GetBatch: %v", keys)

	return t.localdb.getBatch(keys)
}

// Rollback aborts the transaction.
//
// This function satisfies the store Tx interface.
func (t *tx) Rollback() error {
	// The only thing that needs to happen on rollback is the lock
	// being released. There are no leveldb resources that need to
	// be released.
	t.localdb.Unlock()

	// The cancel function should do nothing when invoked now
	// that the tx has been rolled back.
	t.cancel = func() {}

	log.Debugf("Tx rolled back")

	return nil
}

// Commit commits the transaction.
//
// This function satisfies the store Tx interface.
func (t *tx) Commit() error {
	// Write the transaction operations to disk
	err := t.localdb.db.Write(t.batch, nil)
	if err != nil {
		return err
	}

	// Release the lock that was held on tx creation
	t.localdb.Unlock()

	// The cancel function should do nothing when invoked now
	// that the tx has been committed.
	t.cancel = func() {}

	log.Debugf("Tx committed")

	return nil
}
