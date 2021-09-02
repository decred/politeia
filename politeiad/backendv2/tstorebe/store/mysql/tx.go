// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mysql

import (
	"database/sql"

	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
)

var (
	_ store.Tx = (*sqlTx)(nil)
)

// sqlTx implements the store Tx interface using a sql transaction.
type sqlTx struct {
	mysql *mysql
	tx    *sql.Tx
}

// newTx returns a new sqlTx and the cancel function that releases all
// resources associated with the tx.
func newSqlTx(mysql *mysql) (*sqlTx, func(), error) {
	tx, cancel, err := mysql.beginTx()
	if err != nil {
		return nil, nil, err
	}

	return &sqlTx{
		mysql: mysql,
		tx:    tx,
	}, cancel, nil
}

// Insert inserts a new entry into the key-value store for each of the provided
// key-value pairs.
//
// An ErrDuplicateKey is returned if a provided key already exists in the
// key-value store.
//
// This function satisfies the store Tx interface.
func (s *sqlTx) Insert(blobs map[string][]byte, encrypt bool) error {
	log.Tracef("Tx Insert: %v blobs", len(blobs))

	return s.mysql.insert(blobs, encrypt, s.tx)
}

// Update updates the provided key-value pairs in the store.
//
// An ErrNotFound is returned if the caller attempts to update an entry that
// does not exist.
//
// This function satisfies the store Tx interface.
func (s *sqlTx) Update(blobs map[string][]byte, encrypt bool) error {
	log.Tracef("Tx Update: %v blobs", len(blobs))

	return s.mysql.update(blobs, encrypt, s.tx)
}

// Del deletes the provided blobs from the store.
//
// Keys that do not correspond to blob entries are ignored. An error IS NOT
// returned.
//
// This function satisfies the store Tx interface.
func (s *sqlTx) Del(keys []string) error {
	log.Tracef("Tx Del: %v", keys)

	return s.mysql.del(keys, s.tx)
}

// Get returns the blob for the provided key.
//
// An ErrNotFound error is returned if the key does not correspond to an entry.
//
// This function satisfies the store Tx interface.
func (s *sqlTx) Get(key string) ([]byte, error) {
	log.Tracef("Tx Get: %v", key)

	blobs, err := s.mysql.getBatch([]string{key}, s.tx)
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
func (s *sqlTx) GetBatch(keys []string) (map[string][]byte, error) {
	log.Tracef("Tx GetBatch: %v", keys)

	return s.mysql.getBatch(keys, s.tx)
}

// Rollback aborts the transaction.
//
// This function satisfies the store Tx interface.
func (s *sqlTx) Rollback() error {
	log.Tracef("Tx Rollback")

	return s.tx.Rollback()
}

// Commit commits the transaction.
//
// This function satisfies the store Tx interface.
func (s *sqlTx) Commit() error {
	log.Tracef("Tx Commit")

	return s.tx.Commit()
}
