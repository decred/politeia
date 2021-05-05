// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mysql

import (
	"database/sql"

	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
)

// sqlTx implements the store Tx interface using a sql transaction.
type sqlTx struct {
	mysql *mysql
	tx    *sql.Tx
}

// Put saves a key-value pair to the store.
//
// This function satisfies the store Tx interface.
func (s *sqlTx) Put(blobs map[string][]byte, encrypt bool) error {
	return s.mysql.put(blobs, encrypt, s.tx)
}

// Del deletes an entry from the store.
//
// This function satisfies the store Tx interface.
func (s *sqlTx) Del(keys []string) error {
	return s.mysql.del(keys, s.tx)
}

// Get retrieves entries from the store. An entry will not exist in the
// returned map if for any blobs that are not found. It is the responsibility
// of the caller to ensure a blob was returned for all provided keys.
//
// This function satisfies the store Tx interface.
func (s *sqlTx) Get(keys []string) (map[string][]byte, error) {
	return s.mysql.get(keys, s.tx)
}

// Rollback aborts the transaction.
//
// This function satisfies the store Tx interface.
func (s *sqlTx) Rollback() error {
	return s.tx.Rollback()
}

// Commit commits the transaction.
//
// This function satisfies the store Tx interface.
func (s *sqlTx) Commit() error {
	return s.tx.Commit()
}

// Tx returns a new database transaction as well as the cancel function that
// releases all resources associated with it.
//
// This function satisfies the store BlobKV interface.
func (s *mysql) Tx() (store.Tx, func(), error) {
	tx, cancel, err := s.beginTx()
	if err != nil {
		return nil, nil, err
	}

	return &sqlTx{
		mysql: s,
		tx:    tx,
	}, cancel, nil
}
