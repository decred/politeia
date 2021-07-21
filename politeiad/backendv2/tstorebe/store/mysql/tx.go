// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mysql

import (
	"database/sql"
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
	log.Tracef("Tx Put: %v blobs", len(blobs))

	return s.mysql.put(blobs, encrypt, s.tx)
}

// Del deletes an entry from the store.
//
// This function satisfies the store Tx interface.
func (s *sqlTx) Del(keys []string) error {
	log.Tracef("Tx Del: %v", keys)

	return s.mysql.del(keys, s.tx)
}

// Get retrieves entries from the store. An entry will not exist in the
// returned map if for any blobs that are not found. It is the responsibility
// of the caller to ensure a blob was returned for all provided keys.
//
// This function satisfies the store Tx interface.
func (s *sqlTx) Get(keys []string) (map[string][]byte, error) {
	log.Tracef("Tx Get: %v", keys)

	return s.mysql.get(keys, s.tx)
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
