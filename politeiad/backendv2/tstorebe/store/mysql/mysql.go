// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
	"github.com/google/uuid"

	_ "github.com/go-sql-driver/mysql"
)

const (
	// Database options
	connTimeout     = 1 * time.Minute
	connMaxLifetime = 1 * time.Minute
	maxOpenConns    = 0 // 0 is unlimited
	maxIdleConns    = 100
)

// tableKeyValue defines the key-value table. The key is a uuid.
const tableKeyValue = `
  k VARCHAR(38) NOT NULL PRIMARY KEY,
  v LONGBLOB NOT NULL
`

var (
	_ store.BlobKV = (*mysql)(nil)
)

// mysql implements the store BlobKV interface using a mysql driver.
type mysql struct {
	db *sql.DB
}

func ctxWithTimeout() (context.Context, func()) {
	return context.WithTimeout(context.Background(), connTimeout)
}

func (s *mysql) put(blobs map[string][]byte) error {
	ctx, cancel := ctxWithTimeout()
	defer cancel()

	// Start transaction
	opts := &sql.TxOptions{
		Isolation: sql.LevelDefault,
	}
	tx, err := s.db.BeginTx(ctx, opts)
	if err != nil {
		return fmt.Errorf("begin tx: %v", err)
	}

	// Save blobs
	for k, v := range blobs {
		_, err = tx.ExecContext(ctx, "INSERT INTO kv (k, v) VALUES (?, ?);", k, v)
		if err != nil {
			// Attempt to roll back the transaction
			if err2 := tx.Rollback(); err2 != nil {
				// We're in trouble!
				e := fmt.Sprintf("put: %v, unable to rollback: %v", err, err2)
				panic(e)
			}
		}
	}

	// Commit transaction
	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("commit tx: %v", err)
	}

	log.Debugf("Saved blobs (%v) to store", len(blobs))

	return nil
}

// Put saves the provided blobs to the store  The keys for the blobs are
// returned using the same odering that the blobs were provided in. This
// operation is performed atomically.
//
// This function satisfies the store BlobKV interface.
func (s *mysql) Put(blobs [][]byte) ([]string, error) {
	log.Tracef("Put: %v blobs", len(blobs))

	// Setup the keys. The keys are returned in the same order that
	// the blobs are in.
	var (
		keys   = make([]string, 0, len(blobs))
		blobkv = make(map[string][]byte, len(blobs))
	)
	for _, v := range blobs {
		k := uuid.New().String()
		keys = append(keys, k)
		blobkv[k] = v
	}

	// Save blobs
	err := s.put(blobkv)
	if err != nil {
		return nil, err
	}

	// Return the keys
	return keys, nil
}

// PutKV saves the provided blobs to the store. This method allows the caller
// to specify the key instead of having the store create one. This operation is
// performed atomically.
//
// This function satisfies the store BlobKV interface.
func (s *mysql) PutKV(blobs map[string][]byte) error {
	log.Tracef("PutKV: %v blobs", len(blobs))

	return s.put(blobs)
}

// Del deletes the provided blobs from the store  This operation is performed
// atomically.
//
// This function satisfies the store BlobKV interface.
func (s *mysql) Del(keys []string) error {
	log.Tracef("Del: %v", keys)

	ctx, cancel := ctxWithTimeout()
	defer cancel()

	// Start transaction
	opts := &sql.TxOptions{
		Isolation: sql.LevelDefault,
	}
	tx, err := s.db.BeginTx(ctx, opts)
	if err != nil {
		return err
	}

	// Delete blobs
	for _, v := range keys {
		_, err = tx.ExecContext(ctx, "DELETE FROM kv WHERE k IN (?);", v)
		if err != nil {
			// Attempt to roll back the transaction
			if err2 := tx.Rollback(); err2 != nil {
				// We're in trouble!
				e := fmt.Sprintf("del: %v, unable to rollback: %v", err, err2)
				panic(e)
			}
		}
	}

	// Commit transaction
	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("commit: %v", err)
	}

	log.Debugf("Deleted blobs (%v) from store", len(keys))

	return nil
}

// Get returns blobs from the store for the provided keys. An entry will not
// exist in the returned map if for any blobs that are not found. It is the
// responsibility of the caller to ensure a blob was returned for all provided
// keys.
//
// This function satisfies the store BlobKV interface.
func (s *mysql) Get(keys []string) (map[string][]byte, error) {
	log.Tracef("Get: %v", keys)

	ctx, cancel := ctxWithTimeout()
	defer cancel()

	// Build query. A placeholder parameter (?) is required for each
	// key being requested.
	//
	// Ex 3 keys: "SELECT k, v FROM kv WHERE k IN (?, ?, ?)"
	sql := "SELECT k, v FROM kv WHERE k IN ("
	for i := 0; i < len(keys); i++ {
		sql += "?"
		// Don't add a comma on the last one
		if i < len(keys)-1 {
			sql += ","
		}
	}
	sql += ");"

	log.Tracef("%v", sql)

	// The keys must be converted to []interface{} for the query method
	// to accept them.
	args := make([]interface{}, len(keys))
	for i, v := range keys {
		args[i] = v
	}

	// Get blobs
	rows, err := s.db.QueryContext(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("query: %v", err)
	}
	defer rows.Close()

	reply := make(map[string][]byte, len(keys))
	for rows.Next() {
		var k string
		var v []byte
		err = rows.Scan(&k, &v)
		if err != nil {
			return nil, fmt.Errorf("scan: %v", err)
		}
		reply[k] = v
	}
	err = rows.Err()
	if err != nil {
		return nil, fmt.Errorf("next: %v", err)
	}

	return reply, nil
}

// Closes closes the blob store connection.
func (s *mysql) Close() {
	s.db.Close()
}

func New(host, user, password, dbname string) (*mysql, error) {
	// Connect to database
	log.Infof("Host: %v:[password]@tcp(%v)/%v", user, host, dbname)

	h := fmt.Sprintf("%v:%v@tcp(%v)/%v", user, password, host, dbname)
	db, err := sql.Open("mysql", h)
	if err != nil {
		return nil, err
	}

	// Setup database options
	db.SetConnMaxLifetime(connMaxLifetime)
	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)

	// Verify database connection
	err = db.Ping()
	if err != nil {
		return nil, fmt.Errorf("db ping: %v", err)
	}

	// Setup key-value table
	q := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS kv (%s)`, tableKeyValue)
	_, err = db.Exec(q)
	if err != nil {
		return nil, fmt.Errorf("create table: %v", err)
	}

	return &mysql{
		db: db,
	}, nil
}
