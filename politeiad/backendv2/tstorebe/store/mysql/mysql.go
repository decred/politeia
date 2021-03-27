// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
	"github.com/decred/politeia/util"

	_ "github.com/go-sql-driver/mysql"
)

const (
	// Database options
	connTimeout     = 1 * time.Minute
	connMaxLifetime = 1 * time.Minute
	maxOpenConns    = 0 // 0 is unlimited
	maxIdleConns    = 100

	// Database table names
	tableNameKeyValue = "kv"
	tableNameNonce    = "nonce"
)

// tableKeyValue defines the key-value table.
const tableKeyValue = `
  k VARCHAR(255) NOT NULL PRIMARY KEY,
  v LONGBLOB NOT NULL
`

// tableNonce defines the table used to track the encryption nonce.
const tableNonce = `
  n BIGINT PRIMARY KEY AUTO_INCREMENT
`

var (
	_ store.BlobKV = (*mysql)(nil)
)

// mysql implements the store BlobKV interface using a mysql driver.
type mysql struct {
	shutdown uint64
	db       *sql.DB
	getNonce func(context.Context, *sql.Tx) ([24]byte, error)
	key      [32]byte
}

func ctxWithTimeout() (context.Context, func()) {
	return context.WithTimeout(context.Background(), connTimeout)
}

func (s *mysql) isShutdown() bool {
	return atomic.LoadUint64(&s.shutdown) != 0
}

func (s *mysql) put(blobs map[string][]byte, encrypt bool, ctx context.Context, tx *sql.Tx) error {
	// Encrypt blobs
	if encrypt {
		for k, v := range blobs {
			e, err := s.encrypt(ctx, tx, v)
			if err != nil {
				return fmt.Errorf("encrypt: %v", err)
			}
			blobs[k] = e
		}
	}

	// Save blobs
	for k, v := range blobs {
		_, err := tx.ExecContext(ctx,
			"INSERT INTO kv (k, v) VALUES (?, ?);", k, v)
		if err != nil {
			return fmt.Errorf("exec put: %v", err)
		}
	}

	return nil
}

// Put saves the provided key-value pairs to the store. This operation is
// performed atomically.
//
// This function satisfies the store BlobKV interface.
func (s *mysql) Put(blobs map[string][]byte, encrypt bool) error {
	log.Tracef("Put: %v blobs", len(blobs))

	if s.isShutdown() {
		return store.ErrShutdown
	}

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
	err = s.put(blobs, encrypt, ctx, tx)
	if err != nil {
		// Attempt to roll back the transaction
		if err2 := tx.Rollback(); err2 != nil {
			// We're in trouble!
			e := fmt.Sprintf("put: %v, unable to rollback: %v", err, err2)
			panic(e)
		}
		return err
	}

	// Commit transaction
	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("commit tx: %v", err)
	}

	log.Debugf("Saved blobs (%v) to store", len(blobs))

	return nil
}

// Del deletes the provided blobs from the store  This operation is performed
// atomically.
//
// This function satisfies the store BlobKV interface.
func (s *mysql) Del(keys []string) error {
	log.Tracef("Del: %v", keys)

	if s.isShutdown() {
		return store.ErrShutdown
	}

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
			return err
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

	if s.isShutdown() {
		return nil, store.ErrShutdown
	}

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

	// Decrypt data blobs
	for k, v := range reply {
		encrypted := isEncrypted(v)
		log.Tracef("Blob is encrypted: %v", encrypted)
		if !encrypted {
			continue
		}
		b, _, err := s.decrypt(v)
		if err != nil {
			return nil, fmt.Errorf("decrypt: %v", err)
		}
		reply[k] = b
	}

	return reply, nil
}

// Closes closes the blob store connection.
func (s *mysql) Close() {
	log.Tracef("Close")

	atomic.AddUint64(&s.shutdown, 1)

	// Zero the encryption key
	util.Zero(s.key[:])

	// Close mysql connection
	s.db.Close()
}

func New(appDir, host, user, password, dbname string) (*mysql, error) {
	// The password is required to derive the encryption key
	if password == "" {
		return nil, fmt.Errorf("password not provided")
	}

	// Connect to database
	log.Infof("MySQL host: %v:[password]@tcp(%v)/%v", user, host, dbname)

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
	q := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %v (%v)`,
		tableNameKeyValue, tableKeyValue)
	_, err = db.Exec(q)
	if err != nil {
		return nil, fmt.Errorf("create kv table: %v", err)
	}

	// Setup nonce table
	q = fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %v (%v)`,
		tableNameNonce, tableNonce)
	_, err = db.Exec(q)
	if err != nil {
		return nil, fmt.Errorf("create nonce table: %v", err)
	}

	// Setup mysql context
	s := &mysql{
		db: db,
	}
	s.getNonce = s.getDbNonce

	// Derive encryption key from password. Key is set in argon2idKey
	err = s.deriveEncryptionKey(password)
	if err != nil {
		return nil, fmt.Errorf("deriveEncryptionKey: %v", err)
	}

	return s, nil
}
