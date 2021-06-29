// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
	"github.com/decred/politeia/util"

	// MySQL driver.
	_ "github.com/go-sql-driver/mysql"
)

const (
	// Database options
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
	key      [32]byte
	testing  bool // Only set during unit tests
}

// isShutdown returns whether the mysql context has been shutdown.
func (s *mysql) isShutdown() bool {
	return atomic.LoadUint64(&s.shutdown) != 0
}

// beginTx returns a new sql transaction and the cancel function for the
// context that was used to create the transaction.
func (s *mysql) beginTx() (*sql.Tx, func(), error) {
	ctx, cancel := ctxForTx()

	opts := &sql.TxOptions{
		Isolation: sql.LevelDefault,
	}
	tx, err := s.db.BeginTx(ctx, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("begin tx: %v", err)
	}

	return tx, cancel, nil
}

// put saves the provided blobs to the kv store using the provided transaction.
func (s *mysql) put(blobs map[string][]byte, encrypt bool, tx *sql.Tx) error {
	// Setup context
	ctx, cancel := ctxForOp()
	defer cancel()

	// Encrypt blobs
	if encrypt {
		encrypted := make(map[string][]byte, len(blobs))
		for k, v := range blobs {
			e, err := s.encrypt(ctx, tx, v)
			if err != nil {
				return fmt.Errorf("encrypt: %v", err)
			}
			encrypted[k] = e
		}

		// Sanity check
		if len(encrypted) != len(blobs) {
			return fmt.Errorf("unexpected number of encrypted blobs")
		}

		blobs = encrypted
	}

	// Save blobs
	for k, v := range blobs {
		_, err := tx.ExecContext(ctx,
			"INSERT INTO kv (k, v) VALUES (?, ?);", k, v)
		if err != nil {
			return fmt.Errorf("exec put: %v", err)
		}
	}

	log.Debugf("Saved blobs (%v) to store", len(blobs))

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

	// Start transaction
	tx, cancel, err := s.beginTx()
	if err != nil {
		return err
	}
	defer cancel()

	// Save blobs
	err = s.put(blobs, encrypt, tx)
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

	return nil
}

// del deletes the provided blobs from the store using the provided
// transaction.
func (s *mysql) del(keys []string, tx *sql.Tx) error {
	// Setup context
	ctx, cancel := ctxForOp()
	defer cancel()

	// Delete blobs
	for _, v := range keys {
		_, err := tx.ExecContext(ctx, "DELETE FROM kv WHERE k IN (?);", v)
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

	log.Debugf("Deleted blobs (%v) from store", len(keys))

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

	// Start transaction
	tx, cancel, err := s.beginTx()
	if err != nil {
		return err
	}
	defer cancel()

	// Delete blobs
	err = s.del(keys, tx)
	if err != nil {
		return err
	}

	// Commit transaction
	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("commit: %v", err)
	}

	return nil
}

// querier describes the query method that is present on both the sql DB
// context and on the sql Tx context. This interface allows us to use the same
// code for executing individual queries and transaction queries.
type querier interface {
	QueryContext(context.Context, string, ...interface{}) (*sql.Rows, error)
}

// get returns blobs from the store for the provided keys. An entry will not
// exist in the returned map if for any blobs that are not found. It is the
// responsibility of the caller to ensure a blob was returned for all provided
// keys.
func (s *mysql) get(keys []string, q querier) (map[string][]byte, error) {
	// Converted the keys to []interface{}. The QueryContext method
	// will only accept them as interfaces.
	args := make([]interface{}, len(keys))
	for i, v := range keys {
		args[i] = v
	}

	// Setup context
	ctx, cancel := ctxForOp()
	defer cancel()

	// Get blobs
	rows, err := q.QueryContext(ctx, buildQuery(keys), args...)
	if err != nil {
		return nil, fmt.Errorf("query: %v", err)
	}
	defer rows.Close()

	// Unpack reply
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

	return s.get(keys, s.db)
}

// Tx returns a new database transaction as well as the cancel function that
// releases all resources associated with it.
//
// This function satisfies the store BlobKV interface.
func (s *mysql) Tx() (store.Tx, func(), error) {
	return newSqlTx(s)
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

// New returns a new mysql context.
func New(host, user, password, dbname string) (*mysql, error) {
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

	// Derive the encryption key from the password. This function saves
	// it to the mysql context.
	err = s.deriveEncryptionKey(password)
	if err != nil {
		return nil, fmt.Errorf("deriveEncryptionKey: %v", err)
	}

	return s, nil
}

const (
	// timeoutOp is the timeout for a single database operation.
	timeoutOp = 1 * time.Minute

	// timeoutTx is the timeout for a database transaction.
	timeoutTx = 3 * time.Minute
)

// ctxForOp returns a context and cancel function for a single database
// operation.
func ctxForOp() (context.Context, func()) {
	return context.WithTimeout(context.Background(), timeoutOp)
}

// ctxForTx returns a context and a cancel function for a database transaction.
func ctxForTx() (context.Context, func()) {
	return context.WithTimeout(context.Background(), timeoutTx)
}

// buildQuery builds and returns a SELECT query using the provided keys.
func buildQuery(keys []string) string {
	builder := strings.Builder{}

	// A placeholder parameter (?) is required for each key being
	// requested.
	//
	// Ex 3 keys: "SELECT k, v FROM kv WHERE k IN (?, ?, ?)"
	builder.WriteString("SELECT k, v FROM kv WHERE k IN (")
	for i := 0; i < len(keys); i++ {
		builder.WriteString("?")
		// Don't add a comma on the last one
		if i < len(keys)-1 {
			builder.WriteString(",")
		}
	}
	builder.WriteString(");")

	sql := builder.String()
	log.Tracef("%v", sql)

	return sql
}
