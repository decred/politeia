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
	"github.com/pkg/errors"

	driver "github.com/go-sql-driver/mysql" // MySQL driver
)

const (
	// Database options
	connMaxLifetime = 1 * time.Minute
	maxOpenConns    = 0 // 0 is unlimited
	maxIdleConns    = 100

	// Database table names
	tableNameKeyValue = "kv"
	tableNameNonce    = "nonce"

	// timeoutOp is the timeout for a single database operation.
	timeoutOp = 1 * time.Minute

	// timeoutTx is the timeout for a database transaction.
	timeoutTx = 5 * time.Minute
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

// New returns a new mysql context.
func New(host, user, password, dbname string) (*mysql, error) {
	// The password is required to derive the encryption key
	if password == "" {
		return nil, errors.Errorf("password not provided")
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
		return nil, errors.Errorf("ping mysql: %v", err)
	}

	// Setup key-value table
	q := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %v (%v)`,
		tableNameKeyValue, tableKeyValue)
	_, err = db.Exec(q)
	if err != nil {
		return nil, errors.Errorf("create kv table: %v", err)
	}

	// Setup nonce table
	q = fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %v (%v)`,
		tableNameNonce, tableNonce)
	_, err = db.Exec(q)
	if err != nil {
		return nil, errors.Errorf("create nonce table: %v", err)
	}

	// Setup mysql context
	s := &mysql{
		db: db,
	}

	// Derive the encryption key from the password and
	// set the mysql context encryption key field.
	err = s.deriveEncryptionKey(password)
	if err != nil {
		return nil, err
	}

	// Verify that all database operations are working as
	// expected. These are not expensive and should only
	// take a second to run.
	log.Infof("Verifying key-value store operations")

	err = store.TestBlobKV(s)
	if err != nil {
		return nil, err
	}
	err = store.TestTx(s)
	if err != nil {
		return nil, err
	}

	return s, nil
}

// Insert inserts a new entry into the key-value store for each of the provided
// key-value pairs. This operation is atomic.
//
// An ErrDuplicateKey is returned if a provided key already exists in the
// key-value store.
//
// This function satisfies the store BlobKV interface.
func (s *mysql) Insert(blobs map[string][]byte, encrypt bool) error {
	log.Tracef("Insert: %v blobs", len(blobs))

	if s.isShutdown() {
		return store.ErrShutdown
	}

	// Start transaction
	tx, cancel, err := s.beginTx()
	if err != nil {
		return err
	}
	defer cancel()

	// Insert blobs
	err = s.insert(blobs, encrypt, tx)
	if err != nil {
		// Attempt to roll back the transaction
		if err2 := tx.Rollback(); err2 != nil {
			// We're in trouble!
			e := fmt.Sprintf("insert: %v, unable to rollback: %v", err, err2)
			panic(e)
		}
		return err
	}

	// Commit transaction
	err = tx.Commit()
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

// Update updates the provided key-value pairs in the store. This operation is
// atomic.
//
// An ErrNotFound is returned if the caller attempts to update an entry that
// does not exist.
func (s *mysql) Update(blobs map[string][]byte, encrypt bool) error {
	log.Tracef("Update: %v blobs", len(blobs))

	if s.isShutdown() {
		return store.ErrShutdown
	}

	// Start transaction
	tx, cancel, err := s.beginTx()
	if err != nil {
		return err
	}
	defer cancel()

	// Update blobs
	err = s.update(blobs, encrypt, tx)
	if err != nil {
		// Attempt to roll back the transaction
		if err2 := tx.Rollback(); err2 != nil {
			// We're in trouble!
			e := fmt.Sprintf("update: %v, unable to rollback: %v", err, err2)
			panic(e)
		}
		return err
	}

	// Commit transaction
	err = tx.Commit()
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

// Del deletes the provided blobs from the store. This operation is atomic.
//
// Keys that do not correspond to blob entries are ignored. An error IS NOT
// returned.
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
		// Attempt to roll back the transaction
		if err2 := tx.Rollback(); err2 != nil {
			// We're in trouble!
			e := fmt.Sprintf("del: %v, unable to rollback: %v", err, err2)
			panic(e)
		}
		return err
	}

	// Commit transaction
	err = tx.Commit()
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

// Get returns the blob for the provided key.
//
// An ErrNotFound error is returned if the key does not correspond to an entry.
//
// This function satisfies the store BlobKV interface.
func (s *mysql) Get(key string) ([]byte, error) {
	log.Tracef("Get: %v", key)

	if s.isShutdown() {
		return nil, store.ErrShutdown
	}

	blobs, err := s.getBatch([]string{key}, s.db)
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
// for all provided keys.
//
// This function satisfies the store BlobKV interface.
func (s *mysql) GetBatch(keys []string) (map[string][]byte, error) {
	log.Tracef("GetBatch: %v", keys)

	if s.isShutdown() {
		return nil, store.ErrShutdown
	}

	return s.getBatch(keys, s.db)
}

// Tx returns a new database transaction as well as the cancel function that
// releases all resources associated with it.
//
// This function satisfies the store BlobKV interface.
func (s *mysql) Tx() (store.Tx, func(), error) {
	return newSqlTx(s)
}

// Close closes the db connection.
func (s *mysql) Close() {
	log.Tracef("Close")

	// Mark the database as shutdown
	atomic.AddUint64(&s.shutdown, 1)

	// Zero out the encryption key
	util.Zero(s.key[:])

	// Close the mysql connection
	s.db.Close()
}

// insert inserts a new entry into the key-value store for each of the provided
// key-value pairs using the provided transaction.
//
// An ErrDuplicateKey is returned if a provided key already exists in the
// key-value store.
func (s *mysql) insert(blobs map[string][]byte, encrypt bool, tx *sql.Tx) error {
	// Setup context
	ctx, cancel := ctxForOp()
	defer cancel()

	// Encrypt blobs
	var err error
	if encrypt {
		blobs, err = s.encryptBlobs(blobs, tx, ctx)
		if err != nil {
			return err
		}
	}

	// Save blobs
	for k, v := range blobs {
		_, err := tx.ExecContext(ctx,
			"INSERT INTO kv (k, v) VALUES (?, ?);", k, v)
		if err != nil {
			var sqlErr *driver.MySQLError
			if errors.As(err, &sqlErr) && sqlErr.Number == 1062 {
				// This key already exists
				err = fmt.Errorf("%w: %v", store.ErrDuplicateKey, k)
			}
			return errors.WithStack(err)
		}
	}

	log.Debugf("Inserted blobs (%v) into kv store", len(blobs))

	return nil
}

// update updates the provided key-value pairs in the store using the provided
// transaction.
//
// An ErrNotFound is returned if the caller attempts to update an entry that
// does not exist.
func (s *mysql) update(blobs map[string][]byte, encrypt bool, tx *sql.Tx) error {
	// Setup context
	ctx, cancel := ctxForOp()
	defer cancel()

	// Encrypt blobs
	var err error
	if encrypt {
		blobs, err = s.encryptBlobs(blobs, tx, ctx)
		if err != nil {
			return err
		}
	}

	// Save blobs
	for k, v := range blobs {
		r, err := tx.ExecContext(ctx,
			"UPDATE kv SET v = ? where k = ?;", v, k)
		if err != nil {
			return errors.WithStack(err)
		}
		count, err := r.RowsAffected()
		if err != nil {
			return errors.WithStack(err)
		}
		if count == 0 {
			// Nothing was updated
			e := fmt.Errorf("%w: %v", store.ErrNotFound, k)
			return errors.WithStack(e)
		}
	}

	log.Debugf("Updated blobs (%v) in kv store", len(blobs))

	return nil
}

// Del deletes the entries in the store for the provided keys using the
// provided transaction.
//
// Keys that do not correspond to blob entries are ignored. An error IS NOT
// returned.
func (s *mysql) del(keys []string, tx *sql.Tx) error {
	// Converted the key strings to interface{} types.
	// The ExecContext method only accepts interfaces.
	args := make([]interface{}, len(keys))
	for i, v := range keys {
		args[i] = v
	}

	// Setup context
	ctx, cancel := ctxForOp()
	defer cancel()

	// Setup delete query
	q := fmt.Sprintf("DELETE FROM kv WHERE k IN %v;",
		buildPlaceholders(len(args)))

	// Run delete query
	r, err := tx.ExecContext(ctx, q, args...)
	if err != nil {
		return err
	}
	rows, err := r.RowsAffected()
	if err != nil {
		// Getting the number of rows is just for logging. An
		// error here doesn't impact business logic so don't
		// return it.
		log.Errorf("MySQL rows effected from delete error: %v", err)
	}

	log.Debugf("Deleted blobs (%v/%v) from kv store",
		rows, len(keys))

	return nil
}

// querier describes the query method that is present on both the sql DB
// context and on the sql Tx context. This interface allows us to use the same
// code for executing individual queries and transaction queries.
type querier interface {
	QueryContext(context.Context, string, ...interface{}) (*sql.Rows, error)
}

// getBatch returns the blobs from the store for the provided keys.
//
// An entry will not exist in the returned map if for any blobs that are not
// found. It is the responsibility of the caller to ensure a blob was returned
// for all provided keys.
func (s *mysql) getBatch(keys []string, q querier) (map[string][]byte, error) {
	// Converted the key strings to interface{} types.
	// The QueryContext method only accepts interfaces.
	args := make([]interface{}, len(keys))
	for i, v := range keys {
		args[i] = v
	}

	// Setup context
	ctx, cancel := ctxForOp()
	defer cancel()

	// Setup select query
	sq := fmt.Sprintf("SELECT k, v FROM kv WHERE k IN %v;",
		buildPlaceholders(len(args)))

	// Get blobs
	rows, err := q.QueryContext(ctx, sq, args...)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer rows.Close()

	// Unpack reply
	reply := make(map[string][]byte, len(keys))
	for rows.Next() {
		var k string
		var v []byte
		err = rows.Scan(&k, &v)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		reply[k] = v
	}
	err = rows.Err()
	if err != nil {
		return nil, errors.WithStack(err)
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
			return nil, err
		}
		reply[k] = b
	}

	return reply, nil
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
		return nil, nil, errors.WithStack(err)
	}

	return tx, cancel, nil
}

// encryptBlobs encrypts and returns a set of blobs.
func (s *mysql) encryptBlobs(blobs map[string][]byte, tx *sql.Tx, ctx context.Context) (map[string][]byte, error) {
	encrypted := make(map[string][]byte, len(blobs))
	for k, v := range blobs {
		e, err := s.encrypt(ctx, tx, v)
		if err != nil {
			return nil, err
		}
		encrypted[k] = e
	}

	// Sanity check
	if len(encrypted) != len(blobs) {
		return nil, errors.Errorf("unexpected number of encrypted blobs")
	}

	return encrypted, nil
}

// ctxForOp returns a context and cancel function for a single database
// operation.
func ctxForOp() (context.Context, func()) {
	return context.WithTimeout(context.Background(), timeoutOp)
}

// ctxForTx returns a context and a cancel function for a database transaction.
func ctxForTx() (context.Context, func()) {
	return context.WithTimeout(context.Background(), timeoutTx)
}

// buildPlaceholders builds and returns a parameter placeholder string with the
// specified number of placeholders.
//
// Input: 1  Output: "(?)"
// Input: 3  Output: "(?,?,?)"
func buildPlaceholders(placeholders int) string {
	var b strings.Builder

	b.WriteString("(")
	for i := 0; i < placeholders; i++ {
		b.WriteString("?")
		// Don't add a comma on the last one
		if i < placeholders-1 {
			b.WriteString(",")
		}
	}
	b.WriteString(")")

	return b.String()
}
