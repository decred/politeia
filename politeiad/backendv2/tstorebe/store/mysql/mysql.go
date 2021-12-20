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

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
	"github.com/decred/politeia/util"
	"github.com/pkg/errors"

	// MySQL driver.
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

	// maxPlaceholders is the maximum number of placeholders, "(?, ?, ?)", that
	// can be used in a prepared statement. MySQL uses an uint16 for this, so
	// the limit is the the maximum value of an uint16.
	maxPlaceholders = 65535
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

	// The following fields are only used during unit tests.
	testing bool
	mock    sqlmock.Sqlmock
}

func ctxWithTimeout() (context.Context, func()) {
	return context.WithTimeout(context.Background(), connTimeout)
}

func (s *mysql) isShutdown() bool {
	return atomic.LoadUint64(&s.shutdown) != 0
}

// put saves the provided blobs to the kv store using the provided transaction.
func (s *mysql) put(blobs map[string][]byte, encrypt bool, ctx context.Context, tx *sql.Tx) error {
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

	// Build the select statements
	statements := buildSelectStatements(keys, maxPlaceholders)

	log.Debugf("Get %v blobs using %v prepared statements",
		len(keys), len(statements))

	// Execute the statements
	reply := make(map[string][]byte, len(keys))
	for i, e := range statements {
		log.Debugf("Executing select statement %v/%v", i+1, len(statements))

		ctx, cancel := ctxWithTimeout()
		defer cancel()

		rows, err := s.db.QueryContext(ctx, e.Query, e.Args...)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		defer rows.Close()

		// Unpack the reply
		for rows.Next() {
			var k string
			var v []byte
			err = rows.Scan(&k, &v)
			if err != nil {
				return nil, errors.WithStack(err)
			}

			// Decrypt the blob if required
			if isEncrypted(v) {
				log.Tracef("Encrypted blob: %v", k)
				v, _, err = s.decrypt(v)
				if err != nil {
					return nil, err
				}
			}

			// Save the blob
			reply[k] = v
		}
		err = rows.Err()
		if err != nil {
			return nil, errors.WithStack(err)
		}
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

// selectStatement contains the query string and arguments for a SELECT
// statement.
type selectStatement struct {
	Query string
	Args  []interface{}
}

// buildSelectStatements builds the SELECT statements that can be executed
// against the MySQL key-value store. The maximum number of records that will
// be retrieved in any individual SELECT statement is determined by the size
// argument. The keys are split up into multiple statements if they exceed this
// limit.
func buildSelectStatements(keys []string, size int) []selectStatement {
	statements := make([]selectStatement, 0, (len(keys)/size)+1)
	var startIdx int
	for startIdx < len(keys) {
		// Find the end index
		endIdx := startIdx + size
		if endIdx > len(keys) {
			// We've reached the end of the slice
			endIdx = len(keys)
		}

		// startIdx is included. endIdx is excluded.
		statementKeys := keys[startIdx:endIdx]

		// Build the query
		q := buildSelectQuery(len(statementKeys))
		log.Tracef("%v", q)

		// Convert the keys to interfaces. The sql query
		// methods require arguments be interfaces.
		args := make([]interface{}, len(statementKeys))
		for i, v := range statementKeys {
			args[i] = v
		}

		// Save the statement
		statements = append(statements, selectStatement{
			Query: q,
			Args:  args,
		})

		// Update the start index
		startIdx = endIdx
	}

	return statements
}

// buildSelectQuery returns a query string for the MySQL key-value store.
//
// Example: "SELECT k, v FROM kv WHERE k IN (?,?);"
func buildSelectQuery(placeholders int) string {
	return fmt.Sprintf("SELECT k, v FROM kv WHERE k IN %v;",
		buildPlaceholders(placeholders))
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

// New connects to a mysql instance using the given connection params,
// and returns pointer to the created mysql struct.
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

	// Derive encryption key from password. Key is set in argon2idKey
	err = s.deriveEncryptionKey(password)
	if err != nil {
		return nil, fmt.Errorf("deriveEncryptionKey: %v", err)
	}

	return s, nil
}
