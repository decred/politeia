// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mysql

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/decred/politeia/politeiawww/user"
	"github.com/decred/politeia/util"
	"github.com/google/uuid"
	"github.com/marcopeereboom/sbox"

	// MySQL driver.
	_ "github.com/go-sql-driver/mysql"
)

const (
	// Database options
	connTimeout     = 1 * time.Minute
	connMaxLifetime = 1 * time.Minute
	maxOpenConns    = 0 // 0 is unlimited
	maxIdleConns    = 100

	// Database user (read/write access)
	userPoliteiawww = "politeiawww"

	databaseID = "users"

	// Database table names.
	tableNameKeyValue       = "key_value"
	tableNameUsers          = "users"
	tableNameIdentities     = "identities"
	tableNameSessions       = "sessions"
	tableNameEmailHistories = "email_histories"

	// Key-value store keys.
	keyVersion             = "version"
	keyPaywallAddressIndex = "paywalladdressindex"
)

// tableKeyValue defines the key_value table.
const tableKeyValue = `
  k VARCHAR(255) NOT NULL PRIMARY KEY,
  v LONGBLOB NOT NULL
`

// tableUsers defines the users table.
const tableUsers = `
  id VARCHAR(36) NOT NULL PRIMARY KEY,
  username VARCHAR(64) NOT NULL,
  u_blob BLOB NOT NULL,
  created_at INT(11) NOT NULL,
  updated_at INT(11),
  UNIQUE (username)
`

// tableIdentities defines the identities table.
const tableIdentities = `
  public_key CHAR(64) NOT NULL PRIMARY KEY,
  user_id    VARCHAR(36) NOT NULL,
  activated INT(11) NOT NULL,
  deactivated INT(11) NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
`

// tableSessions defines the sessions table.
const tableSessions = `
  k CHAR(64) NOT NULL PRIMARY KEY,
  user_id VARCHAR(36) NOT NULL,
  created_at INT(11) NOT NULL,
  s_blob BLOB NOT NULL
`

// tableEmailHistories defines the email_histories table.
const tableEmailHistories = `
  user_id VARCHAR(36) NOT NULL PRIMARY KEY,
  h_blob BLOB NOT NULL
`

var (
	_ user.Database = (*mysql)(nil)
	_ user.MailerDB = (*mysql)(nil)
)

// mysql implements the user.Database interface.
type mysql struct {
	sync.RWMutex

	shutdown       bool                            // Backend is shutdown
	userDB         *sql.DB                         // Database context
	encryptionKey  *[32]byte                       // Data at rest encryption key
	pluginSettings map[string][]user.PluginSetting // [pluginID][]PluginSettings
}

type mysqlIdentity struct {
	publicKey   string
	userID      string
	activated   int64
	deactivated int64
}

func ctxWithTimeout() (context.Context, func()) {
	return context.WithTimeout(context.Background(), connTimeout)
}

func (m *mysql) isShutdown() bool {
	m.RLock()
	defer m.RUnlock()

	return m.shutdown
}

// encrypt encrypts the provided data with the mysql encryption key. The
// encrypted blob is prefixed with an sbox header which encodes the provided
// version. The read lock is taken despite the encryption key being a static
// value because the encryption key is zeroed out on shutdown, which causes
// race conditions to be reported when the golang race detector is used.
//
// This function must be called without the lock held.
func (m *mysql) encrypt(version uint32, b []byte) ([]byte, error) {
	m.RLock()
	defer m.RUnlock()

	return sbox.Encrypt(version, m.encryptionKey, b)
}

// decrypt decrypts the provided packed blob using the mysql encryption
// key. The read lock is taken despite the encryption key being a static value
// because the encryption key is zeroed out on shutdown, which causes race
// conditions to be reported when the golang race detector is used.
//
// This function must be called without the lock held.
func (m *mysql) decrypt(b []byte) ([]byte, uint32, error) {
	m.RLock()
	defer m.RUnlock()

	return sbox.Decrypt(m.encryptionKey, b)
}

// setPaywallAddressIndex updates the paywall address index record in the
// key-value store.
//
// This function must be called using a transaction.
func setPaywallAddressIndex(ctx context.Context, tx *sql.Tx, index uint64) error {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, index)
	_, err := tx.ExecContext(ctx,
		`INSERT INTO key_value (k,v)
    VALUES (?, ?)
    ON DUPLICATE KEY UPDATE
    v = ?`,
		keyPaywallAddressIndex, b, b)
	if err != nil {
		return fmt.Errorf("update paywallet index error: %v", err)
	}
	return nil
}

// userNew creates a new user the database.  The userID and paywall address
// index are set before the user record is inserted into the database.
//
// This function must be called using a transaction.
func (m *mysql) userNew(ctx context.Context, tx *sql.Tx, u user.User) (*uuid.UUID, error) {
	// Set user paywall address index.
	var index uint64
	var dbIndex []byte
	err := tx.QueryRowContext(ctx, "SELECT v FROM key_value WHERE k = ?",
		keyPaywallAddressIndex).Scan(&dbIndex)
	switch err {
	// No errors, use database index.
	case nil:
		index = binary.LittleEndian.Uint64(dbIndex) + 1
	// No rows found error; Index wasn't initiated in table yet, default to zero.
	case sql.ErrNoRows:
		index = 0
	// All other errors.
	default:
		return nil, fmt.Errorf("find paywall index: %v", err)
	}

	log.Debugf("userNew paywall index: %v", index)
	u.PaywallAddressIndex = index

	// Set user ID.
	u.ID = uuid.New()

	// Create user record.
	ub, err := user.EncodeUser(u)
	if err != nil {
		return nil, err
	}

	eb, err := m.encrypt(user.VersionUser, ub)
	if err != nil {
		return nil, err
	}

	// Insert new user into database.
	ur := struct {
		ID        string
		Username  string
		Blob      []byte
		CreatedAt int64
	}{
		ID:        u.ID.String(),
		Username:  u.Username,
		Blob:      eb,
		CreatedAt: time.Now().Unix(),
	}
	_, err = tx.ExecContext(ctx,
		"INSERT INTO users (id, username, u_blob, created_at) VALUES (?, ?, ?, ?)",
		ur.ID, ur.Username, ur.Blob, ur.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("create user: %v", err)
	}

	// Update paywall address index.
	err = setPaywallAddressIndex(ctx, tx, index)
	if err != nil {
		return nil, fmt.Errorf("set paywall index: %v", err)
	}

	return &u.ID, nil
}

// rotateKeys rotates the existing database encryption key with the given new
// key.
//
// This function must be called using a transaction.
func rotateKeys(ctx context.Context, tx *sql.Tx, oldKey *[32]byte, newKey *[32]byte) error {
	// Rotate keys for users table.
	type User struct {
		ID   string // UUID
		Blob []byte // Encrypted blob of user data.
	}
	var users []User

	rows, err := tx.QueryContext(ctx, "SELECT id, u_blob FROM users")
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Blob); err != nil {
			return err
		}
		users = append(users, u)
	}
	// Rows.Err will report the last error encountered by Rows.Scan.
	if err = rows.Err(); err != nil {
		return err
	}

	for _, v := range users {
		b, _, err := sbox.Decrypt(oldKey, v.Blob)
		if err != nil {
			return fmt.Errorf("decrypt user '%v': %v",
				v.ID, err)
		}

		eb, err := sbox.Encrypt(user.VersionUser, newKey, b)
		if err != nil {
			return fmt.Errorf("encrypt user '%v': %v",
				v.ID, err)
		}

		v.Blob = eb
		// Store new user blob.
		_, err = tx.ExecContext(ctx,
			"UPDATE users SET u_blob = ? WHERE id = ?", v.Blob, v.ID)
		if err != nil {
			return fmt.Errorf("save user '%v': %v", v.ID, err)
		}
	}

	// Rotate keys for sessions table.
	type Session struct {
		Key  string
		Blob []byte // Encrypted blob of session data.
	}
	var sessions []Session
	rows, err = tx.QueryContext(ctx, "SELECT k, s_blob FROM sessions")
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var s Session
		if err := rows.Scan(&s.Key, &s.Blob); err != nil {
			return err
		}
		sessions = append(sessions, s)
	}
	// Rows.Err will report the last error encountered by Rows.Scan.
	if err = rows.Err(); err != nil {
		return err
	}

	for _, v := range sessions {
		b, _, err := sbox.Decrypt(oldKey, v.Blob)
		if err != nil {
			return fmt.Errorf("decrypt session '%v': %v",
				v.Key, err)
		}

		eb, err := sbox.Encrypt(user.VersionSession, newKey, b)
		if err != nil {
			return fmt.Errorf("encrypt session '%v': %v",
				v.Key, err)
		}

		v.Blob = eb
		// Store new user blob.
		_, err = tx.ExecContext(ctx,
			"UPDATE sessions SET s_blob = ? WHERE k = ?", v.Blob, v.Key)
		if err != nil {
			return fmt.Errorf("save session '%v': %v", v.Key, err)
		}
	}

	return nil
}

// UserNew creates a new user record in the database.
//
// UserNew satisfies the Database interface.
func (m *mysql) UserNew(u user.User) error {
	log.Tracef("UserNew: %v", u.Username)

	if m.isShutdown() {
		return user.ErrShutdown
	}

	ctx, cancel := ctxWithTimeout()
	defer cancel()

	// Start transaction.
	opts := &sql.TxOptions{
		Isolation: sql.LevelDefault,
	}
	tx, err := m.userDB.BeginTx(ctx, opts)
	if err != nil {
		return fmt.Errorf("begin tx: %v", err)
	}
	defer tx.Rollback()

	_, err = m.userNew(ctx, tx, u)
	if err != nil {
		return err
	}

	// Commit transaction.
	if err := tx.Commit(); err != nil {
		if err2 := tx.Rollback(); err2 != nil {
			// We're in trouble!
			panic(fmt.Errorf("rollback tx failed: commit:'%v' rollback:'%v'",
				err, err2))
		}
		return fmt.Errorf("commit tx: %v", err)
	}

	return nil
}

// UserUpdate updates an existing user.
//
// UserUpdate satisfies the Database interface.
func (m *mysql) UserUpdate(u user.User) error {
	log.Tracef("UserUpdate: %v", u.Username)

	if m.isShutdown() {
		return user.ErrShutdown
	}

	b, err := user.EncodeUser(u)
	if err != nil {
		return err
	}

	eb, err := m.encrypt(user.VersionUser, b)
	if err != nil {
		return err
	}

	ctx, cancel := ctxWithTimeout()
	defer cancel()

	// Init a sql transaction.
	opts := &sql.TxOptions{
		Isolation: sql.LevelDefault,
	}
	tx, err := m.userDB.BeginTx(ctx, opts)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	ur := struct {
		ID        string
		Username  string
		Blob      []byte
		UpdatedAt int64
	}{
		ID:        u.ID.String(),
		Username:  u.Username,
		Blob:      eb,
		UpdatedAt: time.Now().Unix(),
	}
	_, err = tx.ExecContext(ctx,
		"UPDATE users SET username = ?, u_blob = ?, updated_at = ? WHERE id = ? ",
		ur.Username, ur.Blob, ur.UpdatedAt, ur.ID)
	if err != nil {
		return fmt.Errorf("create user: %v", err)
	}

	// Upsert user identities
	var ids []mysqlIdentity
	for _, uIdentity := range u.Identities {
		ids = append(ids, mysqlIdentity{
			publicKey:   uIdentity.String(),
			activated:   uIdentity.Activated,
			deactivated: uIdentity.Deactivated,
			userID:      ur.ID,
		})
	}
	err = upsertIdentities(ctx, tx, ids)
	if err != nil {
		return fmt.Errorf("insert new identities: %v", err)
	}

	// Commit transaction.
	if err := tx.Commit(); err != nil {
		if err2 := tx.Rollback(); err2 != nil {
			// We're in trouble!
			panic(fmt.Errorf("rollback tx failed: commit:'%v' rollback:'%v'",
				err, err2))
		}
		return fmt.Errorf("commit tx: %v", err)
	}

	return nil
}

// upsertIdentities upserts list of given user identities to db.
// It inserts new identities and updates identities if they exist on db.
//
// This func should be called with a sql transaction.
func upsertIdentities(ctx context.Context, tx *sql.Tx, ids []mysqlIdentity) error {
	var sb strings.Builder
	sb.WriteString("INSERT INTO " +
		"identities(public_key, user_id, activated, deactivated) VALUES ")

	vals := make([]interface{}, 0, len(ids))
	for i, id := range ids {
		// Trim , for last item
		switch i {
		case len(ids) - 1:
			sb.WriteString("(?, ?, ?, ?)")
		default:
			sb.WriteString("(?, ?, ?, ?),")
		}
		vals = append(vals, id.publicKey, id.userID, id.activated, id.deactivated)
	}

	// Update activated & deactivated columns when key already exists.
	sb.WriteString("ON DUPLICATE KEY UPDATE activated=VALUES(activated), " +
		"deactivated=VALUES(deactivated)")

	_, err := tx.ExecContext(ctx, sb.String(), vals...)
	if err != nil {
		return err
	}

	return nil
}

// UserGetByUsername returns a user record given its username, if found in the
// database. returns user.ErrUserNotFound user not found.
//
// UserGetByUsername satisfies the Database interface.
func (m *mysql) UserGetByUsername(username string) (*user.User, error) {
	log.Tracef("UserGetByUsername: %v", username)

	if m.isShutdown() {
		return nil, user.ErrShutdown
	}

	ctx, cancel := ctxWithTimeout()
	defer cancel()

	var uBlob []byte
	err := m.userDB.QueryRowContext(ctx,
		"SELECT u_blob FROM users WHERE username = ?", username).Scan(&uBlob)
	switch {
	case err == sql.ErrNoRows:
		return nil, user.ErrUserNotFound
	case err != nil:
		return nil, err
	}

	b, _, err := m.decrypt(uBlob)
	if err != nil {
		return nil, err
	}

	usr, err := user.DecodeUser(b)
	if err != nil {
		return nil, err
	}

	return usr, nil
}

// UserGetById returns a user record given its UUID, if found in the
// database.
//
// UserGetById satisfies the Database interface.
func (m *mysql) UserGetById(id uuid.UUID) (*user.User, error) {
	log.Tracef("UserGetById: %v", id)

	if m.isShutdown() {
		return nil, user.ErrShutdown
	}

	ctx, cancel := ctxWithTimeout()
	defer cancel()

	var uBlob []byte
	err := m.userDB.QueryRowContext(ctx,
		"SELECT u_blob FROM users WHERE id = ?", id).Scan(&uBlob)
	switch {
	case err == sql.ErrNoRows:
		return nil, user.ErrUserNotFound
	case err != nil:
		return nil, err
	}

	b, _, err := m.decrypt(uBlob)
	if err != nil {
		return nil, err
	}

	usr, err := user.DecodeUser(b)
	if err != nil {
		return nil, err
	}

	return usr, nil
}

// UserGetByPubKey returns a user record given its public key. The public key
// can be any of the public keys in the user's identity history.
//
// UserGetByPubKey satisfies the Database interface.
func (m *mysql) UserGetByPubKey(pubKey string) (*user.User, error) {
	log.Tracef("UserGetByPubKey: %v", pubKey)

	if m.isShutdown() {
		return nil, user.ErrShutdown
	}

	ctx, cancel := ctxWithTimeout()
	defer cancel()

	var uBlob []byte
	q := `SELECT u_blob
        FROM users
        INNER JOIN identities
          ON users.id = identities.user_id
          WHERE identities.public_key = ?`
	err := m.userDB.QueryRowContext(ctx, q, pubKey).Scan(&uBlob)
	switch {
	case err == sql.ErrNoRows:
		return nil, user.ErrUserNotFound
	case err != nil:
		return nil, err
	}

	b, _, err := m.decrypt(uBlob)
	if err != nil {
		return nil, err
	}
	usr, err := user.DecodeUser(b)
	if err != nil {
		return nil, err
	}

	return usr, nil
}

// UsersGetByPubKey returns a [pubkey]user.User map for the provided public
// keys. Public keys can be any of the public keys in the user's identity
// history. If a user is not found, the map will not include an entry for the
// corresponding public key. It is responsibility of the caller to ensure
// results are returned for all of the provided public keys.
//
// UsersGetByPubKey satisfies the Database interface.
func (m *mysql) UsersGetByPubKey(pubKeys []string) (map[string]user.User, error) {
	log.Tracef("UserGetByPubKey: %v", pubKeys)

	if m.isShutdown() {
		return nil, user.ErrShutdown
	}

	ctx, cancel := ctxWithTimeout()
	defer cancel()

	// Lookup users by pubkey.
	q := `SELECT u_blob
          FROM users
            INNER JOIN identities
            ON users.id = identities.user_id
            WHERE identities.public_key IN (?` +
		strings.Repeat(",?", len(pubKeys)-1) + `)`

	args := make([]interface{}, len(pubKeys))
	for i, id := range pubKeys {
		args[i] = id
	}
	rows, err := m.userDB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Put provided pubkeys into a map
	pk := make(map[string]struct{}, len(pubKeys))
	for _, v := range pubKeys {
		pk[v] = struct{}{}
	}

	// Decrypt user data blobs and compile a users map for
	// the provided pubkeys.
	users := make(map[string]user.User, len(pubKeys)) // [pubkey]User
	for rows.Next() {
		var uBlob []byte
		err := rows.Scan(&uBlob)
		if err != nil {
			return nil, err
		}

		b, _, err := m.decrypt(uBlob)
		if err != nil {
			return nil, err
		}

		usr, err := user.DecodeUser(b)
		if err != nil {
			return nil, err
		}

		for _, id := range usr.Identities {
			_, ok := pk[id.String()]
			if ok {
				users[id.String()] = *usr
			}
		}
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}

	return users, nil
}

// InsertUser inserts a user record into the database. The record must be a
// complete user record and the user must not already exist. This function is
// intended to be used for migrations between databases.
//
// InsertUser satisfies the Database interface.
func (m *mysql) InsertUser(u user.User) error {
	log.Tracef("UserInsert: %v", u.Username)

	if m.isShutdown() {
		return user.ErrShutdown
	}

	ctx, cancel := ctxWithTimeout()
	defer cancel()

	ub, err := user.EncodeUser(u)
	if err != nil {
		return err
	}

	eb, err := m.encrypt(user.VersionUser, ub)
	if err != nil {
		return err
	}

	// Insert new user into database.
	ur := struct {
		ID        string
		Username  string
		Blob      []byte
		CreatedAt int64
	}{
		ID:        u.ID.String(),
		Username:  u.Username,
		Blob:      eb,
		CreatedAt: time.Now().Unix(),
	}
	_, err = m.userDB.ExecContext(ctx,
		"INSERT INTO users (ID, username, uBlob, createdAt) VALUES (?, ?, ?, ?)",
		ur.ID, ur.Username, ur.Blob, ur.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert user: %v", err)
	}

	return nil
}

// AllUsers iterate over all users and executes given callback.
//
// AllUsers satisfies the Database interface.
func (m *mysql) AllUsers(callback func(u *user.User)) error {
	log.Tracef("AllUsers")

	if m.isShutdown() {
		return user.ErrShutdown
	}

	ctx, cancel := ctxWithTimeout()
	defer cancel()

	// Lookup all users.
	type User struct {
		Blob []byte
	}
	var users []User
	rows, err := m.userDB.QueryContext(ctx, "SELECT u_blob FROM users")
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var u User
		err := rows.Scan(&u.Blob)
		if err != nil {
			return err
		}
		users = append(users, u)
	}
	if err = rows.Err(); err != nil {
		return err
	}

	// Invoke callback on each user.
	for _, v := range users {
		b, _, err := m.decrypt(v.Blob)
		if err != nil {
			return err
		}

		u, err := user.DecodeUser(b)
		if err != nil {
			return err
		}

		callback(u)
	}

	return nil
}

// SessionSave saves the given session to the database. New sessions are
// inserted into the database. Existing sessions are updated in the database.
//
// SessionSave satisfies the user Database interface.
func (m *mysql) SessionSave(us user.Session) error {
	log.Tracef("SessionSave: %v", us.ID)

	if m.isShutdown() {
		return user.ErrShutdown
	}

	ctx, cancel := ctxWithTimeout()
	defer cancel()

	type Session struct {
		Key       string // SHA256 hash of the session ID
		UserID    string // User UUID
		CreatedAt int64  // Created at UNIX timestamp
		Blob      []byte // Encrypted user session
	}
	sb, err := user.EncodeSession(us)
	if err != nil {
		return nil
	}
	eb, err := m.encrypt(user.VersionSession, sb)
	if err != nil {
		return err
	}
	session := Session{
		Key:       hex.EncodeToString(util.Digest([]byte(us.ID))),
		UserID:    us.UserID.String(),
		CreatedAt: us.CreatedAt,
		Blob:      eb,
	}

	// Check if session already exists.
	var (
		update bool
		k      string
	)
	err = m.userDB.
		QueryRowContext(ctx, "SELECT k FROM sessions WHERE k = ?", session.Key).
		Scan(&k)
	switch err {
	case nil:
		// Session already exists; update existing session.
		update = true
	case sql.ErrNoRows:
		// Session doesn't exist; continue.
	default:
		// All other errors.
		return fmt.Errorf("lookup: %v", err)
	}

	// Save session record
	if update {
		_, err := m.userDB.ExecContext(ctx,
			`UPDATE sessions
		  SET user_id = ?, created_at = ?, s_blob = ?
			WHERE k = ?`,
			session.UserID, session.CreatedAt, session.Blob, session.Key)
		if err != nil {
			return fmt.Errorf("update: %v", err)
		}
	} else {
		_, err := m.userDB.ExecContext(ctx,
			`INSERT INTO sessions
		(k, user_id, created_at, s_blob)
		VALUES (?, ?, ?, ?)`,
			session.Key, session.UserID, session.CreatedAt, session.Blob)
		if err != nil {
			return fmt.Errorf("create: %v", err)
		}
	}

	return nil
}

// SessionGetByID gets a session by its ID. Returns a user.ErrorSessionNotFound
// if the given session ID does not exist.
//
// SessionGetByID satisfies the Database interface.
func (m *mysql) SessionGetByID(sid string) (*user.Session, error) {
	log.Tracef("SessionGetByID: %v", sid)

	if m.isShutdown() {
		return nil, user.ErrShutdown
	}

	ctx, cancel := ctxWithTimeout()
	defer cancel()

	var blob []byte
	err := m.userDB.QueryRowContext(ctx, "SELECT s_blob FROM sessions WHERE k = ?",
		hex.EncodeToString(util.Digest([]byte(sid)))).
		Scan(&blob)
	switch {
	case err == sql.ErrNoRows:
		return nil, user.ErrSessionNotFound
	case err != nil:
		return nil, err
	}

	b, _, err := m.decrypt(blob)
	if err != nil {
		return nil, err
	}
	return user.DecodeSession(b)
}

// SessionDeleteByID deletes the session with the given id.
//
// SessionDeleteByID satisfies the Database interface.
func (m *mysql) SessionDeleteByID(sid string) error {
	log.Tracef("SessionDeleteByID: %v", sid)

	if m.isShutdown() {
		return user.ErrShutdown
	}

	ctx, cancel := ctxWithTimeout()
	defer cancel()

	_, err := m.userDB.ExecContext(ctx, "DELETE FROM sessions WHERE k = ?",
		hex.EncodeToString(util.Digest([]byte(sid))))
	if err != nil {
		return err
	}

	return nil
}

// SessionsDeleteByUserID deletes all sessions for the given user ID, except
// the session IDs in exemptSessionIDs.
//
// SessionsDeleteByUserID satisfies the Database interface.
func (m *mysql) SessionsDeleteByUserID(uid uuid.UUID, exemptSessionIDs []string) error {
	log.Tracef("SessionsDeleteByUserID: %v %v", uid.String(), exemptSessionIDs)

	ctx, cancel := ctxWithTimeout()
	defer cancel()

	// Session primary key is a SHA256 hash of the session ID.
	exempt := make([]string, 0, len(exemptSessionIDs))
	for _, v := range exemptSessionIDs {
		exempt = append(exempt, hex.EncodeToString(util.Digest([]byte(v))))
	}

	// Using an empty NOT IN() set will result in no records being
	// deleted.
	if len(exempt) == 0 {
		_, err := m.userDB.
			ExecContext(ctx, "DELETE FROM sessions WHERE user_id = ?", uid.String())
		return err
	}

	_, err := m.userDB.
		ExecContext(ctx, "DELETE FROM sessions WHERE user_id = ? AND k NOT IN (?)",
			uid.String(), exempt)
	return err
}

// SetPaywallAddressIndex updates the paywall address index.
//
// SetPaywallAddressIndex satisfies the Database interface.
func (m *mysql) SetPaywallAddressIndex(index uint64) error {
	log.Tracef("SetPaywallAddressIndex: %v", index)

	if m.isShutdown() {
		return user.ErrShutdown
	}

	ctx, cancel := ctxWithTimeout()
	defer cancel()

	// Start transaction.
	opts := &sql.TxOptions{
		Isolation: sql.LevelDefault,
	}
	tx, err := m.userDB.BeginTx(ctx, opts)
	if err != nil {
		return fmt.Errorf("begin tx: %v", err)
	}
	defer tx.Rollback()

	err = setPaywallAddressIndex(ctx, tx, index)
	if err != nil {
		return err
	}

	// Commit transaction.
	if err := tx.Commit(); err != nil {
		if err2 := tx.Rollback(); err2 != nil {
			// We're in trouble!
			panic(fmt.Errorf("rollback tx failed: commit:'%v' rollback:'%v'",
				err, err2))
		}
		return fmt.Errorf("commit tx: %v", err)
	}

	return nil
}

// RotateKeys rotates the existing database encryption key with the given new
// key.
//
// RotateKeys satisfies the Database interface.
func (m *mysql) RotateKeys(newKeyPath string) error {
	log.Tracef("RotateKeys: %v", newKeyPath)

	if m.isShutdown() {
		return user.ErrShutdown
	}

	// Load and validate new encryption key.
	newKey, err := util.LoadEncryptionKey(log, newKeyPath)
	if err != nil {
		return fmt.Errorf("load encryption key '%v': %v",
			newKeyPath, err)
	}

	if bytes.Equal(newKey[:], m.encryptionKey[:]) {
		return fmt.Errorf("keys are the same")
	}

	log.Infof("Rotating encryption keys")

	ctx, cancel := ctxWithTimeout()
	defer cancel()

	m.Lock()
	defer m.Unlock()

	// Rotate keys using a transaction.
	opts := &sql.TxOptions{
		Isolation: sql.LevelDefault,
	}
	tx, err := m.userDB.BeginTx(ctx, opts)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	err = rotateKeys(ctx, tx, m.encryptionKey, newKey)
	if err != nil {
		return err
	}

	// Commit transaction.
	if err := tx.Commit(); err != nil {
		if err2 := tx.Rollback(); err2 != nil {
			// We're in trouble!
			panic(fmt.Errorf("rollback tx failed: commit:'%v' rollback:'%v'",
				err, err2))
		}
		return fmt.Errorf("commit tx: %v", err)
	}

	// Update context.
	m.encryptionKey = newKey

	return nil
}

// RegisterPlugin registers a plugin.
//
// RegisterPlugin satisfies the Database interface.
func (m *mysql) RegisterPlugin(p user.Plugin) error {
	log.Tracef("RegisterPlugin: %v %v", p.ID, p.Version)

	if m.isShutdown() {
		return user.ErrShutdown
	}

	// Setup plugin tables
	var err error
	switch p.ID {
	case user.CMSPluginID:
	default:
		return user.ErrInvalidPlugin
	}
	if err != nil {
		return err
	}

	// Save plugin settings.
	m.Lock()
	defer m.Unlock()

	m.pluginSettings[p.ID] = p.Settings

	return nil
}

// PluginExec executes a plugin command.
//
// PluginExec satisfies the Database interface.
func (m *mysql) PluginExec(pc user.PluginCommand) (*user.PluginCommandReply, error) {
	log.Tracef("PluginExec: %v %v", pc.ID, pc.Command)

	if m.isShutdown() {
		return nil, user.ErrShutdown
	}

	var payload string
	var err error
	switch pc.ID {
	case user.CMSPluginID:
	default:
		return nil, user.ErrInvalidPlugin
	}
	if err != nil {
		return nil, err
	}

	return &user.PluginCommandReply{
		ID:      pc.ID,
		Command: pc.Command,
		Payload: payload,
	}, nil
}

// EmailHistoriesSave creates or updates the email histories to the database.
// The histories map contains map[userid]EmailHistory.
//
// EmailHistoriesSave satisfies the user MailerDB interface.
func (m *mysql) EmailHistoriesSave(histories map[uuid.UUID]user.EmailHistory) error {
	log.Tracef("EmailHistoriesSave: %v", histories)

	if len(histories) == 0 {
		return nil
	}

	if m.isShutdown() {
		return user.ErrShutdown
	}

	ctx, cancel := ctxWithTimeout()
	defer cancel()

	// Start transaction.
	opts := &sql.TxOptions{
		Isolation: sql.LevelDefault,
	}
	tx, err := m.userDB.BeginTx(ctx, opts)
	if err != nil {
		return fmt.Errorf("begin tx: %v", err)
	}
	defer tx.Rollback()

	// Execute statements
	err = m.emailHistoriesSave(ctx, tx, histories)
	if err != nil {
		return err
	}

	// Commit transaction.
	if err := tx.Commit(); err != nil {
		if err2 := tx.Rollback(); err2 != nil {
			// We're in trouble!
			panic(fmt.Errorf("rollback tx failed: commit:'%v' rollback:'%v'",
				err, err2))
		}
		return fmt.Errorf("commit tx: %v", err)
	}

	return nil
}

// emailHistoriesSave creates or updates the email histories for the given
// users in the histories map[userid]EmailHistory.
//
// This function must be called using a sql transaction.
func (m *mysql) emailHistoriesSave(ctx context.Context, tx *sql.Tx, histories map[uuid.UUID]user.EmailHistory) error {
	for userID, history := range histories {
		var (
			update bool
			em     string
		)
		err := tx.QueryRowContext(ctx,
			"SELECT user_id FROM email_histories WHERE user_id = ?", userID).
			Scan(&em)
		switch err {
		case nil:
			// Email history already exists for this user, update it.
			update = true
		case sql.ErrNoRows:
			// Email history doesn't exist for this user, create new one.
		default:
			// All other errors
			return fmt.Errorf("lookup: %v", err)
		}

		// Make email history blob
		ehb, err := json.Marshal(history)
		if err != nil {
			return fmt.Errorf("convert email history to DB: %w", err)
		}
		eb, err := m.encrypt(user.VersionEmailHistory, ehb)
		if err != nil {
			return err
		}

		// Save email history
		if update {
			_, err := tx.ExecContext(ctx,
				`UPDATE email_histories SET h_blob = ? WHERE user_id = ?`,
				eb, userID)
			if err != nil {
				return fmt.Errorf("update: %v", err)
			}
		} else {
			_, err := tx.ExecContext(ctx,
				`INSERT INTO email_histories (user_id, h_blob) VALUES (?, ?)`,
				userID, eb)
			if err != nil {
				return fmt.Errorf("create: %v", err)
			}
		}
	}

	return nil
}

// EmailHistoriesGet retrieves the email histories for the provided user IDs
// The returned map[userid]EmailHistory will contain an entry for each of the
// provided user ID. If a provided user ID does not correspond to a user in the
// database, then the entry will be skipped in the returned map. An error is not
// returned.
//
// EmailHistoriesGet satisfies the user MailerDB interface.
func (m *mysql) EmailHistoriesGet(users []uuid.UUID) (map[uuid.UUID]user.EmailHistory, error) {
	log.Tracef("EmailHistoriesGet: %v", users)

	if m.isShutdown() {
		return nil, user.ErrShutdown
	}

	ctx, cancel := ctxWithTimeout()
	defer cancel()

	// Lookup email histories by user ids.
	q := `SELECT user_id, h_blob FROM email_histories WHERE user_id IN (?` +
		strings.Repeat(",?", len(users)-1) + `)`

	args := make([]interface{}, len(users))
	for i, userID := range users {
		args[i] = userID.String()
	}
	rows, err := m.userDB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Decrypt email history blob and compile the user emails map with their
	// respective email history.
	type emailHistory struct {
		UserID string
		Blob   []byte
	}
	histories := make(map[uuid.UUID]user.EmailHistory, len(users))
	for rows.Next() {
		var hist emailHistory
		if err := rows.Scan(&hist.UserID, &hist.Blob); err != nil {
			return nil, err
		}

		b, _, err := m.decrypt(hist.Blob)
		if err != nil {
			return nil, err
		}

		var h user.EmailHistory
		err = json.Unmarshal(b, &h)
		if err != nil {
			return nil, err
		}

		uuid, err := uuid.Parse(hist.UserID)
		if err != nil {
			return nil, err
		}

		histories[uuid] = h
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}

	return histories, nil
}

// Close shuts down the database.  All interface functions must return with
// errShutdown if the backend is shutting down.
//
// Close satisfies the Database interface.
func (m *mysql) Close() error {
	log.Tracef("Close")

	m.Lock()
	defer m.Unlock()

	// Zero out encryption key.
	util.Zero(m.encryptionKey[:])
	m.encryptionKey = nil

	m.shutdown = true
	return m.userDB.Close()
}

// New connects to a mysql instance using the given connection params,
// and returns pointer to the created mysql struct.
func New(host, password, network, encryptionKey string) (*mysql, error) {
	// Connect to database.
	dbname := databaseID + "_" + network
	log.Infof("MySQL host: %v:[password]@tcp(%v)/%v", userPoliteiawww, host,
		dbname)

	h := fmt.Sprintf("%v:%v@tcp(%v)/%v", userPoliteiawww, password,
		host, dbname)
	db, err := sql.Open("mysql", h)
	if err != nil {
		return nil, err
	}

	// Verify database connection.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err = db.PingContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("db ping: %v", err)
	}

	// Setup database options.
	db.SetConnMaxLifetime(connMaxLifetime)
	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)

	// Setup key_value table.
	q := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %v (%v)`,
		tableNameKeyValue, tableKeyValue)
	_, err = db.Exec(q)
	if err != nil {
		return nil, fmt.Errorf("create %v table: %v", tableNameKeyValue, err)
	}

	// Setup users table.
	q = fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %v (%v)`,
		tableNameUsers, tableUsers)
	_, err = db.Exec(q)
	if err != nil {
		return nil, fmt.Errorf("create %v table: %v", tableNameUsers, err)
	}

	// Setup identities table.
	q = fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %v (%v)`,
		tableNameIdentities, tableIdentities)
	_, err = db.Exec(q)
	if err != nil {
		return nil, fmt.Errorf("create %v table: %v", tableNameIdentities, err)
	}

	// Setup sessions table.
	q = fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %v (%v)`,
		tableNameSessions, tableSessions)
	_, err = db.Exec(q)
	if err != nil {
		return nil, fmt.Errorf("create %v table: %v", tableNameSessions, err)
	}

	// Setup email_histories table.
	q = fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %v (%v)`,
		tableNameEmailHistories, tableEmailHistories)
	_, err = db.Exec(q)
	if err != nil {
		return nil, fmt.Errorf("create %v table: %v",
			tableNameEmailHistories, err)
	}

	// Load encryption key.
	key, err := util.LoadEncryptionKey(log, encryptionKey)
	if err != nil {
		return nil, err
	}

	return &mysql{
		userDB:        db,
		encryptionKey: key,
	}, nil
}
