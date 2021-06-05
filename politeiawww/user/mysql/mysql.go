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
	tableNameKeyValue   = "key_value"
	tableNameUsers      = "users"
	tableNameIdentities = "identities"
	tableNameSessions   = "sessions"

	// Key-value store keys.
	keyVersion             = "version"
	keyPaywallAddressIndex = "paywalladdressindex"
)

// tableKeyValue defines the key-value table.
const tableKeyValue = `
  k VARCHAR(255) NOT NULL PRIMARY KEY,
  v LONGBLOB NOT NULL
`

// tableUsers defines the users table.
const tableUsers = `
  ID VARCHAR(36) NOT NULL PRIMARY KEY,
  username VARCHAR(64) NOT NULL,
  uBlob BLOB NOT NULL,
  createdAt INT(11) NOT NULL,
  updatedAt INT(11),
  UNIQUE (username)
`

// tableIdentities defines the identities table.
const tableIdentities = `
  publicKey CHAR(64) NOT NULL PRIMARY KEY,
  userID    VARCHAR(36) NOT NULL,
  activated INT(11) NOT NULL,
  deactivated INT(11) NOT NULL,
  FOREIGN KEY (userID) REFERENCES users(ID)
`

// tableSessions defines the sessions table.
const tableSessions = `
  k CHAR(64) NOT NULL PRIMARY KEY,
  userID VARCHAR(36) NOT NULL,
  createdAt INT(11) NOT NULL,
  sBlob BLOB NOT NULL
`

var (
	_ user.Database = (*mysql)(nil)
)

// mysql implements the user.Database interface.
type mysql struct {
	sync.RWMutex

	shutdown       bool                            // Backend is shutdown
	userDB         *sql.DB                         // Database context
	encryptionKey  *[32]byte                       // Data at rest encryption key
	pluginSettings map[string][]user.PluginSetting // [pluginID][]PluginSettings
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
		"INSERT INTO users (ID, username, uBlob, createdAt) VALUES (?, ?, ?, ?)",
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

	rows, err := tx.QueryContext(ctx, "SELECT ID, uBlob FROM users")
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
	if err := rows.Err(); err != nil {
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
			"UPDATE users SET uBlob = ? WHERE ID = ?", v.Blob, v.ID)
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
	rows, err = tx.QueryContext(ctx, "SELECT k, sBlob FROM sessions")
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
	if err := rows.Err(); err != nil {
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
			"UPDATE sessions SET sBlob = ? WHERE k = ?", v.Blob, v.Key)
		if err != nil {
			return fmt.Errorf("save session '%v': %v", v.Key, err)
		}
	}

	return nil
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

// UserNew creates a new user record in the database.
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
	_, err = m.userDB.ExecContext(ctx,
		"UPDATE users SET username = ?, uBlob = ?, updatedAt = ? WHERE ID = ? ",
		ur.Username, ur.Blob, ur.UpdatedAt, ur.ID)
	if err != nil {
		return fmt.Errorf("create user: %v", err)
	}

	return nil
}

// UserGetByUsername returns a user record given its username, if found in the
// database. returns user.ErrUserNotFound user not found.
func (m *mysql) UserGetByUsername(username string) (*user.User, error) {
	log.Tracef("UserGetByUsername: %v", username)

	if m.isShutdown() {
		return nil, user.ErrShutdown
	}

	ctx, cancel := ctxWithTimeout()
	defer cancel()

	var uBlob []byte
	err := m.userDB.QueryRowContext(ctx,
		"SELECT uBlob FROM users WHERE username = ?", username).Scan(&uBlob)
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
func (m *mysql) UserGetById(id uuid.UUID) (*user.User, error) {
	log.Tracef("UserGetById: %v", id)

	if m.isShutdown() {
		return nil, user.ErrShutdown
	}

	ctx, cancel := ctxWithTimeout()
	defer cancel()

	var uBlob []byte
	err := m.userDB.QueryRowContext(ctx,
		"SELECT uBlob FROM users WHERE ID = ?", id).Scan(&uBlob)
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
func (m *mysql) UserGetByPubKey(pubKey string) (*user.User, error) {
	log.Tracef("UserGetByPubKey: %v", pubKey)

	if m.isShutdown() {
		return nil, user.ErrShutdown
	}

	ctx, cancel := ctxWithTimeout()
	defer cancel()

	var uBlob []byte
	q := `SELECT uBlob
        FROM users
        INNER JOIN identities
          ON users.ID = identities.userID
          WHERE identities.publicKey = ?`
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
	q := `SELECT uBlob
          FROM users
            INNER JOIN identities
            ON users.ID = identities.userID
            WHERE identities.publicKey IN (?` +
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

// AllUsers iterate over all users and executes given callback.
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
	rows, err := m.userDB.QueryContext(ctx, "SELECT uBlob FROM users")
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
		  SET userID = ?, createdAt = ?, sBlob = ?
			WHERE k = ?`,
			session.UserID, session.CreatedAt, session.Blob, session.Key)
		if err != nil {
			return fmt.Errorf("upate: %v", err)
		}
	} else {
		_, err := m.userDB.ExecContext(ctx,
			`INSERT INTO sessions
		(k, userID, createdAt, sBlob)
		VALUES (?, ?, ?, ?)`,
			session.Key, session.UserID, session.CreatedAt, session.Blob)
		if err != nil {
			return fmt.Errorf("create: %v", err)
		}
	}

	return nil
}

// Get a session by its ID. Returns a user.ErrorSessionNotFound if the given
// session ID does not exist
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
	err := m.userDB.QueryRowContext(ctx, "SELECT sBlob FROM sessions WHERE k = ?",
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
			ExecContext(ctx, "DELETE FROM sessions WHERE userID = ?", uid.String())
		return err
	}

	_, err := m.userDB.
		ExecContext(ctx, "DELETE FROM sessions WHERE usedID = ? AND key NOT IN (?)",
			uid.String(), exempt)
	return err
}

// RegisterPlugin registers a plugin.
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

// PluginExec executes a plugin command.
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

// Close shuts down the database.  All interface functions must return with
// errShutdown if the backend is shutting down.
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

	h := fmt.Sprintf("%v:%v@tcp(%v)/%v", userPoliteiawww, password, host, dbname)
	db, err := sql.Open("mysql", h)
	if err != nil {
		return nil, err
	}

	// Setup database options.
	db.SetConnMaxLifetime(connMaxLifetime)
	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)

	// Verify database connection.
	err = db.Ping()
	if err != nil {
		return nil, fmt.Errorf("db ping: %v", err)
	}

	// Setup key-value table.
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
