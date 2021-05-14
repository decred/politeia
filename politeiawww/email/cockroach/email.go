// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cockroach

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/decred/politeia/politeiawww/email"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/jinzhu/gorm"
)

const (
	databaseID             = "email"
	databaseVersion uint32 = 1

	// Database table names
	tableUserEmailHistory = "email"
	// TODO
	// This key doesn't belong here, move into separate file
	tableKeyValue = "key_value"

	// Database user (read/write access)
	userPoliteiawww = "politeiawww"

	// Key-value store keys
	keyVersion             = "version"
	keyPaywallAddressIndex = "paywalladdressindex"
)

// emailDB provides access to email database.
type emailDB struct {
	sync.RWMutex

	shutdown bool     // Backend is shutdown
	userDB   *gorm.DB // Database context
}

// NewEmailDB opens a connection to the CockroachDB email database and returns
// a new emailDB context. sslRootCert, sslCert, sslKey, and encryptionKey
// are file paths.
func NewEmailDB(host, network, sslRootCert, sslCert, sslKey string) (*emailDB, error) {
	log.Tracef("New: %v %v %v %v %v", host, network, sslRootCert,
		sslCert, sslKey)

	// Build url
	dbName := databaseID + "_" + network
	rawURL := "postgresql://" + userPoliteiawww + "@" + host + "/" + dbName
	u, err := url.Parse(rawURL)
	if err != nil {
		// TODO - replace all %v with %w for error types
		return nil, fmt.Errorf("parse url '%v': %v", rawURL, err)
	}

	q := u.Query()
	q.Add("sslmode", "require")
	q.Add("sslrootcert", sslRootCert)
	q.Add("sslcert", sslCert)
	q.Add("sslkey", sslKey)
	u.RawQuery = q.Encode()

	// Connect to database
	db, err := gorm.Open("postgres", u.String())
	if err != nil {
		return nil, fmt.Errorf("connect to database '%v': %v",
			u.String(), err)
	}

	log.Infof("Host: %v", rawURL)

	// Create context
	c := &emailDB{
		userDB: db,
	}

	// Disable gorm logging. This prevents duplicate errors
	// from being printed since we handle errors manually.
	c.userDB.LogMode(false)

	// Disable automatic table name pluralization.
	// We set table names manually.
	c.userDB.SingularTable(true)

	// Setup database tables
	tx := c.userDB.Begin()
	err = c.createTables(tx)
	if err != nil {
		tx.Rollback()
		return nil, err
	}

	err = tx.Commit().Error
	if err != nil {
		return nil, err
	}

	// Check version record
	kv := KeyValue{
		Key: keyVersion,
	}
	err = c.userDB.Find(&kv).Error
	if err != nil {
		return nil, fmt.Errorf("find version: %v", err)
	}

	// XXX A version mismatch will need to trigger a db
	// migration, but just return an error for now.
	version := binary.LittleEndian.Uint32(kv.Value)
	if version != databaseVersion {
		return nil, fmt.Errorf("version mismatch: got %v, want %v",
			version, databaseVersion)
	}

	return c, err
}

// isShutdown returns whether the backend has been shutdown.
func (c *emailDB) isShutdown() bool {
	c.RLock()
	defer c.RUnlock()

	return c.shutdown
}

func (c *emailDB) RefreshHistories(recipients []string, warningSent bool, timestamp time.Time) error {
	log.Tracef(
		"UserNew: %v %v %v",
		recipients,
		warningSent,
		timestamp,
	)

	if c.isShutdown() {
		return user.ErrShutdown
	}

	// TODO - rewrite implementation
	//// Create new user with a transaction
	//tx := c.userDB.Begin()
	//_, err := c.userNew(tx, u)
	//if err != nil {
	//	tx.Rollback()
	//	return err
	//}
	//
	//return tx.Commit().Error

	return nil
}

func (c *emailDB) FetchHistories(emails []string) ([]email.UserHistory, error) {
	log.Tracef("FetchHistories: %v", emails)

	if c.isShutdown() {
		return nil, user.ErrShutdown
	}

	// TODO - rewrite implementation
	//var u UserEmailHistory
	//err := c.userDB.
	//	Where("username = ?", username).
	//	Find(&u).
	//	Error
	//if err != nil {
	//	if errors.Is(err, gorm.ErrRecordNotFound) {
	//		err = user.ErrUserNotFound
	//	}
	//	return nil, err
	//}

	return nil, nil
}

// Close shuts down the database.  All interface functions must return with
// errShutdown if the backend is shutting down.
func (c *emailDB) Close() error {
	log.Tracef("Close")

	c.Lock()
	defer c.Unlock()

	c.shutdown = true
	return c.userDB.Close()
}

func (c *emailDB) createTables(tx *gorm.DB) error {
	if !tx.HasTable(tableKeyValue) {
		err := tx.CreateTable(&KeyValue{}).Error
		if err != nil {
			return err
		}
	}
	if !tx.HasTable(tableUserEmailHistory) {
		err := tx.CreateTable(&UserEmailHistory{}).Error
		if err != nil {
			return err
		}
	}

	// Insert version record
	kv := KeyValue{
		Key: keyVersion,
	}
	err := tx.Find(&kv).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			b := make([]byte, 8)
			binary.LittleEndian.PutUint32(b, databaseVersion)
			kv.Value = b
			err = tx.Save(&kv).Error
		}
	}

	return err
}
