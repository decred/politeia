// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cockroachdb

import (
	"net/url"
	"path/filepath"
	"sync"
	"time"

	"github.com/decred/politeia/politeiawww/database"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

const (
	dbPrefix = "users_"

	// UserPoliteiawww is a database user with read/write access.
	UserPoliteiawww = "politeiawww"

	// Database table names.
	tableKeyValue = "key_value"

	// UserVersion is the curent database version.
	UserVersion uint32 = 1
)

var (
	_ database.Database = (*cockroachdb)(nil)
)

// Config defines a set of config options to be passed in when creating a new
// cockroachdb context.
type Config struct {
	UseEncryption bool // Apply data encryption or not
}

// cockroachdb implements the database interface.
type cockroachdb struct {
	sync.RWMutex
	shutdown      bool                    // Backend is shutdown
	usersdb       *gorm.DB                // Database context
	encryptionKey *database.EncryptionKey // Encryption key
	dbAddress     string                  // Database address

	cfg *Config // cockroachdb context config
}

// buildDBQueryStirng assembles the certification query string contained
// in the database connection URL.
func buildDBQueryString(rootCert, certDir string, u *url.URL) string {
	v := url.Values{}
	v.Set("ssl", "true")
	v.Set("sslmode", "require")
	v.Set("sslrootcert", filepath.Clean(rootCert))
	v.Set("sslkey", filepath.Join(certDir, "client."+u.User.String()+".key"))
	v.Set("sslcert", filepath.Join(certDir, "client."+u.User.String()+".crt"))

	return v.Encode()
}

// createTables sets up the tables for cockroach db.
func createTables(db *gorm.DB) error {
	log.Tracef("createTables")

	if !db.HasTable(tableKeyValue) {
		err := db.CreateTable(&KeyValue{}).Error
		if err != nil {
			return err
		}
	}

	return nil
}

// Put stores a payload by a given key.
func (c *cockroachdb) Put(key string, payload []byte) error {
	log.Tracef("Put: %v", key)

	c.RLock()
	shutdown := c.shutdown
	c.RUnlock()

	if shutdown {
		return database.ErrShutdown
	}

	// Run put within a transaction.
	tx := c.usersdb.Begin()

	// Encrypt payload.
	var err error
	if c.cfg.UseEncryption {
		payload, err = database.Encrypt(database.DatabaseVersion, c.encryptionKey.Key, payload)
		if err != nil {
			return err
		}
	}

	// Try to find the record with the provided key.
	var keyValue KeyValue
	err = tx.Where("key = ?", key).First(&keyValue).Error
	if gorm.IsRecordNotFoundError(err) {
		// If the record is not found, create one
		err = tx.Create(&KeyValue{
			Key:     key,
			Payload: payload,
		}).Error
		if err != nil {
			tx.Rollback()
			return err
		}
	} else if err != nil {
		tx.Rollback()
		return err
	} else {
		// Record found, update existent value.
		err = tx.Model(&keyValue).Update(&KeyValue{
			Payload: payload,
		}).Error
		if err != nil {
			tx.Rollback()
			return err
		}
	}

	return tx.Commit().Error
}

// Get returns a payload by a given key.
func (c *cockroachdb) Get(key string) ([]byte, error) {
	log.Tracef("Get: %v", key)

	c.RLock()
	shutdown := c.shutdown
	c.RUnlock()

	if shutdown {
		return nil, database.ErrShutdown
	}

	// Try to find the record in the database.
	var keyValue KeyValue
	err := c.usersdb.Where("key = ?", key).First(&keyValue).Error
	if gorm.IsRecordNotFoundError(err) {
		return nil, database.ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	// Return the record payload as it is if the encryption is disabled.
	if !c.cfg.UseEncryption {
		return keyValue.Payload, nil
	}

	// Decrypt the record payload.
	payload, _, err := database.Decrypt(c.encryptionKey.Key, keyValue.Payload)
	if err != nil {
		return nil, err
	}

	return payload, nil
}

// Remove removes a database record by the provided key.
func (c *cockroachdb) Remove(key string) error {
	log.Tracef("Remove: %v", key)

	c.RLock()
	shutdown := c.shutdown
	c.RUnlock()

	if shutdown {
		return database.ErrShutdown
	}

	err := c.usersdb.Where("key = ?", key).Delete(KeyValue{}).Error
	if err != nil {
		return err
	}

	return nil
}

// GetAll iterates over the entire database, applying the provided callback
// function for each record.
func (c *cockroachdb) GetAll(callbackFn func(string, []byte) error) error {
	log.Tracef("GetAll")

	c.RLock()
	shutdown := c.shutdown
	c.RUnlock()

	if shutdown {
		return database.ErrShutdown
	}

	var values []KeyValue
	err := c.usersdb.Find(&values).Error
	if err != nil {
		return err
	}
	for _, v := range values {
		// Decrypt the record payload.
		if !c.cfg.UseEncryption {
			err := callbackFn(v.Key, v.Payload)
			if err != nil {
				return err
			}
			continue
		}

		decValue, _, err := database.Decrypt(c.encryptionKey.Key, v.Payload)
		if err != nil {
			return err
		}

		err = callbackFn(v.Key, decValue)
		if err != nil {
			return err
		}
	}

	return nil
}

// Has returns true if the database does contain the given key.
func (c *cockroachdb) Has(key string) (bool, error) {
	log.Tracef("Has: %v", key)

	c.RLock()
	shutdown := c.shutdown
	c.RUnlock()

	if shutdown {
		return false, database.ErrShutdown
	}

	// Try to find the record in the database.
	var keyValue KeyValue
	err := c.usersdb.Where("key = ?", key).First(&keyValue).Error
	if gorm.IsRecordNotFoundError(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	return true, nil

}

// GetSnapshot returns a snapshot from the entire database.
func (c *cockroachdb) GetSnapshot() (*database.Snapshot, error) {
	log.Tracef("GetSnapshot")

	c.RLock()
	shutdown := c.shutdown
	c.RUnlock()

	if shutdown {
		return nil, database.ErrShutdown
	}

	// Build the db snapshot within a transaction.
	tx := c.usersdb.Begin()
	snapshot := database.Snapshot{
		Time:     time.Now().Unix(),
		Version:  database.DatabaseVersion,
		Snapshot: make(map[string][]byte),
	}

	// Find all values in the database.
	var values []KeyValue
	err := tx.Find(&values).Error
	if err != nil {
		tx.Rollback()
		return nil, err
	}

	for _, v := range values {
		// Decrypt the record payload.
		if !c.cfg.UseEncryption {
			snapshot.Snapshot[v.Key] = v.Payload
			continue
		}

		decValue, _, err := database.Decrypt(c.encryptionKey.Key, v.Payload)
		if err != nil {
			tx.Rollback()
			return nil, err
		}
		snapshot.Snapshot[v.Key] = decValue
	}

	err = tx.Commit().Error
	if err != nil {
		return nil, err
	}

	return &snapshot, nil
}

// BuildFromSnapshot builds recreates the entire the database using the
// provided snapshot. It won't recreate the database if the snapshot version
// does not match the current version of the database.
func (c *cockroachdb) BuildFromSnapshot(snapshot database.Snapshot) error {
	log.Tracef("BuildFromSnapshot")

	c.RLock()
	shutdown := c.shutdown
	c.RUnlock()

	if shutdown {
		return database.ErrShutdown
	}

	// validate snapshot version
	if snapshot.Version != database.DatabaseVersion {
		return database.ErrWrongSnapshotVersion
	}

	// Run the database rebuild withint a transaction
	tx := c.usersdb.Begin()

	// Delete the database content
	err := tx.Delete(&KeyValue{}).Error
	if err != nil {
		tx.Rollback()
		return err
	}

	// Iterate over the snapshot and create the records into the dbtransaction.
	for key, v := range snapshot.Snapshot {
		payload := v
		// Encrypt the payload if encryption is turned on
		if c.cfg.UseEncryption {
			payload, err = database.Encrypt(database.DatabaseVersion, c.encryptionKey.Key, v)
			if err != nil {
				tx.Rollback()
				return err
			}
		}
		// Create the record in the db transaction.
		err = tx.Create(&KeyValue{
			Key:     key,
			Payload: payload,
		}).Error
		if err != nil {
			tx.Rollback()
			return err
		}
	}

	// Commit the transaction.
	return tx.Commit().Error
}

// Open opens a new database connection and make sure there is a version record
// stored in the database. If the version record already exists, it will try to
// decrypt it to verify that the encryption key is valid; otherwise a new version
// record will be created in the database.
func (c *cockroachdb) Open() error {
	log.Tracef("Open cockroachdb")

	// Open a new database connection.
	db, err := gorm.Open("postgres", c.dbAddress)
	if err != nil {
		log.Debugf("Open: could not connect to %v", c.dbAddress)
		return err
	}

	c.usersdb = db

	// See if we need to write a version record.
	_, err = c.Get(database.DatabaseVersionKey)

	if err == database.ErrNotFound {
		// Write version record.
		payload, err := database.EncodeVersion(database.Version{
			Version: database.DatabaseVersion,
			Time:    time.Now().Unix(),
		})
		if err != nil {
			return err
		}

		return c.Put(database.DatabaseVersionKey, payload)
	} else if err != nil {
		return err
	}

	return nil
}

// Close shuts down the database.  All interface functions MUST return with
// errShutdown if the backend is shutting down.
func (c *cockroachdb) Close() error {
	log.Tracef("Close")

	c.Lock()
	defer c.Unlock()

	c.shutdown = true
	return c.usersdb.Close()
}

// CreateCDB uses the CockroachDB root user to create a database,
// politeiawww user if it does not already exist. User permissions are then
// set for the database and the database tables are created if they do not
// already exist.
func CreateCDB(host, net, rootCert, certDir string) error {
	log.Tracef("Create cockroachDB: %v %v %v %v", host, net, rootCert, certDir)
	// Connect to CockroachDB as root user. CockroachDB connects
	// to defaultdb when a database is not specified.
	h := "postgresql://root@" + host
	u, err := url.Parse(h)
	if err != nil {
		log.Debugf("Create: could not parse url %v", h)
		return err
	}

	qs := buildDBQueryString(rootCert, certDir, u)

	addr := u.String() + "?" + qs

	db, err := gorm.Open("postgres", addr)
	if err != nil {
		log.Debugf("Create: could not connect to %v", addr)
		return err
	}
	defer db.Close()

	// Setup politeiawww database and users.
	dbName := dbPrefix + net
	q := "CREATE DATABASE IF NOT EXISTS " + dbName
	err = db.Exec(q).Error
	if err != nil {
		return err
	}

	q = "CREATE USER IF NOT EXISTS " + UserPoliteiawww
	err = db.Exec(q).Error
	if err != nil {
		return err
	}
	q = "GRANT ALL ON DATABASE " + dbName + " TO " + UserPoliteiawww
	err = db.Exec(q).Error
	if err != nil {
		return err
	}

	// Connect to records database with root user.
	h = "postgresql://root@" + host + "/" + dbName
	u, err = url.Parse(h)
	if err != nil {
		log.Debugf("Create: could not parse url %v", h)
		return err
	}
	addr = u.String() + "?" + qs
	pdb, err := gorm.Open("postgres", addr)
	defer pdb.Close()
	if err != nil {
		log.Debugf("Create: could not connect to %v", addr)
		return err
	}

	// Setup database tables.
	tx := pdb.Begin()
	err = createTables(tx)
	if err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit().Error
}

// NewCDB returns a new cockroachdb context which contains a connection to the
// specified database that was made using the passed in user and certificates.
func NewCDB(user, host, net, rootCert, certDir string, dbKey *database.EncryptionKey, cfg *Config) (*cockroachdb, error) {
	log.Tracef("New CockroachDB: %v %v %v %v %v %v", user, host, net, rootCert, certDir)

	// Connect to the database.
	h := "postgresql://" + user + "@" + host + "/" + dbPrefix + net
	u, err := url.Parse(h)
	if err != nil {
		log.Debugf("New: could not parse url %v", h)
		return nil, err
	}

	qs := buildDBQueryString(rootCert, certDir, u)

	addr := u.String() + "?" + qs

	// If config is not set we create a default one.
	if cfg == nil {
		cfg = &Config{
			UseEncryption: true,
		}
	}

	// Setup db context.
	c := &cockroachdb{
		dbAddress:     addr,
		encryptionKey: dbKey,
		cfg:           cfg,
	}

	// Open the database
	err = c.Open()
	if err != nil {
		return nil, err
	}

	// Disable gorm logging. This prevents duplicate errors from
	// being printed since we handle errors manually.
	c.usersdb.LogMode(false)

	// Disable automatic table name pluralization. We set table
	// names manually.
	c.usersdb.SingularTable(true)

	return c, err
}
