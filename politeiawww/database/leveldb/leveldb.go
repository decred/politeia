// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package leveldb

import (
	"path/filepath"
	"sync"
	"time"

	"github.com/decred/politeia/politeiawww/database"
	ldb "github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

const (
	UserdbPath = "users"
)

var (
	_ database.Database = (*leveldb)(nil)
)

// Config defines a set of config options to be passed in when creating a new
// leveldb context.
type Config struct {
	UseEncryption bool // Apply data encryption or not
}

// leveldb implements the database interface.
type leveldb struct {
	sync.RWMutex
	shutdown      bool                    // Backend is shutdown
	root          string                  // Database root
	userdb        *ldb.DB                 // Database context
	encryptionKey *database.EncryptionKey // Encryption key

	cfg *Config // leveldb context config
}

// Put stores a payload by a given key.
func (l *leveldb) Put(key string, payload []byte) error {
	log.Tracef("Put %v:", key)

	l.RLock()
	shutdown := l.shutdown
	l.RUnlock()

	if shutdown {
		return database.ErrShutdown
	}

	var err error
	if l.cfg.UseEncryption {
		// Encrypt payload.
		payload, err = database.Encrypt(database.DatabaseVersion, l.encryptionKey.Key, payload)
		if err != nil {
			return err
		}
	}

	return l.userdb.Put([]byte(key), payload, nil)
}

// Get returns a payload by a given key.
func (l *leveldb) Get(key string) ([]byte, error) {
	log.Tracef("Get: %v", key)

	l.RLock()
	shutdown := l.shutdown
	l.RUnlock()

	if shutdown {
		return nil, database.ErrShutdown
	}

	// Try to find the record in the database.
	payload, err := l.userdb.Get([]byte(key), nil)
	if err == ldb.ErrNotFound {
		return nil, database.ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	// Return the plain value if encryption is disabled.
	if !l.cfg.UseEncryption {
		return payload, nil
	}

	// Decrypt record.
	payload, _, err = database.Decrypt(l.encryptionKey.Key, payload)
	if err != nil {
		return nil, err
	}

	return payload, nil
}

// Remove removes a database record by the provided key.
func (l *leveldb) Remove(key string) error {
	log.Tracef("Remove: %v", key)

	l.RLock()
	shutdown := l.shutdown
	l.RUnlock()

	if shutdown {
		return database.ErrShutdown
	}

	return l.userdb.Delete([]byte(key), nil)
}

// GetAll iterates over the entire database, applying the provided callback
// function for each record.
func (l *leveldb) GetAll(callbackFn func(string, []byte) error) error {
	log.Tracef("GetAll")

	l.RLock()
	shutdown := l.shutdown
	l.RUnlock()

	if shutdown {
		return database.ErrShutdown
	}

	iter := l.userdb.NewIterator(nil, nil)
	defer iter.Release()

	for iter.Next() {
		key := iter.Key()
		value := iter.Value()

		if !l.cfg.UseEncryption {
			err := callbackFn(string(key), value)
			if err != nil {
				return err
			}
			continue
		}

		// Decrypt the record payload.
		decValue, _, err := database.Decrypt(l.encryptionKey.Key, value)
		if err != nil {
			return err
		}

		err = callbackFn(string(key), decValue)
		if err != nil {
			return err
		}
		// err = callbackFn(string(key), decValue)
		// if err != nil {
		// 	return err
		// }
	}

	return iter.Error()
}

// Has returns true if the database does contain the given key.
func (l *leveldb) Has(key string) (bool, error) {
	log.Tracef("Has: %v", key)

	l.RLock()
	shutdown := l.shutdown
	l.RUnlock()

	if shutdown {
		return false, database.ErrShutdown
	}

	// Try to find the record in the database.
	return l.userdb.Has([]byte(key), nil)
}

// GetSnapshot returns a snapshot from the entire database.
func (l *leveldb) GetSnapshot() (*database.Snapshot, error) {
	log.Tracef("GetSnapshot")

	l.RLock()
	shutdown := l.shutdown
	l.RUnlock()

	if shutdown {
		return nil, database.ErrShutdown
	}

	// Get leveldb snapshot.
	userdbSnapshot, err := l.userdb.GetSnapshot()
	if err != nil {
		return nil, err
	}
	defer userdbSnapshot.Release()

	snapshot := database.Snapshot{
		Time:     time.Now().Unix(),
		Version:  database.DatabaseVersion,
		Snapshot: make(map[string][]byte),
	}

	iter := userdbSnapshot.NewIterator(nil, nil)
	for iter.Next() {
		key := iter.Key()
		origValue := iter.Value()
		value := make([]byte, len(origValue))
		copy(value, origValue)

		if !l.cfg.UseEncryption {
			snapshot.Snapshot[string(key)] = value
			continue
		}

		// Decrypt the record payload.
		decValue, _, err := database.Decrypt(l.encryptionKey.Key, value)
		if err != nil {
			return nil, err
		}
		snapshot.Snapshot[string(key)] = decValue
	}

	return &snapshot, nil
}

// BuildFromSnapshot builds recreates the entire the database using the
// provided snapshot. It won't recreate the database if the snapshot version
// does not match the current version of the database.
func (l *leveldb) BuildFromSnapshot(snapshot database.Snapshot) error {
	log.Tracef("BuildFromSnapshot")

	l.RLock()
	shutdown := l.shutdown
	l.RUnlock()

	if shutdown {
		return database.ErrShutdown
	}

	// validate snapshot version
	if snapshot.Version != database.DatabaseVersion {
		return database.ErrWrongSnapshotVersion
	}

	// Run the database rebuild within a transaction
	tx, err := l.userdb.OpenTransaction()
	if err != nil {
		return err
	}

	// Delete database content.
	iter := tx.NewIterator(nil, nil)
	for iter.Next() {
		key := iter.Key()

		err := tx.Delete(key, nil)
		if err != nil {
			tx.Discard()
			return err
		}
	}
	iter.Release()

	for k, v := range snapshot.Snapshot {
		payload := v
		// Encrypt the payload if encryption is turned on
		if l.cfg.UseEncryption {
			payload, err = database.Encrypt(database.DatabaseVersion, l.encryptionKey.Key, v)
			if err != nil {
				tx.Discard()
				return err
			}
		}

		// Create the record in the db transaction.
		err := tx.Put([]byte(k), payload, nil)
		if err != nil {
			tx.Discard()
			return err
		}
	}

	// Commit the transaction.
	return tx.Commit()
}

// Open opens a new database connection and make sure there is a version record
// stored in the database. If the version record already exists, it will try to
// decrypt it to verify that the encryption key is valid; otherwise a new version
// record will be created in the database.
func (l *leveldb) Open() error {
	log.Tracef("Open leveldb")

	// Open the database.
	var err error
	l.userdb, err = ldb.OpenFile(filepath.Join(l.root, UserdbPath), &opt.Options{
		ErrorIfMissing: true,
	})
	if err != nil {
		return err
	}

	// See if we need to write a version record.
	payload, err := l.Get(database.DatabaseVersionKey)

	if err == database.ErrNotFound {
		// Write version record.
		payload, err = database.EncodeVersion(database.Version{
			Version: database.DatabaseVersion,
			Time:    time.Now().Unix(),
		})
		if err != nil {
			return err
		}

		return l.Put(database.DatabaseVersionKey, payload)
	} else if err != nil {
		return err
	}

	return nil
}

// Close shuts down the database.  All interface functions MUST return with
// errShutdown if the backend is shutting down.
//
// Close satisfies the backend interface.
func (l *leveldb) Close() error {
	l.Lock()
	defer l.Unlock()

	l.shutdown = true
	return l.userdb.Close()
}

// CreateLevelDB creates a new leveldb database if does not already exist.
func CreateLevelDB(dataDir string) error {
	log.Tracef("Create LevelDB: %v %v", dataDir)

	// OpenFile is called to make sure the db will be created in case it
	// does not already exist.
	db, err := ldb.OpenFile(filepath.Join(dataDir, UserdbPath), nil)
	if err != nil {
		return err
	}

	// Close database.
	err = db.Close()
	if err != nil {
		return err
	}

	return nil
}

// NewLevelDB creates a new leveldb instance. It must be called after the Create
// method, otherwise it will throw an error.
func NewLevelDB(dataDir string, dbKey *database.EncryptionKey, cfg *Config) (*leveldb, error) {
	log.Tracef("New LevelDB: %v %v", dataDir, dbKey)

	// If config is not set we create a default one.
	if cfg == nil {
		cfg = &Config{
			UseEncryption: true,
		}
	}

	// Setup db context.
	l := &leveldb{
		root:          dataDir,
		encryptionKey: dbKey,
		cfg:           cfg,
	}

	err := l.Open()
	if err != nil {
		return nil, err
	}

	return l, nil
}
