// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"os"
	"path/filepath"
	"sync"

	"github.com/pkg/errors"
	"github.com/syndtr/goleveldb/leveldb"
)

var (
	// errShutdown is returned by all methods once the database has been
	// shutdown.
	errShutdown = errors.New("database is shutdown")

	// errNotFound is returned by some methods when a database entry is not
	// found.
	errNotFound = errors.New("entry not found")
)

// kvdb provides a concurrency safe API for interacting with the LevelDB
// key-value database.
type kvdb struct {
	sync.Mutex
	db       *leveldb.DB
	shutdown bool
}

// newkvdb returns a new kvdb.
func newKvdb(dataDir string) (*kvdb, error) {
	// Setup the LevelDB data directory
	dataDir = filepath.Join(dataDir, "leveldb")
	err := os.MkdirAll(dataDir, 0700)
	if err != nil {
		return nil, err
	}

	log.Tracef("LevelDB: %v", dataDir)

	// Open up a LevelDB connection
	db, err := leveldb.OpenFile(dataDir, nil)
	if err != nil {
		return nil, err
	}

	return &kvdb{
		db: db,
	}, nil
}

// Put saves an entry to the key-value database for each of the provided
// key-value pairs. Existing entries are overwritten. This operation is atomic.
func (d *kvdb) Put(entries map[string][]byte) error {
	log.Tracef("LevelDB Put")

	d.Lock()
	defer d.Unlock()
	if d.shutdown {
		return errShutdown
	}

	batch := new(leveldb.Batch)
	for k, v := range entries {
		batch.Put([]byte(k), v)
	}

	return d.db.Write(batch, nil)
}

// Del deletes the provided entries from the database. This operation is
// atomic.
//
// Keys that do not correspond to database entries are ignored. An error is
// not returned.
func (d *kvdb) Del(keys []string) error {
	log.Tracef("LevelDB Del: %v", keys)

	d.Lock()
	defer d.Unlock()
	if d.shutdown {
		return errShutdown
	}

	batch := new(leveldb.Batch)
	for _, k := range keys {
		batch.Delete([]byte(k))
	}

	return d.db.Write(batch, nil)
}

// Get gets an entry from the database.
//
// An errNotFound error is returned if the key does not correspond to an entry.
func (d *kvdb) Get(key string) ([]byte, error) {
	log.Tracef("LevelDB Get: %v", key)

	d.Lock()
	defer d.Unlock()
	if d.shutdown {
		return nil, errShutdown
	}

	value, err := d.db.Get([]byte(key), nil)
	if err == leveldb.ErrNotFound {
		return nil, errNotFound
	} else if err != nil {
		return nil, errors.WithStack(err)
	}

	return value, nil
}

// GetBatch gets a batch of entries from the database.
//
// An entry will not exist in the returned map for keys that are not found. It
// is the responsibility of the caller to ensure a entry was returned for all
// provided keys. An error is not returned.
func (d *kvdb) GetBatch(keys []string) (map[string][]byte, error) {
	log.Tracef("LevelDB GetBatch: %v", keys)

	d.Lock()
	defer d.Unlock()
	if d.shutdown {
		return nil, errShutdown
	}

	entries := make(map[string][]byte, len(keys))
	for _, key := range keys {
		value, err := d.db.Get([]byte(key), nil)
		if err == leveldb.ErrNotFound {
			// Entry doesn't exist; continue
		} else if err != nil {
			return nil, errors.WithStack(err)
		}
		entries[key] = value
	}

	return entries, nil
}

// Iter iterates over all entries in the database and invokes the callback
// function on each entry.
func (d *kvdb) Iter(callback func(key string, value []byte) error) error {
	log.Tracef("LevelDB Iter")

	d.Lock()
	defer d.Unlock()
	if d.shutdown {
		return errShutdown
	}

	iter := d.db.NewIterator(nil, nil)
	for iter.Next() {
		err := callback(string(iter.Key()), iter.Value())
		if err != nil {
			iter.Release()
			return err
		}
	}

	iter.Release()
	return iter.Error()
}

// Close closes the database connection.
func (d *kvdb) Close() {
	log.Tracef("LevelDB Close")

	d.Lock()
	defer d.Unlock()

	d.db.Close()
	d.shutdown = true
}
