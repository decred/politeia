// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package localdb

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
	"github.com/decred/politeia/util"
	"github.com/marcopeereboom/sbox"
	"github.com/pkg/errors"
	"github.com/syndtr/goleveldb/leveldb"
)

const (
	// storeDirname contains the directory name that the leveldb
	// database will be saved to.
	storeDirname = "store"

	// encryptionKeyFilename is the filename of the encryption key that
	// is created in the store data directory.
	encryptionKeyFilename = "leveldb-sbox.key"
)

var (
	_ store.BlobKV = (*localdb)(nil)
)

// localdb implements the store BlobKV interface using leveldb.
//
// This implementation takes a very simple approach to implementing the store
// BlobKV interface and the store Tx interface. All exported calls are locked
// against concurrent access. While this may not be the most performant
// approach, it is the simpliest way to implement a database transaction using
// leveldb.
//
// NOTE: this implementation was created for testing. The encryption techniques
// used may not be suitable for a production environment. A random secretbox
// encryption key is created on startup and saved to the politeiad application
// dir. Blobs are encrypted using random 24 byte nonces.
type localdb struct {
	sync.Mutex
	db       *leveldb.DB
	key      *[32]byte
	shutdown bool
}

// New returns a new localdb.
func New(appDir, dataDir string) (*localdb, error) {
	// Verify config options
	switch {
	case appDir == "":
		return nil, errors.Errorf("app dir not provided")
	case dataDir == "":
		return nil, errors.Errorf("data dir not provided")
	}

	// Setup leveldb data dir
	fp := filepath.Join(dataDir, storeDirname)
	err := os.MkdirAll(fp, 0700)
	if err != nil {
		return nil, err
	}

	// Open database
	db, err := leveldb.OpenFile(fp, nil)
	if err != nil {
		return nil, err
	}

	// Load encryption key
	keyFile := filepath.Join(appDir, encryptionKeyFilename)
	key, err := util.LoadEncryptionKey(log, keyFile)
	if err != nil {
		return nil, err
	}

	// Setup localdb context
	l := &localdb{
		db:  db,
		key: key,
	}

	// Verify that all database operations are working as
	// expected. These are not expensive and should only
	// take a second to run.
	log.Infof("Verifying key-value store operations")

	err = store.TestBlobKV(l)
	if err != nil {
		return nil, err
	}
	err = store.TestTx(l)
	if err != nil {
		return nil, err
	}

	return l, nil
}

// Insert inserts a new entry into the key-value store for each of the provided
// key-value pairs. This operation is atomic.
//
// An ErrDuplicateKey is returned if a provided key already exists in the
// key-value store.
//
// This function satisfies the store BlobKV interface.
func (l *localdb) Insert(blobs map[string][]byte, encrypt bool) error {
	log.Tracef("Insert: %v blobs", len(blobs))

	l.Lock()
	defer l.Unlock()
	if l.shutdown {
		return store.ErrShutdown
	}

	// Setup a new batch. Batched writes are atomic.
	batch := new(leveldb.Batch)
	err := l.insert(blobs, encrypt, batch)
	if err != nil {
		return err
	}

	// Write batch
	err = l.db.Write(batch, nil)
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
//
// This function satisfies the store BlobKV interface.
func (l *localdb) Update(blobs map[string][]byte, encrypt bool) error {
	log.Tracef("Update: %v blobs", len(blobs))

	l.Lock()
	defer l.Unlock()
	if l.shutdown {
		return store.ErrShutdown
	}

	// Setup a new batch. Batched writes are atomic.
	batch := new(leveldb.Batch)
	err := l.update(blobs, encrypt, batch)
	if err != nil {
		return err
	}

	// Write batch
	err = l.db.Write(batch, nil)
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
func (l *localdb) Del(keys []string) error {
	log.Tracef("Del: %v", keys)

	l.Lock()
	defer l.Unlock()
	if l.shutdown {
		return store.ErrShutdown
	}

	// Setup a new batch. Batched writes are atomic.
	batch := new(leveldb.Batch)
	err := l.del(keys, batch)
	if err != nil {
		return err
	}

	// Write batch
	err = l.db.Write(batch, nil)
	if err != nil {
		return err
	}

	return nil
}

// Get returns the blob for the provided key.
//
// An ErrNotFound error is returned if the key does not correspond to an entry.
//
// This function satisfies the store BlobKV interface.
func (l *localdb) Get(key string) ([]byte, error) {
	log.Tracef("Get: %v", key)

	l.Lock()
	defer l.Unlock()
	if l.shutdown {
		return nil, store.ErrShutdown
	}

	blobs, err := l.getBatch([]string{key})
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
// for all provided keys. An error is not returned.
//
// This function satisfies the store BlobKV interface.
func (l *localdb) GetBatch(keys []string) (map[string][]byte, error) {
	log.Tracef("GetBatch: %v", keys)

	l.Lock()
	defer l.Unlock()
	if l.shutdown {
		return nil, store.ErrShutdown
	}

	return l.getBatch(keys)
}

// Tx returns a new database transaction as well as the cancel function that
// releases all resources associated with it.
//
// This function satisfies the store BlobKV interface.
func (l *localdb) Tx() (store.Tx, func(), error) {
	tx, cancel := newTx(l)
	return tx, cancel, nil
}

// Closes closes the store connection.
//
// This function satisfies the store BlobKV interface.
func (l *localdb) Close() {
	log.Tracef("Close")

	l.Lock()
	defer l.Unlock()

	// Prevent any more localdb calls
	l.shutdown = true

	// Zero the encryption key
	util.Zero(l.key[:])

	// Close database
	l.db.Close()
}

// insert adds a Put entry into the leveldb batch for each of the provided
// key-value pairs.
//
// An ErrDuplicateKey is returned if a provided key already exists in the
// key-value store.
func (l *localdb) insert(blobs map[string][]byte, encrypt bool, batch *leveldb.Batch) error {
	// Verify that all provided keys are unique. These
	// do not need to be part of the leveldb batch.
	keys := make([]string, 0, len(blobs))
	for k := range blobs {
		keys = append(keys, k)
	}
	dups, err := l.getBatch(keys)
	if err != nil {
		return err
	}
	if len(dups) != 0 {
		// Duplicate keys found
		keys = make([]string, 0, len(dups))
		for k := range dups {
			keys = append(keys, k)
		}
		e := fmt.Errorf("%w: %v",
			store.ErrDuplicateKey,
			strings.Join(keys, ", "))
		return errors.WithStack(e)
	}

	// Encrypt blobs
	if encrypt {
		for k, v := range blobs {
			e, err := l.encrypt(v)
			if err != nil {
				return err
			}
			blobs[k] = e
		}
	}

	// Save blobs to batch
	for k, v := range blobs {
		batch.Put([]byte(k), v)
	}

	log.Debugf("Inserted blobs (%v) into kv store", len(blobs))

	return nil
}

// update adds a Put entry into the leveldb batch for each of the provided
// key-value pairs.
//
// An ErrNotFound is returned if the caller attempts to update an entry that
// does not exist.
func (l *localdb) update(blobs map[string][]byte, encrypt bool, batch *leveldb.Batch) error {
	// Verify that all provided keys exist. This is not very
	// performant, but the leveldb implementation should only
	// be used when the load is small enough that performance
	// is not a huge concern.
	keys := make([]string, 0, len(blobs))
	for k := range blobs {
		keys = append(keys, k)
	}
	b, err := l.getBatch(keys)
	if err != nil {
		return err
	}
	if len(b) != len(keys) {
		// There are keys missing
		missing := make([]string, 0, len(b))
		for k := range b {
			missing = append(missing, k)
		}
		e := fmt.Errorf("%w: %v", store.ErrNotFound, strings.Join(missing, ", "))
		return errors.WithStack(e)
	}

	// Encrypt blobs
	if encrypt {
		for k, v := range blobs {
			e, err := l.encrypt(v)
			if err != nil {
				return err
			}
			blobs[k] = e
		}
	}

	// Save blobs to batch
	for k, v := range blobs {
		batch.Put([]byte(k), v)
	}

	log.Debugf("Updated blobs (%v) in kv store", len(blobs))

	return nil
}

// del adds a Delete entry into the leveldb batch for each of the provided
// key-value pairs.
func (l *localdb) del(keys []string, batch *leveldb.Batch) error {
	for _, v := range keys {
		batch.Delete([]byte(v))
	}

	log.Debugf("Deleted blobs (%v) from store", len(keys))

	return nil
}

// getBatch returns the blobs from the store for the provided keys.
//
// An entry will not exist in the returned map if for any blobs that are not
// found. It is the responsibility of the caller to ensure a blob was returned
// for all provided keys.
func (l *localdb) getBatch(keys []string) (map[string][]byte, error) {
	// Lookup blobs
	blobs := make(map[string][]byte, len(keys))
	for _, v := range keys {
		b, err := l.db.Get([]byte(v), nil)
		if err != nil {
			if errors.Is(err, leveldb.ErrNotFound) {
				// File does not exist. This is ok.
				continue
			}
			return nil, errors.WithStack(err)
		}
		blobs[v] = b
	}

	// Decrypt blobs
	for k, v := range blobs {
		encrypted := isEncrypted(v)
		log.Tracef("Blob is encrypted: %v", encrypted)
		if !encrypted {
			continue
		}
		b, _, err := l.decrypt(v)
		if err != nil {
			return nil, err
		}
		blobs[k] = b
	}

	return blobs, nil
}

// encrypt encrypts and returns the provided data blob.
func (l *localdb) encrypt(data []byte) ([]byte, error) {
	return sbox.Encrypt(0, l.key, data)
}

// decrypt decrypts the provided data blob. It unpacks the sbox header and
// returns the version and unencrypted data if successful.
func (l *localdb) decrypt(data []byte) ([]byte, uint32, error) {
	return sbox.Decrypt(l.key, data)
}

// isEncrypted returns whether the provided blob has been prefixed with an sbox
// header, indicating that it is an encrypted blob.
func isEncrypted(b []byte) bool {
	return bytes.HasPrefix(b, []byte("sbox"))
}
