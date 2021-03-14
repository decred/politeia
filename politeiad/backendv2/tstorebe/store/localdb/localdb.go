// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package localdb

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
	"github.com/decred/politeia/util"
	"github.com/syndtr/goleveldb/leveldb"
)

const (
	// encryptionKeyFilename is the filename of the encryption key that
	// is created in the store data directory.
	encryptionKeyFilename = "leveldb-sbox.key"
)

var (
	_ store.BlobKV = (*localdb)(nil)
)

// localdb implements the store BlobKV interface using leveldb.
//
// NOTE: this implementation was created for testing. The encryption techniques
// used may not be suitable for a production environment. A random secretbox
// encryption key is created on startup and saved to the politeiad application
// dir. Blobs are encrypted using random 24 byte nonces.
type localdb struct {
	sync.RWMutex
	shutdown bool
	db       *leveldb.DB

	// Encryption key and mutex. The key is zero'd out on application
	// exit so the read lock must be held during concurrent access to
	// prevent the golang race detector from complaining.
	key *[32]byte
}

// Put saves the provided key-value pairs to the store. This operation is
// performed atomically.
//
// This function satisfies the store BlobKV interface.
func (l *localdb) Put(blobs map[string][]byte, encrypt bool) error {
	log.Tracef("Put: %v blobs", len(blobs))

	// Encrypt blobs
	if encrypt {
		for k, v := range blobs {
			e, err := l.encrypt(v)
			if err != nil {
				return fmt.Errorf("encrypt: %v", err)
			}
			blobs[k] = e
		}
	}

	// Setup batch
	batch := new(leveldb.Batch)
	for k, v := range blobs {
		batch.Put([]byte(k), v)
	}

	// Write batch
	err := l.db.Write(batch, nil)
	if err != nil {
		return fmt.Errorf("write batch: %v", err)
	}

	log.Debugf("Saved blobs (%v) to store", len(blobs))

	return nil
}

// Del deletes the provided blobs from the store. This operation is performed
// atomically.
//
// This function satisfies the store BlobKV interface.
func (l *localdb) Del(keys []string) error {
	log.Tracef("Del: %v", keys)

	batch := new(leveldb.Batch)
	for _, v := range keys {
		batch.Delete([]byte(v))
	}
	err := l.db.Write(batch, nil)
	if err != nil {
		return err
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
func (l *localdb) Get(keys []string) (map[string][]byte, error) {
	log.Tracef("Get: %v", keys)

	// Lookup blobs
	blobs := make(map[string][]byte, len(keys))
	for _, v := range keys {
		b, err := l.db.Get([]byte(v), nil)
		if err != nil {
			if errors.Is(err, leveldb.ErrNotFound) {
				// File does not exist. This is ok.
				continue
			}
			return nil, fmt.Errorf("get %v: %v", v, err)
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
			return nil, fmt.Errorf("decrypt: %v", err)
		}
		blobs[k] = b
	}

	return blobs, nil
}

// Closes closes the store connection.
//
// This function satisfies the store BlobKV interface.
func (l *localdb) Close() {
	l.Lock()
	defer l.Unlock()

	l.zeroKey()
	l.db.Close()
}

// New returns a new localdb.
func New(appDir, dataDir string) (*localdb, error) {
	// Load encryption key
	keyFile := filepath.Join(appDir, encryptionKeyFilename)
	key, err := util.LoadEncryptionKey(log, keyFile)
	if err != nil {
		return nil, err
	}

	// Open database
	db, err := leveldb.OpenFile(dataDir, nil)
	if err != nil {
		return nil, err
	}

	return &localdb{
		db:  db,
		key: key,
	}, nil
}
