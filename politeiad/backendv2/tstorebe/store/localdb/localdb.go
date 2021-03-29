// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package localdb

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"sync/atomic"

	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
	"github.com/decred/politeia/util"
	"github.com/marcopeereboom/sbox"
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
	shutdown uint64
	db       *leveldb.DB
	key      [32]byte
}

func (l *localdb) isShutdown() bool {
	return atomic.LoadUint64(&l.shutdown) != 0
}

func (l *localdb) encrypt(data []byte) ([]byte, error) {
	return sbox.Encrypt(0, &l.key, data)
}

func (l *localdb) decrypt(data []byte) ([]byte, uint32, error) {
	return sbox.Decrypt(&l.key, data)
}

// Put saves the provided key-value pairs to the store. This operation is
// performed atomically.
//
// This function satisfies the store BlobKV interface.
func (l *localdb) Put(blobs map[string][]byte, encrypt bool) error {
	log.Tracef("Put: %v blobs", len(blobs))

	if l.isShutdown() {
		return store.ErrShutdown
	}

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

	if l.isShutdown() {
		return store.ErrShutdown
	}

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

// isEncrypted returns whether the provided blob has been prefixed with an sbox
// header, indicating that it is an encrypted blob.
func isEncrypted(b []byte) bool {
	return bytes.HasPrefix(b, []byte("sbox"))
}

// Get returns blobs from the store for the provided keys. An entry will not
// exist in the returned map if for any blobs that are not found. It is the
// responsibility of the caller to ensure a blob was returned for all provided
// keys.
//
// This function satisfies the store BlobKV interface.
func (l *localdb) Get(keys []string) (map[string][]byte, error) {
	log.Tracef("Get: %v", keys)

	if l.isShutdown() {
		return nil, store.ErrShutdown
	}

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
	log.Tracef("Close")

	atomic.AddUint64(&l.shutdown, 1)

	// Zero the encryption key
	util.Zero(l.key[:])

	// Close database
	l.db.Close()
}

// New returns a new localdb.
func New(appDir, dataDir string) (*localdb, error) {
	// Load encryption key.
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

	// Create context
	ldb := localdb{
		db: db,
	}
	copy(ldb.key[:], key[:])
	util.Zero(key[:])

	return &ldb, nil
}
