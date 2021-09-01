// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package localdb

import (
	"bytes"
	"os"
	"path/filepath"
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
// TODO put back in
// _ store.BlobKV = (*localdb)(nil)
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

// put saves the provided key-value pairs to the store.
func (l *localdb) put(blobs map[string][]byte, encrypt bool, batch *leveldb.Batch) error {
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

	return nil
}

// del deletes the provided blobs from the store.
func (l *localdb) del(keys []string, batch *leveldb.Batch) error {
	for _, v := range keys {
		batch.Delete([]byte(v))
	}
	return nil
}

// get returns blobs from the store for the provided keys. An entry will not
// exist in the returned map if for any blobs that are not found. It is the
// responsibility of the caller to ensure a blob was returned for all provided
// keys.
func (l *localdb) get(keys []string) (map[string][]byte, error) {
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

// Put saves the provided key-value pairs to the store. This operation is
// performed atomically.
//
// This function satisfies the store BlobKV interface.
func (l *localdb) Put(blobs map[string][]byte, encrypt bool) error {
	log.Tracef("Put: %v blobs", len(blobs))

	l.Lock()
	defer l.Unlock()
	if l.shutdown {
		return store.ErrShutdown
	}

	// Save blobs to a batch
	batch := new(leveldb.Batch)
	err := l.put(blobs, encrypt, batch)
	if err != nil {
		return err
	}

	// Write batch
	err = l.db.Write(batch, nil)
	if err != nil {
		return errors.WithStack(err)
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

	l.Lock()
	defer l.Unlock()
	if l.shutdown {
		return store.ErrShutdown
	}

	batch := new(leveldb.Batch)
	err := l.del(keys, batch)
	if err != nil {
		return err
	}

	err = l.db.Write(batch, nil)
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

	l.Lock()
	defer l.Unlock()
	if l.shutdown {
		return nil, store.ErrShutdown
	}

	return l.get(keys)
}

// Tx returns a new database transaction as well as the cancel function that
// releases all resources associated with it.
//
// This function satisfies the store BlobKV interface.
func (l *localdb) Tx() (store.Tx, func(), error) {
	// TODO put back in
	// tx, cancel := newTx(l)
	// return tx, cancel, nil
	return nil, nil, nil
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

	return &localdb{
		db:  db,
		key: key,
	}, nil
}
