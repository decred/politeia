// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package localdb

import (
	"errors"
	"fmt"
	"sync"

	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
	"github.com/google/uuid"
	"github.com/syndtr/goleveldb/leveldb"
)

var (
	_ store.BlobKV = (*localdb)(nil)
)

// localdb implements the store BlobKV interface using leveldb.
type localdb struct {
	sync.Mutex
	shutdown bool
	root     string // Location of database
	db       *leveldb.DB
}

// Put saves the provided blobs to the store. The keys for the blobs are
// returned using the same odering that the blobs were provided in. This
// operation is performed atomically.
//
// This function satisfies the store BlobKV interface.
func (l *localdb) Put(blobs [][]byte) ([]string, error) {
	log.Tracef("Put: %v", len(blobs))

	// Setup batch
	var (
		batch = new(leveldb.Batch)
		keys  = make([]string, 0, len(blobs))
	)
	for _, v := range blobs {
		key := uuid.New().String()
		batch.Put([]byte(key), v)
		keys = append(keys, key)
	}

	// Write batch
	err := l.db.Write(batch, nil)
	if err != nil {
		return nil, err
	}

	log.Debugf("Saved blobs (%v) to store", len(blobs))

	return keys, nil
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

	return blobs, nil
}

// Closes closes the store connection.
//
// This function satisfies the store BlobKV interface.
func (l *localdb) Close() {
	l.Lock()
	defer l.Unlock()

	l.db.Close()
}

// New returns a new localdb.
func New(root string) (*localdb, error) {
	db, err := leveldb.OpenFile(root, nil)
	if err != nil {
		return nil, err
	}

	return &localdb{
		db:   db,
		root: root,
	}, nil
}
