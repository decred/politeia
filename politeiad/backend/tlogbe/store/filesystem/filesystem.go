// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package filesystem

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"

	"github.com/decred/politeia/politeiad/backend/tlogbe/store"
	"github.com/google/uuid"
)

var (
	_ store.Blob = (*fileSystem)(nil)
)

// fileSystem implements the Blob interface using the file system.
//
// This implementation should be used for TESTING ONLY.
type fileSystem struct {
	sync.RWMutex
	root string // Location of files
}

// put saves a files to the file system.
//
// This function must be called WITH the lock held.
func (f *fileSystem) put(key string, value []byte) error {
	return ioutil.WriteFile(filepath.Join(f.root, key), value, 0600)
}

// This function must be called WITH the lock held.
func (f *fileSystem) del(key string) error {
	err := os.Remove(filepath.Join(f.root, key))
	if err != nil {
		if os.IsNotExist(err) {
			return store.ErrNotFound
		}
		return err
	}
	return nil
}

// get retrieves a file from the file system.
//
// This function must be called WITH the lock held.
func (f *fileSystem) get(key string) ([]byte, error) {
	b, err := ioutil.ReadFile(filepath.Join(f.root, key))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	return b, nil
}

// Put saves the provided blobs to the file system. The keys for the blobs
// are generated in this function and returned.
//
// This function satisfies the Blob interface.
func (f *fileSystem) Put(blobs [][]byte) ([]string, error) {
	log.Tracef("Put: %v", len(blobs))

	f.Lock()
	defer f.Unlock()

	// Save blobs to file system
	keys := make([]string, 0, len(blobs))
	for _, v := range blobs {
		key := uuid.New().String()
		err := f.put(key, v)
		if err != nil {
			// Unwind blobs that have already been saved
			for _, v := range keys {
				err2 := f.del(v)
				if err2 != nil {
					// We're in trouble!
					log.Criticalf("Failed to unwind put blob %v: %v", v, err2)
					continue
				}
			}
			return nil, err
		}
		keys = append(keys, key)
	}

	return keys, nil
}

// Del deletes the files from the file system that correspond to the provided
// keys.
//
// This function satisfies the Blob interface.
func (f *fileSystem) Del(keys []string) error {
	log.Tracef("Del: %v", keys)

	f.Lock()
	defer f.Unlock()

	// Temporarily store del files in case we need to unwind
	dels := make(map[string][]byte, len(keys))
	for _, v := range keys {
		b, err := f.get(v)
		if err != nil {
			return fmt.Errorf("get %v: %v", v, err)
		}
		dels[v] = b
	}

	// Delete files
	deleted := make([]string, 0, len(keys))
	for _, v := range keys {
		err := f.del(v)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				// File does not exist. This is ok.
				continue
			}

			// File does exist but del failed. Unwind deleted files.
			for _, key := range deleted {
				b := dels[key]
				err2 := f.put(key, b)
				if err2 != nil {
					// We're in trouble!
					log.Criticalf("Failed to unwind del blob %v: %v %x", key, err, b)
					continue
				}
			}
			return fmt.Errorf("del %v: %v", v, err)
		}

		deleted = append(deleted, v)
	}

	return nil
}

// Get returns blobs from the file system for the provided keys. An entry will
// not exist in the returned map if for any blobs that are not found. It is the
// responsibility of the caller to ensure a blob was returned for all provided
// keys.
//
// This function satisfies the Blob interface.
func (f *fileSystem) Get(keys []string) (map[string][]byte, error) {
	log.Tracef("Get: %v", keys)

	f.RLock()
	defer f.RUnlock()

	blobs := make(map[string][]byte, len(keys))
	for _, v := range keys {
		b, err := f.get(v)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				// File does not exist. This is ok.
				continue
			}
			return nil, fmt.Errorf("get %v: %v", v, err)
		}
		blobs[v] = b
	}

	return blobs, nil
}

// Enum enumerates over all blobs in the store, invoking the provided function
// for each blob.
//
// This function satisfies the Blob interface.
func (f *fileSystem) Enum(cb func(key string, blob []byte) error) error {
	log.Tracef("Enum")

	f.RLock()
	defer f.RUnlock()

	files, err := ioutil.ReadDir(f.root)
	if err != nil {
		return err
	}

	for _, file := range files {
		if file.Name() == ".." {
			continue
		}
		blob, err := f.get(file.Name())
		if err != nil {
			return err
		}
		err = cb(file.Name(), blob)
		if err != nil {
			return err
		}
	}

	return nil
}

// Closes closes the blob store connection.
//
// This function satisfies the Blob interface.
func (f *fileSystem) Close() {}

// New returns a new fileSystem.
func New(root string) *fileSystem {
	return &fileSystem{
		root: root,
	}
}
