// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package filesystem

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"

	"github.com/decred/politeia/politeiad/backend/tlogbe/store"
)

var (
// TODO put back
// _ store.Blob = (*fileSystem)(nil)
)

// fileSystem implements the Blob interface using the file system.
type fileSystem struct {
	sync.RWMutex
	root string // Location of files
}

func (f *fileSystem) put(key string, value []byte) error {
	return ioutil.WriteFile(filepath.Join(f.root, key), value, 0600)
}

func (f *fileSystem) Put(key string, value []byte) error {
	log.Tracef("Put: %v", key)

	f.Lock()
	defer f.Unlock()

	return f.put(key, value)
}

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

func (f *fileSystem) Get(key string) ([]byte, error) {
	log.Tracef("Get: %v", key)

	f.RLock()
	defer f.RUnlock()

	return f.get(key)
}

func (f *fileSystem) del(key string) error {
	err := os.Remove(filepath.Join(f.root, key))
	if err != nil {
		// Always return not found
		return store.ErrNotFound
	}
	return nil
}

func (f *fileSystem) Del(key string) error {
	log.Tracef("Del: %v", key)

	f.Lock()
	defer f.Unlock()

	return f.del(key)
}

func (f *fileSystem) Enum(cb func(key string, value []byte) error) error {
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
		blob, err := f.Get(file.Name())
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

func (f *fileSystem) batch(ops store.Ops) error {
	for _, fn := range ops.Del {
		log.Tracef("del: %v", fn)
		err := f.del(fn)
		if err != nil {
			return fmt.Errorf("del %v: %v", fn, err)
		}
	}
	for fn, b := range ops.Put {
		log.Tracef("put: %v", fn)
		err := f.put(fn, b)
		if err != nil {
			return fmt.Errorf("put %v: %v", fn, err)
		}
	}
	return nil
}

func (f *fileSystem) Batch(ops store.Ops) error {
	log.Tracef("Batch")

	f.Lock()
	defer f.Unlock()

	// Temporarily store del files in case we need to unwind
	dels := make(map[string][]byte, len(ops.Del))
	for _, fn := range ops.Del {
		b, err := f.get(fn)
		if err != nil {
			return fmt.Errorf("get %v: %v", fn, err)
		}
		dels[fn] = b
	}

	// Temporarily store existing put files in case we need to unwind.
	// An existing put file may or may not exist.
	puts := make(map[string][]byte, len(ops.Put))
	for fn := range ops.Put {
		b, err := f.get(fn)
		if err != nil {
			if err == store.ErrNotFound {
				// File doesn't exist. This is ok.
				continue
			}
			return fmt.Errorf("get %v: %v", fn, err)
		}
		puts[fn] = b
	}

	err := f.batch(ops)
	if err != nil {
		// Unwind puts
		for fn := range ops.Put {
			err2 := f.del(fn)
			if err2 != nil {
				// This is ok. It just means the file was never saved before
				// the batch function exited with an error.
				log.Debugf("batch unwind: del %v: %v", fn, err2)
				continue
			}
		}

		// Replace existing puts
		var unwindFailed bool
		for fn, b := range puts {
			err2 := f.put(fn, b)
			if err2 != nil {
				// We're in trouble!
				log.Criticalf("batch unwind: unable to put original file back %v: %v",
					fn, err2)
				unwindFailed = true
				continue
			}
		}

		// Unwind deletes
		for fn, b := range dels {
			_, err2 := f.get(fn)
			if err2 == nil {
				// File was never deleted. Nothing to do.
				continue
			}
			// File was deleted. Put it back.
			err2 = f.put(fn, b)
			if err2 != nil {
				// We're in trouble!
				log.Criticalf("batch unwind: unable to put deleted file back %v: %v",
					fn, err2)
				unwindFailed = true
				continue
			}
		}

		if unwindFailed {
			// Print orignal error that caused the unwind then panic
			// because the unwind failed.
			log.Errorf("batch: %v", err)
			panic("batch unwind failed")
		}

		return err
	}

	return nil
}

func New(root string) *fileSystem {
	return &fileSystem{
		root: root,
	}
}
