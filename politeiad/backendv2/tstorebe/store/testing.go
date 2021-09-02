// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package store

import (
	"bytes"

	"github.com/pkg/errors"
)

// TestBlobKV runs through a series of BlobKV operations to verify that basic
// functionality of the BlobKV implementation is working correctly.
//
// These are not unit tests. These are intended to be run against an actual
// database on initialization of a BlobKV implemenation.
func TestBlobKV(kv BlobKV) error {
	var (
		key = "testops-key"

		batchKey1 = "testops-batchkey-1"
		batchKey2 = "testops-batchkey-2"

		value1 = []byte("value-1")
		value2 = []byte("value-2")
		value3 = []byte("value-3")
		value4 = []byte("value-4")
	)

	// Clear out any previous test data
	err := kv.Del([]string{key, batchKey1, batchKey2})
	if err != nil {
		return err
	}

	// Verify that the entry doesn't exist
	_, err = kv.Get(key)
	if !errors.Is(err, ErrNotFound) {
		return errors.Errorf("got error %v, want %v",
			err, ErrNotFound)
	}

	// Update an entry that doesn't exist
	blobs := map[string][]byte{key: value1}
	err = kv.Update(blobs, false)
	if !errors.Is(err, ErrNotFound) {
		return errors.Errorf("got error %v, want %v",
			err, ErrNotFound)
	}

	// Verify that the entry still doesn't exist
	_, err = kv.Get(key)
	if !errors.Is(err, ErrNotFound) {
		return errors.Errorf("got error %v, want %v",
			err, ErrNotFound)
	}

	// Insert a new entry
	err = kv.Insert(blobs, false)
	if err != nil {
		return err
	}

	// Verify that the entry exists
	b, err := kv.Get(key)
	if err != nil {
		return err
	}
	if !bytes.Equal(b, value1) {
		return errors.Errorf("got %s, want %s", b, value1)
	}

	// Verify that duplicate keys are not allowed
	err = kv.Insert(blobs, false)
	if !errors.Is(err, ErrDuplicateKey) {
		return errors.Errorf("got error %v, want %v",
			err, ErrDuplicateKey)
	}

	// Update the entry
	blobs = map[string][]byte{key: value2}
	err = kv.Update(blobs, false)
	if err != nil {
		return err
	}

	// Verify that the entry was updated
	b, err = kv.Get(key)
	if err != nil {
		return err
	}
	if !bytes.Equal(b, value2) {
		return errors.Errorf("got %s, want %s", b, value2)
	}

	// Delete the entry
	err = kv.Del([]string{key})
	if err != nil {
		return err
	}

	// Verify that the entry was deleted
	_, err = kv.Get(key)
	if !errors.Is(err, ErrNotFound) {
		return errors.Errorf("got error %v, want %v",
			err, ErrNotFound)
	}

	// Insert an encrypted entry
	blobs = map[string][]byte{key: value1}
	err = kv.Insert(blobs, true)
	if err != nil {
		return err
	}

	// Verify that the entry was inserted
	b, err = kv.Get(key)
	if err != nil {
		return err
	}
	if !bytes.Equal(b, value1) {
		return errors.Errorf("got %s, want %s", b, value1)
	}

	// Update the encrypted entry
	blobs = map[string][]byte{key: value2}
	err = kv.Update(blobs, true)
	if err != nil {
		return err
	}

	// Verify that the entry was updated
	b, err = kv.Get(key)
	if err != nil {
		return err
	}
	if !bytes.Equal(b, value2) {
		return errors.Errorf("got %s, want %s", b, value2)
	}

	// Update the entry to cleartext
	blobs = map[string][]byte{key: value3}
	err = kv.Update(blobs, false)
	if err != nil {
		return err
	}

	// Verify that the entry was updated
	b, err = kv.Get(key)
	if err != nil {
		return err
	}
	if !bytes.Equal(b, value3) {
		return errors.Errorf("got %s, want %s", b, value3)
	}

	// Del the entry
	err = kv.Del([]string{key})
	if err != nil {
		return err
	}

	// Insert a batch
	blobs = map[string][]byte{
		batchKey1: value1,
		batchKey2: value2,
	}
	err = kv.Insert(blobs, false)
	if err != nil {
		return err
	}

	// Verify that the entries were inserted
	blobs, err = kv.GetBatch([]string{batchKey1, batchKey2})
	if err != nil {
		return err
	}
	b1, ok := blobs[batchKey1]
	if !ok {
		return errors.Errorf("blob not inserted: %v", batchKey1)
	}
	if !bytes.Equal(b1, value1) {
		return errors.Errorf("got %s, want %s", b1, value1)
	}
	b2, ok := blobs[batchKey2]
	if !ok {
		return errors.Errorf("blob not inserted: %v", batchKey2)
	}
	if !bytes.Equal(b2, value2) {
		return errors.Errorf("got %s, want %s", b2, value2)
	}

	// Update the batch
	blobs = map[string][]byte{
		batchKey1: value3,
		batchKey2: value4,
	}
	err = kv.Update(blobs, false)
	if err != nil {
		return err
	}

	// Verify that the entries were updated
	blobs, err = kv.GetBatch([]string{batchKey1, batchKey2})
	if err != nil {
		return err
	}
	b1, ok = blobs[batchKey1]
	if !ok {
		return errors.Errorf("blob not inserted: %v", batchKey1)
	}
	if !bytes.Equal(b1, value3) {
		return errors.Errorf("got %s, want %s", b1, value3)
	}
	b2, ok = blobs[batchKey2]
	if !ok {
		return errors.Errorf("blob not inserted: %v", batchKey2)
	}
	if !bytes.Equal(b2, value4) {
		return errors.Errorf("got %s, want %s", b2, value4)
	}

	// Delete the entries
	err = kv.Del([]string{batchKey1, batchKey2})
	if err != nil {
		return err
	}

	return nil
}

// TODO implement TestTx
func TestTx(kv BlobKV) error {
	// Clear out any previous test data

	// Test rollback

	// Test commit

	// Test cancel function

	// Test concurrency safety

	return nil
}
