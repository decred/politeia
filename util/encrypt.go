// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package util

import (
	"encoding/json"
	"io/ioutil"
	"time"

	"github.com/marcopeereboom/sbox"
)

// EncryptionKey wraps a 32 byte encryption key and the time when it
// was created.
type EncryptionKey struct {
	Key  [32]byte // Key used for encryption
	Time int64    // Time key was created
}

// EncodeEncryptionKey encodes EncryptionKey into a JSON byte slice.
func EncodeEncryptionKey(ek EncryptionKey) ([]byte, error) {
	k, err := json.Marshal(ek)
	if err != nil {
		return nil, err
	}

	return k, nil
}

// DecodeEncryptionKey decodes a JSON byte slice into EncryptionKey.
func DecodeEncryptionKey(payload []byte) (*EncryptionKey, error) {
	var ek EncryptionKey

	err := json.Unmarshal(payload, &ek)
	if err != nil {
		return nil, err
	}

	return &ek, nil
}

// Encrypt encrypts a byte slice with the provided version using the
// provided key.
func Encrypt(version uint32, key [32]byte, data []byte) ([]byte, error) {
	return sbox.Encrypt(version, &key, data)
}

// Decrypt decrypts a byte slice using the provided key.
func Decrypt(key [32]byte, data []byte) ([]byte, uint32, error) {
	return sbox.Decrypt(&key, data)
}

// SaveEncryptionKey saves a EncryptionKey into the provided filepath.
func SaveEncryptionKey(ek EncryptionKey, filepath string) error {
	k, err := EncodeEncryptionKey(ek)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filepath, k, 0600)
}

// LoadEncryptionKey loads a EncryptionKey from the provided filepath.
func LoadEncryptionKey(filepath string) (*EncryptionKey, error) {
	k, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	ek, err := DecodeEncryptionKey(k)
	if err != nil {
		return nil, err
	}

	return ek, nil
}

// NewEncryptionKey creates and save a new encryption key at the provided
// filepath.
func NewEncryptionKey(filepath string) error {
	secretKey, err := sbox.NewKey()
	if err != nil {
		return err
	}

	return SaveEncryptionKey(EncryptionKey{
		Key:  *secretKey,
		Time: time.Now().Unix(),
	}, filepath)
}
