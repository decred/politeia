// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package database

import (
	"io/ioutil"
	"time"

	"github.com/marcopeereboom/sbox"
)

// Encrypt encrypts a byte slice with the provided version using
// the provided key.
func Encrypt(version uint32, key [32]byte, data []byte) ([]byte, error) {
	return sbox.Encrypt(version, &key, data)
}

// Decrypt decrypts a byte slice using the provided key.
func Decrypt(key [32]byte, data []byte) ([]byte, uint32, error) {
	return sbox.Decrypt(&key, data)
}

// SaveEncryptionKey saves a EncryptionKey into the provided filename.
func SaveEncryptionKey(ek EncryptionKey, filename string) error {
	k, err := EncodeEncryptionKey(ek)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filename, k, 0600)
}

// LoadEncryptionKey loads a EncryptionKey from the provided filename.
func LoadEncryptionKey(filename string) (*EncryptionKey, error) {
	k, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	ek, err := DecodeEncryptionKey(k)
	if err != nil {
		return nil, err
	}

	return ek, nil
}

// NewEncryptionKey creates and save a new encription key in the provided
// directory.
func NewEncryptionKey(filename string) error {
	secretKey, err := sbox.NewKey()
	if err != nil {
		return err
	}

	return SaveEncryptionKey(EncryptionKey{
		Key:  *secretKey,
		Time: time.Now().Unix(),
	}, filename)
}
