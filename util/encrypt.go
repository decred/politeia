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

// VersionEncryptionKey is the version of the EncryptionKey struct.
const VersionEncryptionKey = 1

// EncryptionKey wraps a 32 byte encryption key.
type EncryptionKey struct {
	Version uint      `json:"version"` // Version of this struct
	Key     *[32]byte `json:"key"`     // Key used for encryption
	Time    int64     `json:"time"`    // UNIX timestamp of key creation
}

// EncodeEncryptionKey encodes an EncryptionKey into a JSON byte slice.
func EncodeEncryptionKey(ek EncryptionKey) ([]byte, error) {
	k, err := json.Marshal(ek)
	if err != nil {
		return nil, err
	}

	return k, nil
}

// DecodeEncryptionKey decodes a JSON byte slice into an EncryptionKey.
func DecodeEncryptionKey(payload []byte) (*EncryptionKey, error) {
	var ek EncryptionKey

	err := json.Unmarshal(payload, &ek)
	if err != nil {
		return nil, err
	}

	return &ek, nil
}

// Encrypt encrypts the provided byte slice with the provided key. It prefixes
// the encrypted blob with an sbox header which encodes the provided version.
// The version is used to identify or version the packed blob.
func Encrypt(version uint32, key *[32]byte, data []byte) ([]byte, error) {
	return sbox.Encrypt(version, key, data)
}

// Decrypt decrypts the packed blob using the provided key. It unpacks the sbox
// header and returns the version and unencrypted data if successful.
func Decrypt(key *[32]byte, packed []byte) ([]byte, uint32, error) {
	return sbox.Decrypt(key, packed)
}

// SaveEncryptionKey saves an EncryptionKey into the provided filepath.
func SaveEncryptionKey(ek EncryptionKey, filepath string) error {
	k, err := EncodeEncryptionKey(ek)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filepath, k, 0600)
}

// LoadEncryptionKey loads an EncryptionKey from the provided filepath.
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

// NewEncryptionKeyFile generates a new secret key for a NACL secret box and
// writes it to the provided filepath.
func NewEncryptionKeyFile(filepath string) error {
	secretKey, err := sbox.NewKey()
	if err != nil {
		return err
	}

	return SaveEncryptionKey(EncryptionKey{
		Version: VersionEncryptionKey,
		Key:     secretKey,
		Time:    time.Now().Unix(),
	}, filepath)
}
