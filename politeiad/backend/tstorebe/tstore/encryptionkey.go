// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tstore

import (
	"sync"

	"github.com/decred/politeia/util"
	"github.com/marcopeereboom/sbox"
)

// encryptionKey provides an API for encrypting and decrypting data. The
// encryption key is zero'd out on application exit so the lock must be held
// anytime the key is accessed in order to prevent the golang race detector
// from complaining.
type encryptionKey struct {
	sync.RWMutex
	key *[32]byte
}

// encrypt encrypts the provided data. It prefixes the encrypted blob with an
// sbox header which encodes the provided version. The version is user provided
// and can be used as a hint to identify or version the packed blob. Version is
// not inspected or used by Encrypt and Decrypt.
func (e *encryptionKey) encrypt(version uint32, blob []byte) ([]byte, error) {
	e.RLock()
	defer e.RUnlock()

	return sbox.Encrypt(version, e.key, blob)
}

// decrypt decrypts the provided packed blob. The decrypted blob and the
// version that was used to encrypt the blob are returned.
func (e *encryptionKey) decrypt(blob []byte) ([]byte, uint32, error) {
	e.RLock()
	defer e.RUnlock()

	return sbox.Decrypt(e.key, blob)
}

// Zero zeroes out the encryption key.
func (e *encryptionKey) zero() {
	e.Lock()
	defer e.Unlock()

	util.Zero(e.key[:])
	e.key = nil
}

func newEncryptionKey(key *[32]byte) *encryptionKey {
	return &encryptionKey{
		key: key,
	}
}
