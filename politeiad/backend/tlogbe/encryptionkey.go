// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlogbe

import (
	"sync"

	"github.com/decred/politeia/util"
	"github.com/marcopeereboom/sbox"
)

// EncryptionKey provides an API for encrypting and decrypting data using a
// structure that can be passed to plugins and accessed concurrently.
type EncryptionKey struct {
	sync.RWMutex
	key *[32]byte
}

// Encrypt encrypts the provided data. It prefixes the encrypted blob with an
// sbox header which encodes the provided version. The version is user provided
// and can be used as a hint to identify or version the packed blob. Version is
// not inspected or used by Encrypt and Decrypt. The read lock is held to
// prevent the golang race detector from complaining when the encryption key is
// zeroed out on application exit.
func (e *EncryptionKey) Encrypt(version uint32, blob []byte) ([]byte, error) {
	e.RLock()
	defer e.RUnlock()

	return sbox.Encrypt(version, e.key, blob)
}

// decrypt decrypts the provided packed blob. The decrypted blob and the
// version that was used to encrypt the blob are returned. The read lock is
// held to prevent the golang race detector from complaining when the
// encryption key is zeroed out on application exit.
func (e *EncryptionKey) Decrypt(blob []byte) ([]byte, uint32, error) {
	e.RLock()
	defer e.RUnlock()

	return sbox.Decrypt(e.key, blob)
}

// Zero zeroes out the encryption key.
func (e *EncryptionKey) Zero() {
	e.Lock()
	defer e.Unlock()

	util.Zero(e.key[:])
	e.key = nil
}

func encryptionKeyNew(key *[32]byte) *EncryptionKey {
	return &EncryptionKey{
		key: key,
	}
}
