// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mysql

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/decred/politeia/util"
	"github.com/marcopeereboom/sbox"
	"golang.org/x/crypto/argon2"
)

const (
	// argon2idKey is the kv store key for the argon2idParams structure
	// that is saved on initial key derivation.
	argon2idKey = "argon2id"
)

// argon2idParams is saved to the kv store the first time the key is derived.
type argon2idParams struct {
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"`
	Threads uint8  `json:"threads"`
	KeyLen  uint32 `json:"keylen"`
	Salt    []byte `json:"salt"`
}

// argon2idKey derives a 32 byte key from the provided password using the
// Aragon2id key derivation function. A random 16 byte salt is created the
// first time the key is derived. The salt and the other argon2id params are
// saved to the kv store. Subsequent calls to this fuction will pull the
// existing salt and params from the kv store and use them to derive the key.
func (s *mysql) argon2idKey(password string) (*[32]byte, error) {
	log.Infof("Deriving encryption key from password")

	// Check if a key already exists
	blobs, err := s.Get([]string{argon2idKey})
	if err != nil {
		return nil, fmt.Errorf("get: %v", err)
	}
	var salt []byte
	var wasFound bool
	b, ok := blobs[argon2idKey]
	if ok {
		// Key already exists. Use the existing salt.
		log.Infof("Encryption key salt already exists")

		var ap argon2idParams
		err = json.Unmarshal(b, &ap)
		if err != nil {
			return nil, err
		}

		salt = ap.Salt
		wasFound = true
	} else {
		// Key does not exist. Create a random 16 byte salt.
		log.Infof("Encryption key salt not found; creating a new one")

		salt, err = util.Random(16)
		if err != nil {
			return nil, err
		}
	}

	// Derive key
	var (
		pass           = []byte(password)
		time    uint32 = 1
		memory  uint32 = 64 * 1024 // 64 MB
		threads uint8  = 4         // Number of available CPUs
		keyLen  uint32 = 32        // In bytes
	)
	k := argon2.IDKey(pass, salt, time, memory, threads, keyLen)
	var key [32]byte
	copy(key[:], k)
	util.Zero(k)

	// Save params to the kv store if this is the first time the key
	// was derived.
	if !wasFound {
		ap := argon2idParams{
			Time:    time,
			Memory:  memory,
			Threads: threads,
			KeyLen:  keyLen,
			Salt:    salt,
		}
		b, err := json.Marshal(ap)
		if err != nil {
			return nil, err
		}
		kv := map[string][]byte{
			argon2idKey: b,
		}
		err = s.Put(kv, false)
		if err != nil {
			return nil, fmt.Errorf("put: %v", err)
		}

		log.Infof("Encryption key derivation params saved to kv store")
	}

	return &key, nil
}

func (s *mysql) encrypt(ctx context.Context, tx *sql.Tx, key *[32]byte, data []byte) ([]byte, error) {
	// Get nonce value
	nonce, err := s.nonce(ctx, tx)
	if err != nil {
		return nil, err
	}

	log.Tracef("Encrypting with nonce: %v", nonce)

	// Prepare nonce
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(nonce))
	n, err := sbox.NewNonceFromBytes(b)
	if err != nil {
		return nil, err
	}
	nonceb := n.Current()

	// The encryption key is zero'd out on application exit so the read
	// lock must be held during concurrent access to prevent the golang
	// race detector from complaining.
	s.RLock()
	defer s.RUnlock()

	return sbox.EncryptN(0, key, nonceb, data)
}

func (s *mysql) decrypt(key *[32]byte, data []byte) ([]byte, uint32, error) {
	// The encryption key is zero'd out on application exit so the read
	// lock must be held during concurrent access to prevent the golang
	// race detector from complaining.
	s.RLock()
	defer s.RUnlock()

	return sbox.Decrypt(key, data)
}

// isEncrypted returns whether the provided blob has been prefixed with an sbox
// header, indicating that it is an encrypted blob.
func isEncrypted(b []byte) bool {
	return bytes.HasPrefix(b, []byte("sbox"))
}
