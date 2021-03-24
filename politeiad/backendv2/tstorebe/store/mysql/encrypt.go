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

func newArgon2Params() argon2idParams {
	salt, err := util.Random(16)
	if err != nil {
		panic(err)
	}
	return argon2idParams{
		Time:    1,
		Memory:  64 * 1024, // In KiB
		Threads: 4,
		KeyLen:  32,
		Salt:    salt,
	}
}

// argon2idKey derives a 32 byte key from the provided password using the
// Aragon2id key derivation function. A random 16 byte salt is created the
// first time the key is derived. The salt and the other argon2id params are
// saved to the kv store. Subsequent calls to this fuction will pull the
// existing salt and params from the kv store and use them to derive the key.
func (s *mysql) argon2idKey(password string) error {
	log.Infof("Deriving encryption key from password")

	// Check if a key already exists
	blobs, err := s.Get([]string{argon2idKey})
	if err != nil {
		return fmt.Errorf("get: %v", err)
	}
	var save bool
	var ap argon2idParams
	b, ok := blobs[argon2idKey]
	if ok {
		log.Debugf("Encryption key salt already exists")
		err = json.Unmarshal(b, &ap)
		if err != nil {
			return err
		}
	} else {
		log.Infof("Encryption key not found; creating a new one")
		ap = newArgon2Params()
		save = true
	}

	// Derive key
	k := argon2.IDKey([]byte(password), ap.Salt, ap.Time, ap.Memory,
		ap.Threads, ap.KeyLen)
	copy(s.key[:], k)
	util.Zero(k)

	// Save params to the kv store if this is the first time the key
	// was derived.
	if save {
		b, err := json.Marshal(ap)
		if err != nil {
			return err
		}
		kv := map[string][]byte{
			argon2idKey: b,
		}
		err = s.Put(kv, false)
		if err != nil {
			return fmt.Errorf("put: %v", err)
		}

		log.Infof("Encryption key derivation params saved to kv store")
	}

	return nil
}

func (s *mysql) encrypt(ctx context.Context, tx *sql.Tx, data []byte) ([]byte, error) {
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

	return sbox.EncryptN(0, &s.key, nonceb, data)
}

func (s *mysql) decrypt(data []byte) ([]byte, uint32, error) {
	return sbox.Decrypt(&s.key, data)
}

// isEncrypted returns whether the provided blob has been prefixed with an sbox
// header, indicating that it is an encrypted blob.
func isEncrypted(b []byte) bool {
	return bytes.HasPrefix(b, []byte("sbox"))
}
