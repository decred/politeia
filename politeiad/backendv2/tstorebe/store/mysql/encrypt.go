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
	// encryptionKeyParamsKey is the kv store key for the encryption
	// key params that are saved on initial key derivation.
	encryptionKeyParamsKey = "store-mysql-encryptionkeyparams"
)

// encryptionKeyParams is saved to the kv store on initial derivation of the
// encryption key. It contains the params that were used to derive the key and
// a SHA256 digest of the key. Subsequent derivations will use the existing
// params to derive the key and will use the digest to verify that the
// encryption key has not changed.
type encryptionKeyParams struct {
	Digest []byte            `json:"digest"` // SHA256 digest
	Params util.Argon2Params `json:"params"`
}

// argon2idKey derives an encryption key using the provided parameters and the
// Argon2id key derivation function. The derived key is set to be the
// encryption key on the mysql context.
func (s *mysql) argon2idKey(password string, ap util.Argon2Params) {
	k := argon2.IDKey([]byte(password), ap.Salt, ap.Time, ap.Memory,
		ap.Threads, ap.KeyLen)
	copy(s.key[:], k)
	util.Zero(k)
}

// deriveEncryption derives a 32 byte key from the provided password using the
// Aragon2id key derivation function. A random 16 byte salt is created the
// first time the key is derived. The salt and the other argon2id params are
// saved to the kv store. Subsequent calls to this fuction will pull the
// existing salt and params from the kv store and use them to derive the key,
// then will use the saved encryption key digest to verify that the key has
// not changed.
func (s *mysql) deriveEncryptionKey(password string) error {
	log.Infof("Deriving encryption key")

	// Check if the key params already exist in the kv store. Existing
	// params means that the key has been derived previously. These
	// params will be used if found. If no params exist then new ones
	// will be created and saved to the kv store for future use.
	blobs, err := s.Get([]string{encryptionKeyParamsKey})
	if err != nil {
		return fmt.Errorf("get: %v", err)
	}
	var (
		save bool
		ekp  encryptionKeyParams
	)
	b, ok := blobs[encryptionKeyParamsKey]
	if ok {
		log.Debugf("Encryption key params found in kv store")
		err = json.Unmarshal(b, &ekp)
		if err != nil {
			return err
		}
	} else {
		log.Infof("Encryption key params not found; creating new ones")
		ekp = encryptionKeyParams{
			Params: util.NewArgon2Params(),
		}
		save = true
	}

	// Derive key
	s.argon2idKey(password, ekp.Params)

	// Check if the params need to be saved
	keyDigest := util.Digest(s.key[:])
	if save {
		// This was the first time the key was derived. Save the params
		// to the kv store.
		ekp.Digest = keyDigest
		b, err := json.Marshal(ekp)
		if err != nil {
			return err
		}
		kv := map[string][]byte{
			encryptionKeyParamsKey: b,
		}
		err = s.Put(kv, false)
		if err != nil {
			return fmt.Errorf("put: %v", err)
		}

		log.Infof("Encryption key params saved to kv store")
	} else {
		// This was not the first time the key was derived. Verify that
		// the key has not changed.
		if !bytes.Equal(ekp.Digest, keyDigest) {
			return fmt.Errorf("attempting to use different encryption key")
		}
	}

	return nil
}

var emptyNonce = [24]byte{}

func (s *mysql) getDbNonce(ctx context.Context, tx *sql.Tx) ([24]byte, error) {
	// Get nonce value
	nonce, err := s.nonce(ctx, tx)
	if err != nil {
		return emptyNonce, err
	}

	log.Tracef("Encrypting with nonce: %v", nonce)

	// Prepare nonce
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(nonce))
	n, err := sbox.NewNonceFromBytes(b)
	if err != nil {
		return emptyNonce, err
	}
	return n.Current(), nil
}

func (s *mysql) getTestNonce(ctx context.Context, tx *sql.Tx) ([24]byte, error) {
	nonce, err := util.Random(8)
	if err != nil {
		return emptyNonce, err
	}
	n, err := sbox.NewNonceFromBytes(nonce)
	if err != nil {
		return emptyNonce, err
	}
	return n.Current(), nil
}

func (s *mysql) encrypt(ctx context.Context, tx *sql.Tx, data []byte) ([]byte, error) {
	nonce, err := s.getNonce(ctx, tx)
	if err != nil {
		return nil, err
	}
	return sbox.EncryptN(0, &s.key, nonce, data)
}

func (s *mysql) decrypt(data []byte) ([]byte, uint32, error) {
	return sbox.Decrypt(&s.key, data)
}

// isEncrypted returns whether the provided blob has been prefixed with an sbox
// header, indicating that it is an encrypted blob.
func isEncrypted(b []byte) bool {
	return bytes.HasPrefix(b, []byte("sbox"))
}
