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

	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
	"github.com/decred/politeia/util"
	"github.com/marcopeereboom/sbox"
	"github.com/pkg/errors"
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
	b, err := s.Get(encryptionKeyParamsKey)
	if err != nil {
		if err == store.ErrNotFound {
			return s.createKeyParams(password)
		}
		return err
	}

	log.Debugf("Encryption key params found in kv store")

	var ekp encryptionKeyParams
	err = json.Unmarshal(b, &ekp)
	if err != nil {
		return err
	}

	// Derive key
	s.argon2idKey(password, ekp.Params)

	// Verify that the key as not changed
	keyDigest := util.Digest(s.key[:])
	if !bytes.Equal(ekp.Digest, keyDigest) {
		return errors.Errorf("attempting to use different encryption key")
	}

	return nil
}

// createKeyParams creates new Aragon2id derivation parameters and saved them
// to the database. This function should be called if encryption key params do
// not yet exist in the database. The encryption key is derived and stored
// in-memory as part of the mysql context during this process as well.
func (s *mysql) createKeyParams(password string) error {
	log.Infof("Encryption key params not found; creating new ones")

	// Create new params
	ekp := encryptionKeyParams{
		Params: util.NewArgon2Params(),
	}

	// Derive key
	s.argon2idKey(password, ekp.Params)

	// Add key digest to the params
	ekp.Digest = util.Digest(s.key[:])

	// Save the key
	b, err := json.Marshal(ekp)
	if err != nil {
		return err
	}
	kv := map[string][]byte{
		encryptionKeyParamsKey: b,
	}
	err = s.Insert(kv, false)
	if err != nil {
		return err
	}

	log.Infof("Encryption key params saved to kv store")

	return nil
}

var emptyNonce = [24]byte{}

// getDBNonce retrieves a new nonce from the database. The nonce is guaranteed
// to be unique for every invocation of this function.
func (s *mysql) getDBNonce(ctx context.Context, tx *sql.Tx) ([24]byte, error) {
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

// getTestNonce returns a new nonce that can be used for testing. This nonce
// is not guaranteed to be unique.
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

// getNonce returns a unique nonce.
func (s *mysql) getNonce(ctx context.Context, tx *sql.Tx) ([24]byte, error) {
	if s.testing {
		return s.getTestNonce(ctx, tx)
	}
	return s.getDBNonce(ctx, tx)
}

// encrypt encrypts the provided data using a unqiue nonce.
func (s *mysql) encrypt(ctx context.Context, tx *sql.Tx, data []byte) ([]byte, error) {
	nonce, err := s.getNonce(ctx, tx)
	if err != nil {
		return nil, err
	}
	return sbox.EncryptN(0, &s.key, nonce, data)
}

// decrypt decrypts the provided data.
func (s *mysql) decrypt(data []byte) ([]byte, uint32, error) {
	return sbox.Decrypt(&s.key, data)
}

// isEncrypted returns whether the provided blob has been prefixed with an sbox
// header, indicating that it is an encrypted blob.
func isEncrypted(b []byte) bool {
	return bytes.HasPrefix(b, []byte("sbox"))
}
