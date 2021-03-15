// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mysql

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"fmt"

	"github.com/decred/politeia/util"
	"github.com/marcopeereboom/sbox"
	"golang.org/x/crypto/argon2"
)

// salt creates a random salt and saves it to the kv store. Subsequent calls to
// this function will return the existing salt.
func (s *mysql) salt(size int) ([]byte, error) {
	saltKey := "salt"

	// Check if a salt already exists in the database
	blobs, err := s.Get([]string{saltKey})
	if err != nil {
		return nil, fmt.Errorf("get: %v", err)
	}
	salt, ok := blobs[saltKey]
	if ok {
		// Salt already exists
		log.Debugf("Salt found in kv store")
		return salt, nil
	}

	// Salt doesn't exist yet. Create one and save it.
	salt, err = util.Random(size)
	if err != nil {
		return nil, err
	}
	kv := map[string][]byte{
		saltKey: salt,
	}
	err = s.Put(kv, false)
	if err != nil {
		return nil, fmt.Errorf("put: %v", err)
	}

	log.Debugf("Salt created and saved to kv store")

	return salt, nil
}

// aragon2idKey derives a 32 byte aragon2id key from the provided password.
// The salt is generated the first time the key is derived and saved to the kv
// store. Subsequent calls to this fuction will use the existing salt.
func (s *mysql) argon2idKey(password string) (*[32]byte, error) {
	var (
		pass           = []byte(password)
		saltLen int    = 16 // In bytes
		time    uint32 = 1
		memory  uint32 = 64 * 1024 // 64 MB
		threads uint8  = 4         // Number of available CPUs
		keyLen  uint32 = 32        // In bytes
	)
	salt, err := s.salt(saltLen)
	if err != nil {
		return nil, fmt.Errorf("salt: %v", err)
	}
	k := argon2.IDKey(pass, salt, time, memory, threads, keyLen)
	var key [32]byte
	copy(key[:], k)
	util.Zero(k)

	return &key, nil
}

// nonce returns a new nonce value. This function guarantees that the returned
// nonce will be unique for every invocation.
//
// This function must be called using a transaction.
func (s *mysql) nonce(ctx context.Context, tx *sql.Tx) (int64, error) {
	_, err := tx.ExecContext(ctx, "INSERT INTO nonce () VALUES ();")
	if err != nil {
		return 0, fmt.Errorf("insert: %v", err)
	}

	// Get the nonce value that was just created
	rows, err := tx.QueryContext(ctx, "SELECT LAST_INSERT_ID();")
	if err != nil {
		return 0, fmt.Errorf("query: %v", err)
	}
	defer rows.Close()

	var nonce int64
	for rows.Next() {
		if nonce > 0 {
			// There should only ever be one row returned. Something is
			// wrong if we've already scanned the nonce and its still
			// scanning rows.
			return 0, fmt.Errorf("multiple rows returned for nonce")
		}
		err = rows.Scan(&nonce)
		if err != nil {
			return 0, fmt.Errorf("scan: %v", err)
		}
	}
	err = rows.Err()
	if err != nil {
		return 0, fmt.Errorf("next: %v", err)
	}
	if nonce == 0 {
		return 0, fmt.Errorf("invalid 0 nonce")
	}

	return nonce, nil
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

	// Encrypt blob
	s.RLock()
	defer s.RUnlock()

	return sbox.EncryptN(0, s.key, nonceb, data)
}

func (s *mysql) decrypt(data []byte) ([]byte, uint32, error) {
	s.RLock()
	defer s.RUnlock()

	return sbox.Decrypt(s.key, data)
}

func (s *mysql) zeroKey() {
	s.Lock()
	defer s.Unlock()

	util.Zero(s.key[:])
	s.key = nil
}

// isEncrypted returns whether the provided blob has been prefixed with an sbox
// header, indicating that it is an encrypted blob.
func isEncrypted(b []byte) bool {
	return bytes.HasPrefix(b, []byte("sbox"))
}
