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
)

func (s *mysql) encrypt(ctx context.Context, tx *sql.Tx, data []byte) ([]byte, error) {
	// Create a new nonce value
	_, err := tx.ExecContext(ctx, "INSERT INTO nonce () VALUES ();")
	if err != nil {
		return nil, err
	}

	// Get the nonce value that was just created
	rows, err := tx.QueryContext(ctx, "SELECT LAST_INSERT_ID();")
	if err != nil {
		return nil, fmt.Errorf("query: %v", err)
	}
	defer rows.Close()

	var i int64
	for rows.Next() {
		err = rows.Scan(&i)
		if err != nil {
			return nil, fmt.Errorf("scan: %v", err)
		}

		// There should only ever be one value to scan
		break
	}
	err = rows.Err()
	if err != nil {
		return nil, fmt.Errorf("next: %v", err)
	}
	if i == 0 {
		return nil, fmt.Errorf("invalid 0 nonce")
	}

	log.Tracef("Encrypting with nonce: %v", i)

	// Prepare nonce
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(i))
	n, err := sbox.NewNonceFromBytes(b)
	if err != nil {
		return nil, err
	}
	nonce := n.Current()

	// Encrypt blob
	s.keyMtx.RLock()
	defer s.keyMtx.RUnlock()

	return sbox.EncryptN(0, s.key, nonce, data)
}

func (s *mysql) decrypt(data []byte) ([]byte, uint32, error) {
	s.keyMtx.RLock()
	defer s.keyMtx.RUnlock()

	return sbox.Decrypt(s.key, data)
}

func (s *mysql) zeroKey() {
	s.keyMtx.Lock()
	defer s.keyMtx.Unlock()

	util.Zero(s.key[:])
	s.key = nil
}

// isEncrypted returns whether the provided blob has been prefixed with an sbox
// header, indicating that it is an encrypted blob.
func isEncrypted(b []byte) bool {
	return bytes.HasPrefix(b, []byte("sbox"))
}
