// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package localdb

import (
	"bytes"

	"github.com/decred/politeia/util"
	"github.com/marcopeereboom/sbox"
)

func (l *localdb) encrypt(data []byte) ([]byte, error) {
	l.RLock()
	defer l.RUnlock()

	return sbox.Encrypt(0, l.key, data)
}

func (l *localdb) decrypt(data []byte) ([]byte, uint32, error) {
	l.RLock()
	defer l.RUnlock()

	return sbox.Decrypt(l.key, data)
}

func (l *localdb) zeroKey() {
	l.Lock()
	defer l.Unlock()

	util.Zero(l.key[:])
	l.key = nil
}

// isEncrypted returns whether the provided blob has been prefixed with an sbox
// header, indicating that it is an encrypted blob.
func isEncrypted(b []byte) bool {
	return bytes.HasPrefix(b, []byte("sbox"))
}
