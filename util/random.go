// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package util

import (
	"crypto/rand"
	"encoding/binary"
	"io"
)

// Random returns a variable number of bytes of random data.
func Random(n int) ([]byte, error) {
	k := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, k)
	if err != nil {
		return nil, err
	}

	return k, nil
}

// RandomInt returns a random unsigned integer.
func RandomUint64() (uint64, error) {
	k, err := Random(8)
	if err != nil {
		return 0xffffffffffffffff, err
	}
	return binary.LittleEndian.Uint64(k), nil
}
