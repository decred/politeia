// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package util

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
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

// Generates a 64 character hex encoded string has a prefix not equal to any
// of the existingPrefixes
func RandomUniqueToken(existingPrefixes []string, tokenSize int) (string, error) {
	TRIES := 1000

	for i := 0; i < TRIES; i++ {
		token, err := Random(tokenSize)
		if err != nil {
			return "", err
		}
		newToken := hex.EncodeToString(token)
		unique := true
		for _, oldTokenPrefix := range existingPrefixes {
			if newToken[0:len(oldTokenPrefix)] == oldTokenPrefix {
				unique = false
				break
			}
		}

		if unique {
			return newToken, nil
		}
	}

	return "", fmt.Errorf("Failed to find unique token after %v tries", TRIES)
}
