// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlogbe

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/secretbox"
)

func newKey() (*[32]byte, error) {
	var k [32]byte

	_, err := io.ReadFull(rand.Reader, k[:])
	if err != nil {
		return nil, err
	}

	return &k, nil
}

func encryptAndPack(data []byte, key *[32]byte) ([]byte, error) {
	var nonce [24]byte

	// Random nonce
	_, err := io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		return nil, err
	}

	// Encrypt data
	blob := secretbox.Seal(nil, data, &nonce, key)

	// Pack all the things
	packed := make([]byte, len(nonce)+len(blob))
	copy(packed[0:], nonce[:])
	copy(packed[24:], blob)

	return packed, nil
}

func unpackAndDecrypt(key *[32]byte, packed []byte) ([]byte, error) {
	if len(packed) < 24 {
		return nil, errors.New("not an sbox file")
	}

	var nonce [24]byte
	copy(nonce[:], packed[0:24])

	decrypted, ok := secretbox.Open(nil, packed[24:], &nonce, key)
	if !ok {
		return nil, fmt.Errorf("could not decrypt")
	}
	return decrypted, nil
}
