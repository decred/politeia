// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package util

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/decred/slog"
	"github.com/marcopeereboom/sbox"
)

// Zero zeros out a byte slice.
func Zero(in []byte) {
	if in == nil {
		return
	}
	inlen := len(in)
	for i := 0; i < inlen; i++ {
		in[i] ^= in[i]
	}
}

// LoadEncryptionKey loads the encryption key at the provided file path. If a
// key does not exists at the file path then a new secretbox key is created
// and saved to the file path before returning the key.
func LoadEncryptionKey(log slog.Logger, keyFile string) (*[32]byte, error) {
	if keyFile == "" {
		return nil, fmt.Errorf("no key file provided")
	}

	// Setup encryption key file
	if !FileExists(keyFile) {
		// Encryption key file does not exist. Create one.
		log.Infof("Generating encryption key")
		key, err := sbox.NewKey()
		if err != nil {
			return nil, err
		}
		err = ioutil.WriteFile(keyFile, key[:], 0400)
		if err != nil {
			return nil, err
		}
		Zero(key[:])
		log.Infof("Encryption key created: %v", keyFile)
	}

	// Load encryption key
	f, err := os.Open(keyFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var key [32]byte
	n, err := f.Read(key[:])
	if n != len(key) {
		return nil, fmt.Errorf("invalid encryption key length")
	}
	if err != nil {
		return nil, err
	}

	log.Infof("Encryption key: %v", keyFile)

	return &key, nil
}
