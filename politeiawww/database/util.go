// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package database

import (
	"encoding/hex"
	"os"

	"github.com/decred/politeia/politeiad/api/v1/identity"
)

// IsUserRecord returns true if the given key is a user record,
// and false otherwise. This is helpful when iterating the user records
// because the DB contains some non-user records.
func IsUserRecord(key string) bool {
	return key != DatabaseVersionKey && key != LastPaywallAddressIndexKey
}

// IsIdentityActive returns true if the identity is active, false otherwise
func IsIdentityActive(id Identity) bool {
	return id.Activated != 0 && id.Deactivated == 0
}

// ActiveIdentity returns a the current active key.  If there is no active
// valid key the call returns all 0s and false.
func ActiveIdentity(i []Identity) ([identity.PublicKeySize]byte, bool) {
	for _, v := range i {
		if IsIdentityActive(v) {
			return v.Key, true
		}
	}

	return [identity.PublicKeySize]byte{}, false
}

// ActiveIdentityString returns a string representation of the current active
// key.  If there is no active valid key the call returns all 0s and false.
func ActiveIdentityString(i []Identity) (string, bool) {
	key, ok := ActiveIdentity(i)
	return hex.EncodeToString(key[:]), ok
}

// FileExists reports whether the named file or directory exists.
func FileExists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}

	return true
}
