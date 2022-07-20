// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package auth

// user contains the auth plugin user data.
//
// The user is saved to the database by the auth plugin. Certain fields that
// contain sensitive data are encrypted prior to being saved. These fields
// cannot be queried using sql.
//
// Encrypted fields:
// - ContactInfo
type user struct {
	ID          string
	Username    string
	Perms       []string
	ContactInfo []contactInfo
}

type contactType uint32

const (
	contactTypeInvalid contactType = 0
	contactTypeEmail   contactType = 1
)

type contactInfo struct {
	Type     contactType
	Contact  string
	Verified bool
}
