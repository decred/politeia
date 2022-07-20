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
	Password    []byte
	Groups      []string
	ContactInfo []contactInfo
}

const (
	contactTypeEmail = "email"
)

// supportedContactTypes contains the contact types that are supported by
// this plugin.
var supportedContactTypes = map[string]struct{}{
	contactTypeEmail: {},
}

type contactInfo struct {
	Type     string
	Contact  string
	Verified bool
}

func newUser(id, username string, password []byte, groups []string, c []contactInfo) *user {
	return &user{
		ID:          id,
		Username:    username,
		Password:    password,
		Groups:      groups,
		ContactInfo: append([]contactInfo{}, c...),
	}
}
