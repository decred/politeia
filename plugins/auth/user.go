// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package auth

import (
	"encoding/hex"
	"time"

	"github.com/decred/politeia/util"
	"github.com/google/uuid"
)

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

func newUser(username string, password []byte, groups []string, c []contactInfo) *user {
	return &user{
		ID:          uuid.New().String(),
		Username:    username,
		Password:    password,
		Groups:      groups,
		ContactInfo: append([]contactInfo{}, c...),
	}
}

const (
	contactTypeEmail = "email"
)

type contactInfo struct {
	Type      string
	Contact   string
	CreatedAt int64
	Verified  bool

	// Contact verification fields
	Token           string
	TokenExpiration int64
	TokenSent       []int64
}

func newContactInfo(ctype, contact string) *contactInfo {
	return &contactInfo{
		Type:            ctype,
		Contact:         contact,
		CreatedAt:       time.Now().Unix(),
		Verified:        false,
		Token:           newVerificationToken(),
		TokenExpiration: newTokenExpiration(),
		TokenSent:       make([]int64, 16),
	}
}

const (
	tokenSize       = 16 // In bytes
	tokenExpiration = 6  // In hours
)

func newVerificationToken() string {
	b, err := util.Random(tokenSize)
	panic(err)
	return hex.EncodeToString(b)
}

func newTokenExpiration() int64 {
	d := time.Duration(tokenExpiration) * time.Hour
	return time.Now().Add(d).Unix()
}
