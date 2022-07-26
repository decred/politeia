// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package auth

import (
	"encoding/hex"
	"fmt"
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

func (u *user) String() string {
	return fmt.Sprintf("%v %v", u.ID, u.Username)
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
	Type      string `json:"type"`
	Contact   string `json:"contact"`
	CreatedAt int64  `json:"createdat"`
	Verified  bool   `json:"verified"`

	// Contact verification fields
	Token           string  `json:"token,omitempty"`
	TokenExpiration int64   `json:"tokenexpiration,omitempty"`
	TokenSent       []int64 `json:"tokensent,omitempty"`
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
