// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package auth

import (
	"encoding/hex"
	"fmt"
	"time"

	v1 "github.com/decred/politeia/plugins/auth/v1"
	"github.com/decred/politeia/util"
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

// user contains the auth plugin user data.
//
// The user is saved to the database by the auth plugin. It's JSON encoded
// and encrypted prior to being saved to disk. Certain public fields are also
// saved clear text so that they can be queried using SQL.
//
// Data that is saved clear text: ID, CreatedAt, Username, Groups.
type user struct {
	ID           string        `json:"id"`
	CreatedAt    int64         `json:"createdat"`
	Username     string        `json:"username"`
	Password     []byte        `json:"password"`
	Groups       []string      `json:"groups"`
	Logins       []int64       `json:"logins"`
	FailedLogins []int64       `json:"failedlogins"`
	Deactivated  bool          `json:"deactivated"`
	ContactInfo  []contactInfo `json:"contactinfo"`
}

func newUser(username string, password []byte, groups []string, c []contactInfo) *user {
	return &user{
		ID:           uuid.New().String(),
		CreatedAt:    time.Now().Unix(),
		Username:     username,
		Password:     password,
		Groups:       groups,
		Logins:       make([]int64, 0),
		FailedLogins: make([]int64, 0),
		ContactInfo:  append([]contactInfo{}, c...),
	}
}

// String returns a string representation of the user.
func (u *user) String() string {
	return fmt.Sprintf("%v %v", u.ID, u.Username)
}

// AddLogin adds the Unix timestamp for a login. The timestamps from the 10
// most recent logins are saved to the user record.
func (u *user) AddLogin() {
	if len(u.Logins) >= 10 {
		u.Logins = u.Logins[1:]
	}
	u.Logins = append(u.Logins, time.Now().Unix())
}

// AddFailedLogin adds the timestamp of a failed login attempt to the user
// record. Once a failed login attempt is more than 24 hours old, it's
// considered expired and is removed from the failed logins list.
func (u *user) AddFailedLogin(maxFailedLogins uint32) error {
	// Remove existing failed logins that are more than
	// 24 hours old.
	var (
		hrs24    int64 = 60 * 60 * 24 // 24 hours in seconds
		now            = time.Now().Unix()
		filtered       = make([]int64, 0, len(u.FailedLogins))
	)
	for _, ts := range u.FailedLogins {
		if ts < (now - hrs24) {
			// The failed login has expired
			continue
		}
		filtered = append(filtered, ts)
	}

	u.FailedLogins = filtered

	// Add a failed login attempt
	u.FailedLogins = append(u.FailedLogins, time.Now().Unix())

	// Sanity check. This should not be possible. If this error
	// path is being hit then the login logic is not checking
	// for a locked account prior to verifying the password.
	if len(u.FailedLogins) > int(maxFailedLogins) {
		return errors.Errorf("user %v has exceeded the max allowed "+
			"failed logins; this should not be possible", u.Username)
	}

	return nil
}

// IsLocked returns whether the user account has been locked due to failed
// login attempts.
func (u *user) IsLocked(maxFailedLogins uint32) bool {
	return len(u.FailedLogins) >= int(maxFailedLogins)
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
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func newTokenExpiration() int64 {
	d := time.Duration(tokenExpiration) * time.Hour
	return time.Now().Add(d).Unix()
}

func convertUser(u user) v1.User {
	return v1.User{
		ID:          u.ID,
		Username:    u.Username,
		Groups:      u.Groups,
		ContactInfo: convertContactInfo(u.ContactInfo),
	}
}

func convertContactInfo(c []contactInfo) []v1.ContactInfo {
	cv := make([]v1.ContactInfo, 0, len(c))
	for _, v := range c {
		cv = append(cv, v1.ContactInfo{
			Type:     v1.ContactType(v.Type),
			Contact:  v.Contact,
			Verified: v.Verified,
		})
	}
	return cv
}
