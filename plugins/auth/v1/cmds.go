// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

const (
	ID             = "auth"
	Version uint32 = 1
)

const (
	CmdPolicy  = "policy"
	CmdNewUser = "newuser"
)

const (
	PermPublic = "public"
	PermUser   = "user"
	PermAdmin  = "admin"
)

type Settings struct {
	SessionMaxAge     int64    `json:"sessionmaxage"`
	UsernameChars     []string `json:"usernamechars"`
	UsernameMinLength uint32   `json:"usernameminlength"`
	UsernameMaxLength uint32   `json:"usernamemaxlength"`
	PasswordMinLength uint32   `json:"passwordminlength"`
	PasswordMaxLength uint32   `json:"passwordmaxlength"`
}

// User contains the auth plugin user data.
type User struct {
	ID          string        `json:"id"`
	Username    string        `json:"username"`
	ContactInfo []ContactInfo `json:"contactinfo,omitempty"`
	Perms       []string      `json:"perms"`
}

type ContactType uint32

const (
	ContactTypeInvalid ContactType = 0
	ContactTypeEmail   ContactType = 1
)

type ContactInfo struct {
	Type     ContactType `json:"type"`
	Contact  string      `json:"contact"`
	Verified bool        `json:"verified"`
}

type Policy struct{}

type PolicyReply struct {
	Settings Settings `json:"settings"`
}

// NewUser is the request payload for the CmdNewUser.
//
// The username must adhere to the username policy requirements and must be
// unique. The username is not case sensitive.
type NewUser struct {
	Username    string           `json:"username"`
	Password    string           `json:"password"`
	ContactInfo []NewContactInfo `json:"contactinfo"`
}

// NewContactInfo is used to setup a new type of contact info for a user.
type NewContactInfo struct {
	Type    ContactType `json:"type"`
	Contact string      `json:"contact"`
}

// NewUserReply is the reply payload for the CmdNewUser.
type NewUserReply struct {
	User User `json:"user"`
}
