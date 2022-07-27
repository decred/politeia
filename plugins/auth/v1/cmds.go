// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

const (
	PluginID        = "auth"
	Version  uint32 = 1

	CmdNewUser = "newuser"
	CmdLogin   = "login"
	CmdLogout  = "logout"
	CmdMe      = "me"
)

// The following list contains the default user groups.
const (
	PublicUser   = "public"
	StandardUser = "standard"
	AdminUser    = "admin"
)

// User contains the auth plugin user data.
type User struct {
	ID          string        `json:"id"`
	Username    string        `json:"username"`
	Groups      []string      `json:"groups"`
	ContactInfo []ContactInfo `json:"contactinfo,omitempty"`
}

type ContactType string

const (
	ContactTypeEmail ContactType = "email"
)

type ContactInfo struct {
	Type     ContactType `json:"type"`
	Contact  string      `json:"contact"`
	Verified bool        `json:"verified"`
}

type Policy struct{}

type PolicyReply struct {
	SessionMaxAge     int64    `json:"sessionmaxage"`
	UsernameChars     []string `json:"usernamechars"` // Supported characters
	UsernameMinLength uint32   `json:"usernameminlength"`
	UsernameMaxLength uint32   `json:"usernamemaxlength"`
	PasswordMinLength uint32   `json:"passwordminlength"`
	PasswordMaxLength uint32   `json:"passwordmaxlength"`
}

// NewUser is the request payload for the CmdNewUser.
//
// See the PolicyReply for username and password requirements. The username is
// not case sensitive and must be unique.
type NewUser struct {
	Username    string          `json:"username"`
	Password    string          `json:"password"`
	ContactInfo *NewContactInfo `json:"contactinfo,omitempty"`
}

// NewContactInfo is used to setup a new type of contact info for a user.
type NewContactInfo struct {
	Type    ContactType `json:"type"`
	Contact string      `json:"contact"`
}

// NewUserReply is the reply payload for the CmdNewUser.
type NewUserReply struct{}

type Login struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginReply struct {
	User User `json:"user"`
}

type Logout struct{}

type LogoutReply struct{}

type Me struct{}

type MeReply struct {
	User *User `json:"user,omitempty"`
}
