// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package auth

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/decred/politeia/app"
	v1 "github.com/decred/politeia/plugins/auth/v1"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

// write.go contains the execution logic for the auth plugin write commands.

func (p *plugin) cmdNewUser(tx *sql.Tx, c app.Cmd) (*app.CmdReply, error) {
	var nu v1.NewUser
	err := json.Unmarshal([]byte(c.Payload), &nu)
	if err != nil {
		return nil, app.UserErr{
			Code: uint32(v1.ErrCodeInvalidPayload),
		}
	}
	var (
		username = formatUsername(nu.Username)
		password = nu.Password
	)

	// Validate the user credentials
	err = validateUsername(p.settings, username)
	if err != nil {
		return nil, err
	}
	err = validatePassword(p.settings, password)
	if err != nil {
		return nil, err
	}
	// TODO validate contact info

	// Verify that the username is unique
	_, err = p.getUserByUsername(tx, username)
	switch {
	case err == nil:
		return nil, app.UserErr{
			Code:    uint32(v1.ErrCodeInvalidUsername),
			Context: fmt.Sprintf("the username %v is already taken", username),
		}
	case errors.Is(err, errNotFound):
		// This username is unique; continue
	default:
		// All other errors
		return nil, err
	}

	// Hash the password
	hashedPass, err := bcryptHash(password)
	if err != nil {
		return nil, err
	}

	// Insert a new user record
	u := newUser()
	err = p.insertUser(tx, *u)
	if err != nil {
		return nil, err
	}

	// reset_password table should be a key-value table where the
	// key is a hash of the contact info and the value should be
	// a list of user IDs. We need a list since the contact info
	// is not required to be unique.

	// Update the reset password table. This table is needed for
	// password resets. Hash the email using bcrypt.

	// Send any external communications needed to verify the
	// contact info.

	_ = hashedPass

	return nil, nil
}

func bcryptHash(s string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(s), bcrypt.DefaultCost)
}

// formatUsername formats a username to lowercase without any leading or
// trailing spaces.
func formatUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

// validateUsername validates that a username meets the username requirements.
func validateUsername(s settings, username string) error {
	switch {
	case formatUsername(username) != username:
		// Sanity check. The caller should have already done this.
		return errors.Errorf("the username has not been formatted")

	case len(username) < int(s.UsernameMinLength):
		return app.UserErr{
			Code: uint32(v1.ErrCodeInvalidUsername),
			Context: fmt.Sprintf("must be at least %v characters long",
				s.UsernameMinLength),
		}

	case len(username) > int(s.UsernameMaxLength):
		return app.UserErr{
			Code: uint32(v1.ErrCodeInvalidUsername),
			Context: fmt.Sprintf("exceedes max length of %v characters",
				s.UsernameMaxLength),
		}

	case !s.usernameRegexp.MatchString(username):
		return app.UserErr{
			Code: uint32(v1.ErrCodeInvalidUsername),
			Context: fmt.Sprintf("contains invalid characters; valid "+
				"characters are %v", s.UsernameChars),
		}
	}
	return nil
}

// validatePassword validates that a password meets all password requirements.
func validatePassword(s settings, password string) error {
	switch {
	case len(password) < int(s.PasswordMinLength):
		return app.UserErr{
			Code: uint32(v1.ErrCodeInvalidPassword),
			Context: fmt.Sprintf("must be at least %v characters",
				s.PasswordMinLength),
		}

	case len(password) > int(s.PasswordMaxLength):
		return app.UserErr{
			Code: uint32(v1.ErrCodeInvalidPassword),
			Context: fmt.Sprintf("exceedes max length of %v characters",
				s.PasswordMaxLength),
		}
	}
	return nil
}

var (
	// emailRegexp contains the regular expression that is used to validate an
	// email address.
	emailRegexp = regexp.MustCompile(`^[a-zA-Z0-9.!#$%&'*+/=?^_` +
		"`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?" +
		"(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
)
