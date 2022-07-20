// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package auth

import (
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

func (p *plugin) cmdNewUser(c app.Cmd) (*app.CmdReply, error) {
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
	err = p.validateUsername(username)
	if err != nil {
		return nil, err
	}
	err = p.validatePassword(password)
	if err != nil {
		return nil, err
	}

	// Verify that the username is unique

	// Hash the password
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(password),
		bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	// Save the user

	// reset_password table should be a key-value table where the
	// key is a hash of the contact info and the value should be
	// a list of user IDs. We need a list since the contact info
	// is not required to be unique.

	// Update the reset password table. This table is needed for
	// password resets. Hash the email using bcrypt.

	// Send a verification email

	_ = username
	_ = hashedPass

	return nil, nil
}

// formatUsername formats a username to lowercase without any leading or
// trailing spaces.
func formatUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

// validateUsername validates that a username meets the username requirements.
func (p *plugin) validateUsername(username string) error {
	switch {
	case formatUsername(username) != username:
		// Sanity check. The caller should have already done this.
		return errors.Errorf("the username has not been formatted")

	case len(username) < int(p.settings.UsernameMinLength):
		return app.UserErr{
			Code: uint32(v1.ErrCodeInvalidUsername),
			Context: fmt.Sprintf("must be at least %v characters long",
				p.settings.UsernameMinLength),
		}

	case len(username) > int(p.settings.UsernameMaxLength):
		return app.UserErr{
			Code: uint32(v1.ErrCodeInvalidUsername),
			Context: fmt.Sprintf("exceedes max length of %v characters",
				p.settings.UsernameMaxLength),
		}

	case !p.usernameRegexp.MatchString(username):
		return app.UserErr{
			Code: uint32(v1.ErrCodeInvalidUsername),
			Context: fmt.Sprintf("contains invalid characters; valid "+
				"characters are %v", p.settings.UsernameChars),
		}
	}
	return nil
}

// validatePassword validates that a password meets all password requirements.
func (p *plugin) validatePassword(password string) error {
	switch {
	case len(password) < int(p.settings.PasswordMinLength):
		return app.UserErr{
			Code: uint32(v1.ErrCodeInvalidPassword),
			Context: fmt.Sprintf("must be at least %v characters",
				p.settings.PasswordMinLength),
		}

	case len(password) > int(p.settings.PasswordMaxLength):
		return app.UserErr{
			Code: uint32(v1.ErrCodeInvalidPassword),
			Context: fmt.Sprintf("exceedes max length of %v characters",
				p.settings.PasswordMaxLength),
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
