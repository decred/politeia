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
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

// write.go contains the execution logic for the auth plugin write commands.

func (p *plugin) cmdNewUser(tx *sql.Tx, c app.Cmd) (*app.CmdReply, error) {
	var nu v1.NewUser
	err := json.Unmarshal([]byte(c.Payload), &nu)
	if err != nil {
		return nil, userErr{
			Code: v1.ErrCodeInvalidPayload,
		}
	}
	var (
		username    = formatUsername(nu.Username)
		password    = nu.Password
		contactInfo = convertNewContactInfo(nu.ContactInfo)
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
	for _, v := range contactInfo {
		err = validateContactInfo(p.settings, v)
		if err != nil {
			return nil, err
		}
	}

	// Verify that the username is unique
	_, err = p.getUserByUsername(tx, username)
	switch {
	case err == nil:
		return nil, userErr{
			Code:    v1.ErrCodeInvalidUsername,
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
	var (
		userID = uuid.New().String()
		groups = []string{
			v1.PermPublic,
		}
	)
	u := newUser(userID, username, hashedPass, groups, contactInfo)
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

	// Send external communications needed to verify the contact info.

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
		return userErr{
			Code: v1.ErrCodeInvalidUsername,
			Context: fmt.Sprintf("username must be at least %v characters long",
				s.UsernameMinLength),
		}

	case len(username) > int(s.UsernameMaxLength):
		return userErr{
			Code: v1.ErrCodeInvalidUsername,
			Context: fmt.Sprintf("username exceedes the max length of %v characters",
				s.UsernameMaxLength),
		}

	case !s.usernameRegexp.MatchString(username):
		return userErr{
			Code: v1.ErrCodeInvalidUsername,
			Context: fmt.Sprintf("username contains invalid characters; "+
				"valid characters are %v", s.UsernameChars),
		}
	}
	return nil
}

// validatePassword validates that a password meets all password requirements.
func validatePassword(s settings, password string) error {
	switch {
	case len(password) < int(s.PasswordMinLength):
		return userErr{
			Code: v1.ErrCodeInvalidPassword,
			Context: fmt.Sprintf("password must be at least %v characters",
				s.PasswordMinLength),
		}

	case len(password) > int(s.PasswordMaxLength):
		return userErr{
			Code: v1.ErrCodeInvalidPassword,
			Context: fmt.Sprintf("password exceedes the max length of %v characters",
				s.PasswordMaxLength),
		}
	}
	return nil
}

// validateContactInfo validates that contact info data meets the plugin
// requirements.
func validateContactInfo(s settings, c contactInfo) error {
	_, ok := s.ContactTypes[c.Type]
	if !ok {
		return userErr{
			Code:    v1.ErrCodeInvalidContactInfo,
			Context: fmt.Sprintf("%v contact type is invalid", c.Type),
		}
	}

	switch c.Type {
	case contactTypeEmail:
		return validateEmail(c.Contact)
	default:
		// Should not be possible
		return errors.Errorf("invalid contact type")
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

// validateEmail validates that an email address is sane.
func validateEmail(email string) error {
	if !emailRegexp.MatchString(email) {
		return userErr{
			Code:    v1.ErrCodeInvalidContactInfo,
			Context: "email address is invalid",
		}
	}
	return nil
}

func convertNewContactInfo(n []v1.NewContactInfo) []contactInfo {
	c := make([]contactInfo, 0, len(n))
	for _, v := range n {
		c = append(c, contactInfo{
			Type:     string(v.Type),
			Contact:  v.Contact,
			Verified: false,
		})
	}
	return c
}
