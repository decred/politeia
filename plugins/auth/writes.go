// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package auth

import (
	"encoding/json"
	"regexp"

	"github.com/decred/politeia/app"
	v1 "github.com/decred/politeia/plugins/auth/v1"
	"golang.org/x/crypto/bcrypt"
)

// write.go contains the execution logic for all auth plugin write commands.

var (
	// emailRegexp contains the regular expression that is used to validate an
	// email address.
	emailRegexp = regexp.MustCompile(`^[a-zA-Z0-9.!#$%&'*+/=?^_` +
		"`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?" +
		"(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
)

func (p *plugin) cmdNewUser(c app.Cmd) (*app.CmdReply, error) {
	var nu v1.NewUser
	err := json.Unmarshal([]byte(c.Payload), &nu)
	if err != nil {
		return nil, app.UserErr{
			Code: uint32(v1.ErrCodeInvalidPayload),
		}
	}
	var (
		username = nu.Username
		password = nu.Password
	)

	// Verify the user credentials

	// Verify that the username is unique

	// Verify that the email is unique
	/*
		If email already exists:
		- Return a success so that an attacker cannot ascertain what email
		  addresses have politeia accounts.
		- Send an email notification that let's the user know that they've already
			registered an account.
	*/

	// Hash the password
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(password),
		bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	// Save the user

	// Update the email-userID lookup table

	// Send a verification email

	// Return the user

	_ = username
	_ = hashedPass

	return nil, nil
}
