// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	v1 "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// userVerificationResendCmd re-sends the user verification email for an unverified
// user.
type userVerificationResendCmd struct {
	Args struct {
		Email     string `positional-arg-name:"email"`     // User email
		PublicKey string `positional-arg-name:"publickey"` // User public key
	} `positional-args:"true" required:"true"`
}

// Execute executes the resend verification command.
func (cmd *userVerificationResendCmd) Execute(args []string) error {
	rv := v1.ResendVerification{
		Email:     cmd.Args.Email,
		PublicKey: cmd.Args.PublicKey,
	}

	err := shared.PrintJSON(rv)
	if err != nil {
		return err
	}

	rvr, err := client.ResendVerification(rv)
	if err != nil {
		return err
	}

	return shared.PrintJSON(rvr)
}

// userVerificationResendHelpMsg is the output of the help command when
// 'userverificationresend' is specified.
var userVerificationResendHelpMsg = `userverificationresend 

Resend the user verification email.  The user is only allowed to resend the
verification email one time before they must wait for the verification token to
expire.  The 'publickey' argument is typically the same public key that was
used during user creation, but it does not have to be.  Sending in a different
public key is allowed and will update the user's active identity.

The response field 'verificationtoken' will only contain a value if email has
been disabled on politeiawww.

Arguments:
1. email        (string, required)   User email address
2. publickey    (string, required)   User public key`
