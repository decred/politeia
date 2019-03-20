// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package commands

import (
	"fmt"

	"github.com/decred/politeia/politeiawww/api/www/v1"
)

// ResetPasswordCmd resets the password of the specified user.
type ResetPasswordCmd struct {
	Args struct {
		Email       string `positional-arg-name:"email"`       // User email address
		NewPassword string `positional-arg-name:"newpassword"` // New password
	} `positional-args:"true" required:"true"`
}

// Execute executes the reset password command.
func (cmd *ResetPasswordCmd) Execute(args []string) error {
	email := cmd.Args.Email
	newPassword := cmd.Args.NewPassword

	// Get password requirements
	pr, err := client.Policy()
	if err != nil {
		return err
	}

	// Validate new password
	if uint(len(newPassword)) < pr.MinPasswordLength {
		return fmt.Errorf("password must be %v characters long",
			pr.MinPasswordLength)
	}

	// The reset password command is special.  It must be called twice with
	// different parameters.  For the 1st call, it should be called with only
	// an email parameter. On success it will send an email containing a
	// verification token to the email address provided.  If the email server
	// has been disabled, the verification token is sent back in the response
	// body. The 2nd call to reset password should be called with an email,
	// verification token, and new password parameters.
	//
	// politeiawwwcli assumes the email server is disabled.

	// 1st reset password call
	rp := &v1.ResetPassword{
		Email:       email,
		NewPassword: digestSHA3(newPassword),
	}

	err = printJSON(rp)
	if err != nil {
		return err
	}

	rpr, err := client.ResetPassword(rp)
	if err != nil {
		return err
	}

	err = printJSON(rpr)
	if err != nil {
		return err
	}

	// 2nd reset password call
	rp = &v1.ResetPassword{
		Email:             email,
		NewPassword:       digestSHA3(newPassword),
		VerificationToken: rpr.VerificationToken,
	}

	err = printJSON(rp)
	if err != nil {
		return err
	}

	rpr, err = client.ResetPassword(rp)
	if err != nil {
		return err
	}

	return printJSON(rpr)
}

// resetPasswordHelpMsg is the output of the help command when 'resetpassword'
// is specified.
const resetPasswordHelpMsg = `resetpassword "email" "password"

Reset password for currently logged in user. 

Arguments:
1. email      (string, required)   Email address of user
2. password   (string, required)   New password

Result:
{
  "verificationtoken"    (string)  Verification token
}`
