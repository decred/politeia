// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package shared

import (
	"fmt"

	www "github.com/decred/politeia/politeiawww/api/www/v1"
)

// UserPasswordResetCmd resets the password of the specified user.
type UserPasswordResetCmd struct {
	Args struct {
		Username    string `positional-arg-name:"username"`    // Username
		Email       string `positional-arg-name:"email"`       // User email address
		NewPassword string `positional-arg-name:"newpassword"` // New password
	} `positional-args:"true" required:"true"`
}

// Execute executes the reset password command.
func (cmd *UserPasswordResetCmd) Execute(args []string) error {
	username := cmd.Args.Username
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

	// Reset password
	rp := &www.ResetPassword{
		Username: username,
		Email:    email,
	}

	err = PrintJSON(rp)
	if err != nil {
		return err
	}

	rpr, err := client.ResetPassword(rp)
	if err != nil {
		return err
	}

	err = PrintJSON(rpr)
	if err != nil {
		return err
	}

	// The verification token will only be present in the
	// reply if the politeiawww email server has been
	// disabled. If the verification token is not in the
	// reply then there is nothing more that we can do.
	if rpr.VerificationToken == "" {
		return nil
	}

	// Verify  reset password
	vrp := www.VerifyResetPassword{
		Username:          username,
		VerificationToken: rpr.VerificationToken,
		NewPassword:       DigestSHA3(newPassword),
	}

	err = PrintJSON(vrp)
	if err != nil {
		return err
	}

	vrpr, err := client.VerifyResetPassword(vrp)
	if err != nil {
		return err
	}

	return PrintJSON(vrpr)
}

// UserPasswordResetHelpMsg is the output of the help command when 'userpasswordreset'
// is specified.
const UserPasswordResetHelpMsg = `userpasswordreset "username" "email" "newpassword"

Reset the password for a user that is not logged in.

Arguments:
1. username   (string, required)   Username of user
2. email      (string, required)   Email address of user
3. password   (string, required)   New password`
