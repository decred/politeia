// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package shared

import (
	"fmt"

	v1 "github.com/decred/politeia/politeiawww/api/www/v1"
)

// UserPasswordChangeCmd changes the password for the logged in user.
type UserPasswordChangeCmd struct {
	Args struct {
		Password    string `positional-arg-name:"currentPassword"` // Current password
		NewPassword string `positional-arg-name:"newPassword"`     // New password
	} `positional-args:"true" required:"true"`
}

// Execute executes the change password command.
func (cmd *UserPasswordChangeCmd) Execute(args []string) error {
	// Get password requirements
	pr, err := client.Policy()
	if err != nil {
		return err
	}

	// Validate new password
	if uint(len(cmd.Args.NewPassword)) < pr.MinPasswordLength {
		return fmt.Errorf("password must be %v characters long",
			pr.MinPasswordLength)
	}

	// Setup change password request
	cp := &v1.ChangePassword{
		CurrentPassword: DigestSHA3(cmd.Args.Password),
		NewPassword:     DigestSHA3(cmd.Args.NewPassword),
	}

	// Print request details
	err = PrintJSON(cp)
	if err != nil {
		return err
	}

	// Send request
	cpr, err := client.ChangePassword(cp)
	if err != nil {
		return err
	}

	// Print response details
	return PrintJSON(cpr)
}

// UserPasswordChangeHelpMsg is the output of the help command when
// 'userpasswordchange' is specified.
const UserPasswordChangeHelpMsg = `userpasswordchange "currentPassword" "newPassword" 

Change password for the currently logged in user. 

Arguments:
1. currentPassword   (string, required)   Current password 
2. newPassword       (string, required)   New password`
