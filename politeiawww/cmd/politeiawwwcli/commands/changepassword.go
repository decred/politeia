// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package commands

import (
	"fmt"

	"github.com/decred/politeia/politeiawww/api/www/v1"
)

// ChangePasswordCmd changes the password for the logged in user.
type ChangePasswordCmd struct {
	Args struct {
		Password    string `positional-arg-name:"currentPassword"` // Current password
		NewPassword string `positional-arg-name:"newPassword"`     // New password
	} `positional-args:"true" required:"true"`
}

// Execute executes the change password command.
func (cmd *ChangePasswordCmd) Execute(args []string) error {
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
		CurrentPassword: digestSHA3(cmd.Args.Password),
		NewPassword:     digestSHA3(cmd.Args.NewPassword),
	}

	// Print request details
	err = printJSON(cp)
	if err != nil {
		return err
	}

	// Send request
	cpr, err := client.ChangePassword(cp)
	if err != nil {
		return err
	}

	// Print response details
	return printJSON(cpr)
}

// changePasswordHelpMsg is the output of the help command when
// 'changepassword' is specified.
const changePasswordHelpMsg = `changepassword "currentPassword" "newPassword" 

Change password for the currently logged in user. 

Arguments:
1. currentPassword   (string, required)   Current password 
2. newPassword       (string, required)   New password  

Request:
{
  "currentpassword":   (string)  Current password 
  "newpassword":       (string)  New password 
}

Response:
{}`
