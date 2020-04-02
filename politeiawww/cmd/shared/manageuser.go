// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package shared

import (
	"fmt"
	"strconv"

	v1 "github.com/thi4go/politeia/politeiawww/api/www/v1"
)

// ManageUserCmd allows an admin to edit certain properties of the specified
// user.
type ManageUserCmd struct {
	Args struct {
		UserID string `positional-arg-name:"userid"` // User ID
		Action string `positional-arg-name:"action"` // Edit user action
		Reason string `positional-arg-name:"reason"` // Reason for editing user
	} `positional-args:"true" required:"true"`
}

// Execute executes the manage user command.
func (cmd *ManageUserCmd) Execute(args []string) error {
	ManageActions := map[string]v1.UserManageActionT{
		"expirenewuser":       v1.UserManageExpireNewUserVerification,
		"expireupdatekey":     v1.UserManageExpireUpdateKeyVerification,
		"expireresetpassword": v1.UserManageExpireResetPasswordVerification,
		"clearpaywall":        v1.UserManageClearUserPaywall,
		"unlock":              v1.UserManageUnlock,
		"deactivate":          v1.UserManageDeactivate,
		"reactivate":          v1.UserManageReactivate,
	}

	// Parse edit user action.  This can be either the numeric
	// action code or the human readable equivalent.
	var action v1.UserManageActionT
	a, err := strconv.ParseUint(cmd.Args.Action, 10, 32)
	if err == nil {
		// Numeric action code found
		action = v1.UserManageActionT(a)
	} else if a, ok := ManageActions[cmd.Args.Action]; ok {
		// Human readable action code found
		action = a
	} else {
		return fmt.Errorf("Invalid useredit action.  Valid actions are:\n  " +
			"expirenewuser         expires new user verification\n  " +
			"expireupdatekey       expires update user key verification\n  " +
			"expireresetpassword   expires reset password verification\n  " +
			"clearpaywall          clears user registration paywall\n  " +
			"unlock                unlocks user account from failed logins\n  " +
			"deactivate            deactivates user account\n  " +
			"reactivate            reactivates user account")
	}

	// Setup request
	mu := &v1.ManageUser{
		UserID: cmd.Args.UserID,
		Action: action,
		Reason: cmd.Args.Reason,
	}

	// Print request details
	err = PrintJSON(mu)
	if err != nil {
		return err
	}

	// Send request
	mur, err := client.ManageUser(mu)
	if err != nil {
		return err
	}

	// Print response details
	return PrintJSON(mur)
}

// ManageUserHelpMsg is the output of the help command when 'edituser' is
// specified.
const ManageUserHelpMsg = `manageuser "userid" "action" "reason"

Edit the details for the given user id. Requires admin privileges.

Arguments:
1. userid       (string, required)   User id
2. action       (string, required)   Edit user action
3. reason       (string, required)   Reason for editing the user

Valid actions are:
1. expirenewuser           Expires new user verification
2. expireupdatekey         Expires update user key verification
3. expireresetpassword     Expires reset password verification
4. clearpaywall            Clears user registration paywall
5. unlocks                 Unlocks user account from failed logins
6. deactivates             Deactivates user account
7. reactivate              Reactivates user account

Request:
{
  "userid":  (string)    User id
  "action":  (string)    Edit user action
  "reason":  (string)    Reason for action
}

Response:
{}`
