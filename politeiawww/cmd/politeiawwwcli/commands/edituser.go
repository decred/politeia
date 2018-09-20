package commands

import (
	"fmt"
	"strconv"

	"github.com/decred/politeia/politeiawww/api/v1"
)

type EditUserCmd struct {
	Args struct {
		UserID string `positional-arg-name:"userid" description:"User ID"`
		Action string `positional-arg-name:"action" description:"Edit user action"`
		Reason string `positional-arg-name:"reason" description:"Reason for editing the user"`
	} `positional-args:"true" required:"true"`
}

func (cmd *EditUserCmd) Execute(args []string) error {
	EditActions := map[string]v1.UserEditActionT{
		"expirenewuser":       1,
		"expireupdatekey":     2,
		"expireresetpassword": 3,
		"clearpaywall":        4,
		"unlock":              5,
	}

	// Parse edit user action.  This can be either the numeric
	// action code or the human readable equivalent.
	var action v1.UserEditActionT
	a, err := strconv.ParseUint(cmd.Args.Action, 10, 32)
	if err == nil {
		// Numeric action code found
		action = v1.UserEditActionT(a)
	} else if a, ok := EditActions[cmd.Args.Action]; ok {
		// Human readable action code found
		action = a
	} else {
		return fmt.Errorf("Invalid useredit action.  Valid actions are:\n  " +
			"expirenewuser         expires new user verification\n  " +
			"expireupdatekey       expires update user key verification\n  " +
			"expireresetpassword   expires reset password verification\n  " +
			"clearpaywall          clears user registration paywall\n  " +
			"unlock                unlocks user account from failed logins")
	}

	// Setup request
	eu := &v1.EditUser{
		UserID: cmd.Args.UserID,
		Action: action,
		Reason: cmd.Args.Reason,
	}

	// Print request details
	err = Print(eu, cfg.Verbose, cfg.RawJSON)
	if err != nil {
		return err
	}

	// Send request
	eur, err := c.EditUser(eu)
	if err != nil {
		return err
	}

	// Print response details
	return Print(eur, cfg.Verbose, cfg.RawJSON)
}
