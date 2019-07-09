// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package commands

import (
	"fmt"

	"github.com/decred/politeia/politeiawww/api/www/v1"
)

// LoginCmd logs into Politeia using the specified credentials.
type LoginCmd struct {
	Args struct {
		Username string `positional-arg-name:"username"`
		Password string `positional-arg-name:"password"`
	} `positional-args:"true" required:"true"`
}

// Execute executes the login command.
func (cmd *LoginCmd) Execute(args []string) error {
	// Setup login request
	l := &v1.Login{
		Username: cmd.Args.Username,
		Password: digestSHA3(cmd.Args.Password),
	}

	// Print request details
	err := printJSON(l)
	if err != nil {
		return err
	}

	// Send request
	lr, err := client.Login(l)
	if err != nil {
		return err
	}

	// Update the logged in username that we store on disk
	err = cfg.SaveLoggedInUsername(lr.Username)
	if err != nil {
		return fmt.Errorf("SaveLoggedInUsername: %v", err)
	}

	// Print response details
	return printJSON(lr)
}

// loginHelpMsg is the output for the help command when 'login' is specified.
const loginHelpMsg = `login "username" "password"

Login as a user or admin.

Arguments:
1. username   (string, required)   Username
2. password   (string, required)   Password

Result:
{
  "isadmin":              (bool)    Is the user an admin
  "userid":               (string)  User ID
  "email":                (string)  User email
  "username":             (string)  Username
  "publickey":            (string)  Active public key
  "paywalladdress":       (string)  Registration paywall address
  "paywallamount":        (uint64)  Registration paywall amount in atoms
  "paywalltxnotbefore":   (int64)   Minimum timestamp for paywall tx
  "proposalcredits":      (uint64)  Number of available proposal credits 
  "lastlogintime":        (int64)   Unix timestamp of last login date
  "sessionmaxage":        (int64)   Unix timestamp of session max age
}`
