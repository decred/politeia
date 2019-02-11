// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package commands

import "github.com/decred/politeia/politeiawww/api/v1"

// Help message displayed for the command 'politeiawwwcli help login'
var LoginCmdHelpMsg = `login "email" "password"

Login as a user or admin.

Arguments:
1. email      (string, required)   Email address of user
2. password   (string, required)   Accompanying password for provided email

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

type LoginCmd struct {
	Args struct {
		Email    string `positional-arg-name:"email"`
		Password string `positional-arg-name:"password"`
	} `positional-args:"true" required:"true"`
}

func (cmd *LoginCmd) Execute(args []string) error {
	email := cmd.Args.Email
	password := cmd.Args.Password

	// Fetch CSRF tokens
	_, err := c.Version()
	if err != nil {
		return err
	}

	// Setup login request
	l := &v1.Login{
		Email:    email,
		Password: DigestSHA3(password),
	}

	// Print request details
	err = Print(l, cfg.Verbose, cfg.RawJSON)
	if err != nil {
		return err
	}

	// Send request
	lr, err := c.Login(l)
	if err != nil {
		return err
	}

	// Print response details
	return Print(lr, cfg.Verbose, cfg.RawJSON)
}
