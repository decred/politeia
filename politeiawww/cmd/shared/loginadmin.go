// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package shared

import (
	"fmt"
	"net/url"

	v1 "github.com/decred/politeia/politeiawww/api/www/v1"
)

// LoginAdminCmd logs into Politeia with an admin account,
// using the specified credentials.
type LoginAdminCmd struct {
	Args struct {
		Email    string `positional-arg-name:"email"`
		Password string `positional-arg-name:"password"`
	} `positional-args:"true" required:"true"`
}

// Execute executes the loginadmin command. This command calls the
// login route on the admin host of the running pi instance.
func (cmd *LoginAdminCmd) Execute(args []string) error {
	// Fetch CSRF key
	v, err := client.Version()
	if err != nil {
		return err
	}

	// Setup admin login request
	l := &v1.Login{
		Email:    cmd.Args.Email,
		Password: DigestSHA3(cmd.Args.Password),
	}

	// Print request details
	err = PrintJSON(l)
	if err != nil {
		return err
	}

	// Configure admin host
	port := v1.DefaultMainnetAdminPort
	if v.TestNet {
		port = v1.DefaultTestnetAdminPort
	}
	url, err := url.Parse(client.cfg.Host)
	if err != nil {
		return err
	}
	client.cfg.Host = "https://" + url.Hostname() + ":" + port

	// Send request
	lr, err := client.LoginAdmin(l)
	if err != nil {
		return err
	}

	// Update the logged in user data that we store on disk
	err = cfg.SaveUserData(*lr)
	if err != nil {
		return fmt.Errorf("SaveUserData: %v", err)
	}

	// Print response details
	return PrintJSON(lr)
}

// LoginAdminHelpMsg is the output for the help command when 'loginadmin'
// is specified.
const LoginAdminHelpMsg = `loginadmin "email" "password"

Login as an admin.

Arguments:
1. email      (string, required)   Email
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
