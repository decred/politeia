// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package commands

import "github.com/decred/politeia/politeiawww/api/v1"

// Help message displayed for the command 'politeiawwwcli help changeusername'
var ChangeUsernameCmdHelpMsg = `changeusername "password" "newusername" 

Change the username for the currently logged in user.

Arguments:
1. password      (string, required)   Current password 
2. newusername   (string, required)   New username  

Request:
{
  "password":      (string)  Current password 
  "newusername":   (string)  New username
}

Response:
{}`

type ChangeUsernameCmd struct {
	Args struct {
		Password    string `positional-arg-name:"password"`
		NewUsername string `positional-arg-name:"newusername"`
	} `positional-args:"true" required:"true"`
}

func (cmd *ChangeUsernameCmd) Execute(args []string) error {
	cu := &v1.ChangeUsername{
		Password:    DigestSHA3(cmd.Args.Password),
		NewUsername: cmd.Args.NewUsername,
	}

	// Print request details
	err := Print(cu, cfg.Verbose, cfg.RawJSON)
	if err != nil {
		return err
	}

	// Send request
	cur, err := c.ChangeUsername(cu)
	if err != nil {
		return err
	}

	// Print response details
	return Print(cur, cfg.Verbose, cfg.RawJSON)
}
