// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package shared

import v1 "github.com/decred/politeia/politeiawww/api/www/v1"

// UserUsernameChangeCmd changes the username for the logged in user.
type UserUsernameChangeCmd struct {
	Args struct {
		Password    string `positional-arg-name:"password"`    // User password
		NewUsername string `positional-arg-name:"newusername"` // New username
	} `positional-args:"true" required:"true"`
}

// Execute executes the change username command.
func (cmd *UserUsernameChangeCmd) Execute(args []string) error {
	cu := &v1.ChangeUsername{
		Password:    DigestSHA3(cmd.Args.Password),
		NewUsername: cmd.Args.NewUsername,
	}

	// Print request details
	err := PrintJSON(cu)
	if err != nil {
		return err
	}

	// Send request
	cur, err := client.ChangeUsername(cu)
	if err != nil {
		return err
	}

	// Print response details
	return PrintJSON(cur)
}

// UserUsernameChangeHelpMsg is the output of the help command when
// 'userusernamechange' is specified.
var UserUsernameChangeHelpMsg = `userusernamechange "password" "newusername" 

Change the username for the currently logged in user.

Arguments:
1. password      (string, required)   Current password 
2. newusername   (string, required)   New username`
