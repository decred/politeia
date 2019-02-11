// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package commands

import "fmt"

// LogoutCmd logs the user out of Politeia.
type LogoutCmd struct{}

// Execute executes the logout command.
func (cmd *LogoutCmd) Execute(args []string) error {
	lr, err := client.Logout()
	if err != nil {
		return err
	}

	// Update the logged in username that we store on disk
	err = cfg.SaveLoggedInUsername("")
	if err != nil {
		return fmt.Errorf("SaveLoggedInUsername: %v", err)
	}

	return printJSON(lr)
}

// logoutHelpMsg is the output of the help command when 'logout' is specified.
const logoutHelpMsg = `logout 

Logout as a user or admin.

Arguments:
None

Result:
{}`
