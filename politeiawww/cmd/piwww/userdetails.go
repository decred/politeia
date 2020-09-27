// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import "github.com/decred/politeia/politeiawww/cmd/shared"

// userDetailsCmd gets the user details for the specified user.
type userDetailsCmd struct {
	Args struct {
		UserID string `positional-arg-name:"userid"` // User ID
	} `positional-args:"true" required:"true"`
}

// Execute executes the user details command.
func (cmd *userDetailsCmd) Execute(args []string) error {
	udr, err := client.UserDetails(cmd.Args.UserID)
	if err != nil {
		return err
	}
	return shared.PrintJSON(udr)
}

// userDetailsHelpMsg is the output of the help command when 'userdetails' is
// specified.
const userDetailsHelpMsg = `userdetails "userid" 

Fetch user details by user id. 

Arguments:
1. userid      (string, required)   User id`
