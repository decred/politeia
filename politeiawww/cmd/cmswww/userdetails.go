// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	cms "github.com/thi4go/politeia/politeiawww/api/cms/v1"
	"github.com/thi4go/politeia/politeiawww/cmd/shared"
)

// UserDetailsCmd requests a user's information.
type UserDetailsCmd struct {
	Args struct {
		UserID string `positional-arg-name:"userid" optional:"true"`
	} `positional-args:"true" optional:"true"`
}

// Execute executes the cms user information command.
func (cmd *UserDetailsCmd) Execute(args []string) error {

	var uir *cms.UserDetailsReply
	uid := cmd.Args.UserID

	lr, err := client.Me()
	if err != nil {
		return err
	}

	if uid != "" {
		uir, err = client.CMSUserDetails(uid)
	} else {
		uir, err = client.CMSUserDetails(lr.UserID)
	}
	if err != nil {
		return err
	}

	// Print user information reply.
	return shared.PrintJSON(uir)
}

// userDetailsHelpMsg is the output of the help command when 'userdetails' is
// specified.
const userDetailsHelpMsg = `userdetails "userid" 

Fetch user details by user id. 

Arguments:
1. userid      (string, required)   User id 
`
