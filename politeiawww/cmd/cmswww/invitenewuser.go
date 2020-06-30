// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	v1 "github.com/decred/politeia/politeiawww/api/cms/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// InviteNewUserCmd allows administrators to invite contractors to join CMS.
type InviteNewUserCmd struct {
	Args struct {
		Email string `positional-arg-name:"email" `
	} `positional-args:"true"`
	Temporary bool `long:"temp" optional:"true"`
}

// Execute executes the invite new user command.
func (cmd *InviteNewUserCmd) Execute(args []string) error {
	inu := &v1.InviteNewUser{
		Email:     cmd.Args.Email,
		Temporary: cmd.Temporary,
	}

	// Print request details
	err := shared.PrintJSON(inu)
	if err != nil {
		return err
	}

	// Send request
	inur, err := client.InviteNewUser(inu)
	if err != nil {
		return fmt.Errorf("InviteNewUser: %v", err)
	}

	// Print response details
	err = shared.PrintJSON(inur)
	if err != nil {
		return err
	}

	return nil
}

const inviteNewUserHelpMsg = `invite "email"

Send a new user invitation to the given email.

If email has been disabled on the politeiawww server then the verification
token that would normally be sent to the email address will be returned in the
response.

Arguments:
1. email      (string, required)  Email address

Flags:
  --temp      (bool, optional)    Designate the user as a temporary user. This 
                                  means the user will only be able to submit a
                                  single invoice before being deactivated.
`
