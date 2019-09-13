// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/decred/politeia/politeiawww/api/cms/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// InviteNewUserCmd allows administrators to invite contractors to join CMS.
type InviteNewUserCmd struct {
	Args struct {
		Email string `positional-arg-name:"email"`
	} `positional-args:"true" required:"true"`
}

// Execute executes the invite new user command.
func (cmd *InviteNewUserCmd) Execute(args []string) error {
	email := cmd.Args.Email

	if email == "" {
		return fmt.Errorf("invalid credentials: you must specify user " +
			"email")
	}

	inu := &v1.InviteNewUser{
		Email: cmd.Args.Email,
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
