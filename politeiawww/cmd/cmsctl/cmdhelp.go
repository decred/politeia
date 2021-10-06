// Copyright (c) 2017-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// cmdHelp prints a detailed help message for the specified command.
type cmdHelp struct {
	Args struct {
		Command string `positional-arg-name:"command"`
	} `positional-args:"true" required:"true"`
}

// Execute executes the cmdHelp command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdHelp) Execute(args []string) error {
	switch c.Args.Command {
	// Basic commands
	case "version":
		fmt.Printf("%s\n", shared.VersionHelpMsg)
	case "policy":
		fmt.Printf("%s\n", policyHelpMsg)
	case "login":
		fmt.Printf("%s\n", shared.LoginHelpMsg)
	case "logout":
		fmt.Printf("%s\n", shared.LogoutHelpMsg)
	case "me":
		fmt.Printf("%s\n", shared.MeHelpMsg)

	// User commands
	case "userinvitenew":
		fmt.Printf("%s\n", userInviteMsg)
	case "usermanage":
		fmt.Printf("%s\n", shared.UserManageHelpMsg)
	case "userkeyupdate":
		fmt.Printf("%s\n", shared.UserKeyUpdateHelpMsg)
	case "userusernamechange":
		fmt.Printf("%s\n", shared.UserUsernameChangeHelpMsg)
	case "userpasswordchange":
		fmt.Printf("%s\n", shared.UserPasswordChangeHelpMsg)
	case "userpasswordreset":
		fmt.Printf("%s\n", shared.UserPasswordResetHelpMsg)
	case "users":
		fmt.Printf("%s\n", shared.UsersHelpMsg)

		// Proposal commands
	case "invoicepolicy":
		fmt.Printf("%s\n", invoicePolicyHelpMsg)
	case "invoicenew":
		fmt.Printf("%s\n", invoiceNewHelpMsg)

		// Record commands
	case "recordpolicy":
		fmt.Printf("%s\n", recordPolicyHelpMsg)

	default:
		fmt.Printf("invalid command: use the -h,--help flag to view the " +
			"full list of valid commands\n")
	}

	return nil
}
