// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
)

// HelpCmd prints a detailed help message for the specified command.
type HelpCmd struct {
	Args struct {
		Topic string `positional-arg-name:"topic"` // Topic to print help message for
	} `positional-args:"true"`
}

// Execute executes the help command.
func (cmd *HelpCmd) Execute(args []string) error {
	if cmd.Args.Topic == "" {
		return fmt.Errorf("Specify a command to print a detailed help " +
			"message for.  Example: politeiawww_dbutil help addcredits")
	}

	switch cmd.Args.Topic {
	case "addcredits":
		fmt.Printf("%s\n", addCreditsHelpMsg)
	case "createkey":
		fmt.Printf("%s\n", createKeyHelpMsg)
	case "dump":
		fmt.Printf("%s\n", dumpHelpMsg)
	case "migrate":
		fmt.Printf("%s\n", migrateHelpMsg)
	case "resettotp":
		fmt.Printf("%s\n", resetTotpHelpMsg)
	case "setadmin":
		fmt.Printf("%s\n", setAdminHelpMsg)
	case "setemail":
		fmt.Printf("%s\n", setEmailHelpMsg)
	case "stubusers":
		fmt.Printf("%s\n", stubUsersHelpMsg)
	case "verifyidentities":
		fmt.Printf("%s\n", verifyIdentitiesHelpMsg)

	default:
		fmt.Printf("invalid command: use 'politeiawww_dbutil -h' " +
			"to view a list of valid commands\n")
	}

	return nil
}
