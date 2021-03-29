// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
	pclient "github.com/decred/politeia/politeiawww/client"
)

// cmdUserProposals retrieves the proposal records for a user.
type cmdUserProposals struct {
	Args struct {
		UserID string `positional-arg-name:"userID" optional:"true"`
	} `positional-args:"true"`
}

// Execute executes the cmdUserProposals command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdUserProposals) Execute(args []string) error {
	// Setup client
	opts := pclient.Opts{
		HTTPSCert:  cfg.HTTPSCert,
		Cookies:    cfg.Cookies,
		HeaderCSRF: cfg.CSRF,
		Verbose:    cfg.Verbose,
		RawJSON:    cfg.RawJSON,
	}
	pc, err := pclient.New(cfg.Host, opts)
	if err != nil {
		return err
	}

	// Setup user ID
	userID := c.Args.UserID
	if userID == "" {
		// No user ID provided. Use the user ID of the logged in user.
		lr, err := client.Me()
		if err != nil {
			if err.Error() == "401" {
				return fmt.Errorf("no user ID provided and no logged in user found")
			}
			return err
		}
		userID = lr.UserID
	}

	// Get user proposals
	ur := rcv1.UserRecords{
		UserID: userID,
	}
	urr, err := pc.UserRecords(ur)
	if err != nil {
		return err
	}

	// Print record tokens to stdout
	printJSON(urr)

	return nil
}

// userProposalsHelpMsg is printed to stdout by the help command.
const userProposalsHelpMsg = `userproposals "userID"

Retrieve the proprosals that were submitted by a user. If no user ID is given,
the ID of the logged in user will be used.`
