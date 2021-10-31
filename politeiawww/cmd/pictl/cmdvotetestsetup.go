// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
)

// cmdVoteTestSetup starts a batch of proposal votes.
type cmdVoteTestSetup struct {
	Args struct {
		AdminEmail    string `positional-arg-name:"adminemail"`
		AdminPassword string `positional-arg-name:"adminpassword"`
	} `positional-args:"true" required:"true"`

	// Votes is the number of DCR ticket votes that will be started.
	Votes uint32 `long:"votes"`

	// Duration is the duration, in blocks of the DCR ticket votes.
	Duration uint32 `long:"duration"`

	// Quorum is the percent of total votes required for a quorum. This is a
	// pointer so that a value of 0 can be provided. A quorum of zero allows
	// for the vote to be approved or rejected using a single DCR ticket.
	Quorum *uint32 `long:"quorum"`

	// Passing is the percent of cast votes required for a vote options to be
	// considered as passing.
	Passing uint32 `long:"passing"`
}

// Execute executes the cmdVoteTestSetup command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdVoteTestSetup) Execute(args []string) error {
	// Setup vote parameters
	var (
		votes    uint32 = 10
		duration        = defaultDuration
		quorum          = defaultQuorum
		passing         = defaultPassing
	)
	if c.Votes > 0 {
		votes = c.Votes
	}
	if c.Duration > 0 {
		duration = c.Duration
	}
	if c.Quorum != nil {
		quorum = *c.Quorum
	}
	if c.Passing != 0 {
		passing = c.Passing
	}

	// We don't want the output of individual commands printed.
	cfg.Verbose = false
	cfg.RawJSON = false
	cfg.Silent = true

	// Verify the the provided login credentials are for an admin.
	admin := user{
		Email:    c.Args.AdminEmail,
		Password: c.Args.AdminPassword,
	}
	err := userLogin(admin)
	if err != nil {
		return fmt.Errorf("failed to login admin: %v", err)
	}
	lr, err := client.Me()
	if err != nil {
		return err
	}
	if !lr.IsAdmin {
		return fmt.Errorf("provided user is not an admin")
	}
	admin.Username = lr.Username

	// Verify that the paywall is disabled
	policyWWW, err := client.Policy()
	if err != nil {
		return err
	}
	if policyWWW.PaywallEnabled {
		fmt.Printf("WARN: politeiawww paywall is not disabled\n")
	}

	// Setup votes
	for i := 0; i < int(votes); i++ {
		s := fmt.Sprintf("Starting voting period on proposal %v/%v", i+1, votes)
		printInPlace(s)

		// Create a public proposal
		r, err := proposalPublic(admin, admin, &proposalOpts{
			Random:       true,
			RandomImages: false,
		})
		if err != nil {
			return err
		}
		token := r.CensorshipRecord.Token

		// Authorize vote
		err = voteAuthorize(admin, token)
		if err != nil {
			return err
		}

		// Start vote
		err = voteStart(admin, token, duration, quorum, passing)
		if err != nil {
			return err
		}
	}
	fmt.Printf("\n")

	return nil
}

// voteTestSetupHelpMsg is the printed to stdout by the help command.
const voteTestSetupHelpMsg = `votetestsetup [flags] "adminemail" "adminpassword"

Start batch of proposal votes. This command submits the specified number of
proposals, makes them public, then starts the voting period on each one.

Arguments:
1. adminemail     (string, required)  Email for admin account.
2. adminpassword  (string, required)  Password for admin account.

Flags
 --votes    (uint32) Number of votes to start.
                     (default: 10)
 --duration (uint32) Duration, in blocks, of the vote.
                     (default: 6)
 --quorum   (uint32) Percent of total votes required to reach a quorum. A
                     quorum of 0 means that the vote can be approved or
                     rejected using a single DCR ticket.
                     (default: 0)
 --passing  (uint32) Percent of cast votes required for a vote option to be
                     considered as passing.
                     (default: 60)
`
