// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
)

// cmdVoteTestSetup sets up a batch of proposal votes.
type cmdVoteTestSetup struct {
	Args struct {
		AdminEmail    string `positional-arg-name:"adminemail" required:"true"`
		AdminPassword string `positional-arg-name:"adminpassword" required:"true"`
	} `positional-args:"true"`

	// Options to adjust the vote params.
	Votes            uint32 `long:"votes" optional:"true"`
	Duration         uint32 `long:"duration" optional:"true"`
	QuorumPercentage uint32 `long:"quorumpercentage" optional:"true"`
	PassPercentage   uint32 `long:"passpercentage" optional:"true"`

	// IncludeImages is used to include a random number of images when
	// submitting proposals.
	IncludeImages bool `long:"includeimages"`
}

// Execute executes the cmdVoteTestSetup command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdVoteTestSetup) Execute(args []string) error {
	// Setup test parameters
	var (
		votes    uint32 = 10
		duration uint32 = 6  // In blocks
		quorum   uint32 = 1  // Percentage of total tickets
		pass     uint32 = 50 // Percentage of votes cast
	)
	if c.Votes > 0 {
		votes = c.Votes
	}
	if c.Duration > 0 {
		duration = c.Duration
	}
	if c.QuorumPercentage > 0 {
		quorum = c.QuorumPercentage
	}
	if c.PassPercentage > 0 {
		pass = c.PassPercentage
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
		err = voteStart(admin, token, duration, quorum, pass)
		if err != nil {
			return err
		}
	}
	fmt.Printf("\n")

	return nil
}

// voteTestSetupHelpMsg is the printed to stdout by the help command.
const voteTestSetupHelpMsg = `votetestsetup [flags] "adminemail" "adminpassword"

Setup a batch of proposal votes. This command submits the specified number of
proposals, makes them public, then starts the voting period on each one.

Arguments:
1. adminemail     (string, required)  Email for admin account.
2. adminpassword  (string, required)  Password for admin account.

Flags
 --votes         (uint32) Number of votes to start. (default: 10)
 --duration      (uint32) Duration of each vote in blocks. (default: 6)
 --quorum        (uint32) Percent of total votes required to reach a quorum.
                          (default: 1)
 --pass          (uint32) Percent of votes cast required for the vote to be
                          approved. (default: 50)
 --includeimages (bool)   Include images in proposal submissions. This will
                          substantially increase the size of the proposal
                          payload.
`
