// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
)

type cmdSetupVoteTest struct {
	Args struct {
		AdminEmail    string `positional-arg-name:"adminemail" required:"true"`
		AdminPassword string `positional-arg-name:"adminpassword" required:"true"`
		Votes         uint32 `positional-arg-name:"votes"`
	} `positional-args:"true"`

	// IncludeImages is used to include a random number of images when
	// submitting proposals.
	IncludeImages bool `long:"includeimages"`
}

// Execute executes the cmdSetupVoteTest command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdSetupVoteTest) Execute(args []string) error {
	// Setup test parameters
	var (
		votes    uint32 = 10
		duration uint32 = 6  // In blocks
		quorum   uint32 = 1  // Percentage of total tickets
		pass     uint32 = 50 // Percentage of votes cast
	)
	if c.Args.Votes > 0 {
		votes = c.Args.Votes
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
		return fmt.Errorf("paywall is not disabled")
	}

	// Setup votes
	for i := 0; i < int(votes); i++ {
		s := fmt.Sprintf("Starting voting period on proposal %v/%v", i+1, votes)
		printInPlace(s)

		// Create a public proposal
		r, err := proposalPublic(admin, admin, false)
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

// voteAuthorize authorizes the ticket vote.
//
// This function returns with the user logged out.
func voteAuthorize(author user, token string) error {
	// Login author
	err := userLogin(author)
	if err != nil {
		return err
	}

	// Authorize the voting period
	c := cmdVoteAuthorize{}
	c.Args.Token = token
	err = c.Execute(nil)
	if err != nil {
		return fmt.Errorf("cmdVoteAuthorize: %v", err)
	}

	// Logout author
	err = userLogout()
	if err != nil {
		return err
	}

	return nil
}

// voteStart starts the voting period on a record.
//
// This function returns with the admin logged out.
func voteStart(admin user, token string, duration, quorum, pass uint32) error {
	// Login admin
	err := userLogin(admin)
	if err != nil {
		return err
	}

	// Start the voting period
	c := cmdVoteStart{}
	c.Args.Token = token
	c.Args.Duration = duration
	c.Args.QuorumPercentage = quorum
	c.Args.PassPercentage = pass
	err = c.Execute(nil)
	if err != nil {
		return fmt.Errorf("cmdVoteStart: %v", err)
	}

	// Logout admin
	err = userLogout()
	if err != nil {
		return err
	}

	return nil
}
