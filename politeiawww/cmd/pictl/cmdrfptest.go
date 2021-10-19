// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"time"

	tkv1 "github.com/decred/politeia/politeiawww/api/ticketvote/v1"
)

// cmdRFPTest runs tests to ensure the RFP workflow works as expected.
type cmdRFPTest struct {
	Args struct {
		AdminEmail    string `positional-arg-name:"adminemail" required:"true"`
		AdminPassword string `positional-arg-name:"adminpassword" required:"true"`
	} `positional-args:"true"`
}

// Execute executes the cmdRFPTest command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdRFPTest) Execute(args []string) error {
	const (
		// sleepInterval is the time to wait in between requests
		// when polling politeiawww for vote results.
		sleepInterval = 15 * time.Second
	)

	// We don't want the output of individual commands printed.
	cfg.Verbose = false
	cfg.RawJSON = false
	cfg.Silent = true

	// Verify paywall is disabled
	policyWWW, err := client.Policy()
	if err != nil {
		return err
	}
	if policyWWW.PaywallEnabled {
		return fmt.Errorf("paywall is not disabled")
	}

	// Log start time
	fmt.Printf("Start time: %v\n", timestampFromUnix(time.Now().Unix()))

	// Verify admin login credentials
	admin := user{
		Email:    c.Args.AdminEmail,
		Password: c.Args.AdminPassword,
	}
	fmt.Printf("  Login as admin\n")
	err = userLogin(admin)
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

	// Create a RFP and make it public
	fmt.Printf("  Create a RFP\n")
	r, err := proposalPublic(admin, admin, &proposalOpts{
		Random: true,
		RFP:    true,
	})
	if err != nil {
		return err
	}
	tokenRFP := r.CensorshipRecord.Token
	fmt.Printf("  RFP created: %v\n", tokenRFP)

	// Authorize RFP vote
	fmt.Printf("  Authorize vote on RFP\n")
	err = voteAuthorize(admin, tokenRFP)
	if err != nil {
		return err
	}

	// Start RFP vote
	fmt.Printf("  Start vote on RFP\n")
	err = voteStart(admin, tokenRFP, 1, 0, 0)
	if err != nil {
		return err
	}

	// Temporarily enable output to prompt user for password
	cfg.Silent = false

	// Cast votes on RFP
	fmt.Printf("  Cast 'yes' votes\n")
	err = castBallot(tokenRFP, "yes", "")
	if err != nil {
		return err
	}

	cfg.Silent = true

	// Wait to RFP to finish voting
	var vs tkv1.Summary
	for vs.Status != tkv1.VoteStatusApproved &&
		vs.Status != tkv1.VoteStatusRejected {
		var c cmdVoteSummaries
		c.Args.Tokens = []string{tokenRFP}
		summaries, err := voteSummaries(&c)
		if err != nil {
			return err
		}

		vs = summaries[tokenRFP]

		fmt.Printf("  RFP voting still going on, block %v\\%v \n",
			vs.BestBlock, vs.EndBlockHeight)
		time.Sleep(sleepInterval)
	}
	switch vs.Status {
	case tkv1.VoteStatusApproved:
		// RFP approved, continue
		fmt.Printf("  RFP approved successfully\n")
	case tkv1.VoteStatusRejected:
		return fmt.Errorf("wrong RFP vote status, want '%v', got '%v'",
			tkv1.VoteStatuses[tkv1.VoteStatusApproved],
			tkv1.VoteStatuses[tkv1.VoteStatusRejected])
	}

	return nil
}

// RFPTestHelpMsg is the printed to stdout by the help command.
const RFPTestHelpMsg = `rfptest "adminemail" "adminpassword"

Run tests to ensure the RFP workflow works as expected..

Arguments:
1. adminemail     (string, required)  Email for admin account.
2. adminpassword  (string, required)  Password for admin account.
`
