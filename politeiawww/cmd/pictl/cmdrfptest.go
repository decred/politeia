// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"time"

	tkv1 "github.com/decred/politeia/politeiawww/api/ticketvote/v1"
	pclient "github.com/decred/politeia/politeiawww/client"
	"github.com/pkg/errors"
)

// cmdRFPTest runs tests to ensure the RFP workflow works as expected.
type cmdRFPTest struct {
	Args struct {
		AdminEmail    string `positional-arg-name:"adminemail"`
		AdminPassword string `positional-arg-name:"adminpassword"`
	} `positional-args:"true" required:"true"`

	// Password is the user's dcrwallet password.
	Password string `long:"password"`

	// Quorum is the percent of total votes required for a quorum. This is a
	// pointer so that a value of 0 can be provided. A quorum of zero allows
	// for the vote to be approved or rejected using a single DCR ticket.
	Quorum *uint32 `long:"quorum"`

	// Passing is the percent of cast votes required for a vote options to be
	// considered as passing.
	Passing uint32 `long:"passing"`
}

// Execute executes the cmdRFPTest command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdRFPTest) Execute(args []string) error {
	const (
		// sleepInterval is the time to wait in between requests
		// when polling the ticketvote API for vote results or when
		// waiting for the RFP linkby deadline to expire before
		// starting the runoff vote.
		sleepInterval = 15 * time.Second
	)

	// Setup vote parameters
	var (
		quorum  = defaultQuorum
		passing = defaultPassing
	)
	if c.Quorum != nil {
		quorum = *c.Quorum
	}
	if c.Passing != 0 {
		passing = c.Passing
	}

	fmt.Printf("Quorum : %v%%\n", quorum)
	fmt.Printf("Passing: %v%%\n", passing)

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
		return errors.Errorf("paywall is not disabled")
	}

	// Get ticketvote API policy to verify voteduartionmin
	// policy.
	//
	// Setup client
	opts := pclient.Opts{
		HTTPSCert: cfg.HTTPSCert,
		Verbose:   cfg.Verbose,
		RawJSON:   cfg.RawJSON,
	}
	pc, err := pclient.New(cfg.Host, opts)
	if err != nil {
		return err
	}

	// Get policy
	pr, err := pc.TicketVotePolicy()
	if err != nil {
		return err
	}
	if pr.VoteDurationMin > 1 {
		return errors.Errorf("--votedurationmin flag should be <= 1, as the " +
			"tests include RFP & submssions voting, and the RFP deadline is 6m")
	}

	// Log start time
	fmt.Printf("Start time: %v\n", dateAndTimeFromUnix(time.Now().Unix()))

	// Verify admin login credentials
	admin := user{
		Email:    c.Args.AdminEmail,
		Password: c.Args.AdminPassword,
	}
	fmt.Printf("  Login as admin\n")
	err = userLogin(admin)
	if err != nil {
		return errors.Errorf("failed to login admin: %v", err)
	}
	lr, err := client.Me()
	if err != nil {
		return err
	}
	if !lr.IsAdmin {
		return errors.Errorf("provided user is not an admin")
	}
	admin.Username = lr.Username

	// Create a RFP and make it public
	fmt.Printf("  Create a RFP\n")
	// The RFP deadline is in 6 minutes from now, this should be safe as we
	// require the votedurationmin policy to be one block.
	linkByTime := time.Now().Add(6 * time.Minute)
	r, err := proposalPublic(admin, admin, &proposalOpts{
		Random: true,
		LinkBy: time.Until(linkByTime).String(),
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
	err = voteStart(admin, tokenRFP, pr.VoteDurationMin,
		quorum, passing, false)
	if err != nil {
		return err
	}

	// Cast votes on RFP
	fmt.Printf("  Cast 'yes' votes\n")

	// Prompt the user for their password if they haven't already
	// provided it.
	password := c.Password
	if password == "" {
		// Temporarily enable output to prompt user for password
		cfg.Silent = false
		pass, err := promptWalletPassword()
		if err != nil {
			return err
		}
		password = string(pass)
		cfg.Silent = true
	}

	err = castBallot(tokenRFP, tkv1.VoteOptionIDApprove, password)
	if err != nil {
		return err
	}

	// Wait to RFP to finish voting
	var (
		approvedRFP bool
		vs          tkv1.Summary
	)
	for !approvedRFP {
		// Fetch vote summary
		var cvs cmdVoteSummaries
		cvs.Args.Tokens = []string{tokenRFP}
		summaries, err := voteSummaries(&cvs)
		if err != nil {
			return err
		}
		vs = summaries[tokenRFP]

		if vs.Status != tkv1.VoteStatusApproved {
			fmt.Printf("  RFP voting still going on, block %v/%v \n",
				vs.BestBlock, vs.EndBlockHeight)
			time.Sleep(sleepInterval)
		} else {
			approvedRFP = true
		}
	}
	fmt.Printf("  RFP approved successfully\n")
	fmt.Printf("%v\n", voteSummaryString(tokenRFP, vs, 4))

	// Create 1 unvetted censored RFP submission
	fmt.Printf("  Create 1 unvetted censored RFP submission\n")
	r, err = proposalUnvettedCensored(admin, admin, &proposalOpts{
		Random: true,
		LinkTo: tokenRFP,
	})
	if err != nil {
		return err
	}
	tokenUnvettedCensored := r.CensorshipRecord.Token

	// Create 1 vetted censored RFP submission
	fmt.Printf("  Create 1 vetted censored RFP submission\n")
	r, err = proposalVettedCensored(admin, admin, &proposalOpts{
		Random: true,
		LinkTo: tokenRFP,
	})
	if err != nil {
		return err
	}
	tokenVettedCensored := r.CensorshipRecord.Token

	// Create 1 vetted abandoned RFP submission
	fmt.Printf("  Create 1 vetted abandoned RFP submission\n")
	r, err = proposalAbandoned(admin, admin, &proposalOpts{
		Random: true,
		LinkTo: tokenRFP,
	})
	if err != nil {
		return err
	}
	tokenAbandoned := r.CensorshipRecord.Token

	// Create 3 public RFP submissions
	fmt.Printf("  Create 3 public RFP submissions\n")
	var tokensPublic [3]string
	r, err = proposalPublic(admin, admin, &proposalOpts{
		Random: true,
		LinkTo: tokenRFP,
	})
	if err != nil {
		return err
	}
	tokensPublic[0] = r.CensorshipRecord.Token
	r, err = proposalPublic(admin, admin, &proposalOpts{
		Random: true,
		LinkTo: tokenRFP,
	})
	if err != nil {
		return err
	}
	tokensPublic[1] = r.CensorshipRecord.Token
	r, err = proposalPublic(admin, admin, &proposalOpts{
		Random: true,
		LinkTo: tokenRFP,
	})
	if err != nil {
		return err
	}
	tokensPublic[2] = r.CensorshipRecord.Token

	// Wait for the rfp deadline to expire
	for linkByTime.Unix() >= time.Now().Unix() {
		fmt.Printf("  Waiting for the RFP deadline to expire, remaining: %v\n",
			time.Until(linkByTime).Round(time.Second))
		time.Sleep(sleepInterval)
	}

	// Start runoff vote for the submissions
	fmt.Printf("  Start runoff vote for the submissions\n")
	err = voteStart(admin, tokenRFP, pr.VoteDurationMin, quorum, passing, true)
	if err != nil {
		return err
	}

	// Verify that the runoff vote contains only the 3 public proposals
	fmt.Printf("  Verify that the runoff vote contains only the 3 public " +
		"proposals\n")

	// Fetch vote summaries of public proposals
	var cvs cmdVoteSummaries
	tokens := tokensPublic[:]
	cvs.Args.Tokens = tokens
	summaries, err := voteSummaries(&cvs)
	if err != nil {
		return err
	}
	// Ensure public proposals are voting
	for _, t := range tokens {
		s := summaries[t]
		if s.Status != tkv1.VoteStatusStarted {
			return errors.Errorf("submission %v invalid vote status, "+
				"expected: %v, got: %v", t, tkv1.VoteStatuses[tkv1.VoteStatusStarted],
				tkv1.VoteStatuses[s.Status])
		}
	}

	// Fetch vote summaries of abandoned/consored proposals
	tokens = []string{tokenUnvettedCensored, tokenVettedCensored, tokenAbandoned}
	cvs.Args.Tokens = tokens
	summaries, err = voteSummaries(&cvs)
	if err != nil {
		return err
	}
	// Ensure abandoned/censored proposals are not voting
	for _, t := range tokens {
		s := summaries[t]
		if s.Status != tkv1.VoteStatusIneligible {
			return errors.Errorf("submission %v invalid vote status, "+
				"expected: %v, got: %v", t,
				tkv1.VoteStatuses[tkv1.VoteStatusIneligible],
				tkv1.VoteStatuses[s.Status])
		}
	}

	// Vote 'yes' on first public proposal, 'no' on the second and
	// don't vote on third.
	fmt.Printf("  Vote 'yes' on first public proposal, 'no' on the second and" +
		" don't vote on third\n")

	tokenFirst := tokensPublic[0]
	err = castBallot(tokenFirst, tkv1.VoteOptionIDApprove, password)
	if err != nil {
		return err
	}

	tokenSecond := tokensPublic[1]
	err = castBallot(tokenSecond, tkv1.VoteOptionIDReject, password)
	if err != nil {
		return err
	}

	// Wait for the runoff vote to finish
	var approvedSubmission bool
	for !approvedSubmission {
		// Fetch vote summary
		var cvs cmdVoteSummaries
		cvs.Args.Tokens = []string{tokenFirst}
		summaries, err := voteSummaries(&cvs)
		if err != nil {
			return err
		}
		vs = summaries[tokenFirst]

		if vs.Status != tkv1.VoteStatusApproved {
			fmt.Printf("  Runoff voting still going on, block %v/%v \n",
				vs.BestBlock, vs.EndBlockHeight)
			time.Sleep(sleepInterval)
		} else {
			approvedSubmission = true
		}
	}
	fmt.Printf("  First submission was approved successfully\n")
	fmt.Printf("%v\n", voteSummaryString(tokenFirst, vs, 4))

	// Fetch vote summary of rejected proposal
	cvs = cmdVoteSummaries{}
	tokenThird := tokensPublic[2]
	tokens = []string{tokenSecond, tokenThird}
	cvs.Args.Tokens = tokens
	summaries, err = voteSummaries(&cvs)
	if err != nil {
		return err
	}
	for _, t := range tokens {
		s := summaries[t]
		if s.Status != tkv1.VoteStatusRejected {
			return errors.Errorf("public submission %v invalid vote status, "+
				"expected: %v, got: %v", t, tkv1.VoteStatuses[tkv1.VoteStatusRejected],
				tkv1.VoteStatuses[s.Status])
		}
	}
	fmt.Printf("  The other two submissions were rejected successfully\n")
	for i, t := range tokens {
		fmt.Printf("%v\n", voteSummaryString(t, summaries[t], 4))
		if i != len(tokens)-1 {
			fmt.Printf("    -----\n")
		}
	}

	ts := dateAndTimeFromUnix(time.Now().Unix())
	fmt.Printf("Done!\n")
	fmt.Printf("Stop time: %v\n", ts)

	return nil
}

// RFPTestHelpMsg is the printed to stdout by the help command.
const RFPTestHelpMsg = `rfptest "adminemail" "adminpassword"

Run tests to ensure the RFP workflow works as expected.

Arguments:
1. adminemail     (string, required)  Email for admin account.
2. adminpassword  (string, required)  Password for admin account.

Flags:
 --password (string) dcrwallet password. The user will be prompted for their
                     password if one is not provided using this flag.
 --quorum   (uint32) Percent of total votes required to reach a quorum. A
                     quorum of 0 means that the vote can be approved or
                     rejected using a single DCR ticket.
                     (default: 0)
 --passing  (uint32) Percent of cast votes required for a vote option to be
                     considered as passing.
                     (default: 60)
`
