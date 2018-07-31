package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	flags "github.com/btcsuite/go-flags"
	"github.com/davecgh/go-spew/spew"
	"github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/politeiawww/cmd/politeiawwwcli/client"
	"github.com/decred/politeia/politeiawww/cmd/politeiawwwcli/config"
	"github.com/decred/politeia/util"
)

const (
	timeToPoll = 3 // time in seconds which will poll for block confirmations
	faucetURL  = "https://faucet.decred.org/requestfaucet"
)

type AdminOptions struct {
	Email    string `long:"email" short:"e" description:"admin email"`
	Password string `long:"password" short:"p" description:"admin password"`
}

type Options struct {
	Admin         AdminOptions `group:"Admin Options"`
	Host          string       `long:"host" short:"h" default:"https://127.0.0.1:4443" description:"Host"`
	OverrideToken string       `long:"overridetoken" short:"o" description:"Override token for faucet"`
	Json          bool         `long:"json" short:"j" description:"Print JSON"`
	Vote          bool         `long:"vote" short:"v" description:"Run vote routes"`
}

func handleError(err error) {
	if err != nil {
		// Get filename and error line number for error message
		_, fn, line, _ := runtime.Caller(1)
		fmt.Printf("%s:%d %v\n", filepath.Base(fn), line, err)
		os.Exit(1)
	}
}

func vote(opts *Options, c *client.Ctx) {
	adminEmail := opts.Admin.Email
	adminPassword := opts.Admin.Password
	mockPayload := []byte("This is a description")

	// Login (admin)
	lr, id, err := c.Login(adminEmail, adminPassword)
	handleError(err)

	// Admin success
	if !lr.IsAdmin {
		err = fmt.Errorf("%v is not an admin", adminEmail)
		handleError(err)
	}

	// Make sure admin user has a proposal credit
	if lr.ProposalCredits == 0 {
		fmt.Printf("warning: admin has 0 proposal credits. Use politeiawww_dbutil to add "+
			"proposal credits to %v's account.\n", adminEmail)
	}

	// New proposal
	prop1, err := c.NewProposal(id, mockPayload, nil)
	handleError(err)

	// Start vote, wrong state should fail
	_, err = c.StartVote(id, prop1.CensorshipRecord.Token)
	if err == nil {
		err = fmt.Errorf("expected 400, wrong status")
		handleError(err)
	}
	if !strings.HasPrefix(err.Error(), "400") {
		err = fmt.Errorf("expected 400, wrong status got: %v", err)
		handleError(err)
	}

	// SKIPPED: Move prop to Locked, should fail

	// Move prop to vetted
	psr1, err := c.SetPropStatus(id, prop1.CensorshipRecord.Token,
		v1.PropStatusPublic)
	handleError(err)

	if psr1.Proposal.Status != v1.PropStatusPublic {
		err = fmt.Errorf("Invalid status got %v wanted %v", psr1.Proposal.Status,
			v1.PropStatusPublic)
		handleError(err)
	}

	// Add comment
	_, err = c.Comment(id, prop1.CensorshipRecord.Token,
		"I super like this prop", "")
	handleError(err)

	// SKIPPED: Move prop to locked
	// SKIPPED: Get record and verify status

	// Start vote sucess
	svr, err := c.StartVote(id, prop1.CensorshipRecord.Token)
	handleError(err)
	_ = svr
	if opts.Json {
		spew.Dump(svr)
	}

	fmt.Printf("Vote routes complete\n")
}

func main() {
	// Initialize politeiawwwcli config
	err := config.Load()
	handleError(err)
	mockPayload := []byte("This is a description")

	// Parse command line
	var opts Options
	var parser = flags.NewParser(&opts, flags.Default)
	if _, err := parser.Parse(); err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			os.Exit(0)
		} else {
			os.Exit(1)
		}
	}

	// Setup CLI options
	config.Host = opts.Host
	config.PrintJSON = opts.Json

	// Exit if admin email is given without password or vise versa
	if opts.Admin.Email != "" || opts.Admin.Password != "" {
		if opts.Admin.Email == "" || opts.Admin.Password == "" {
			err = fmt.Errorf("Missing admin email or password")
			handleError(err)
		}
	}

	// Setup client
	c, err := client.NewClient(true)
	handleError(err)

	// Version - save CSRF token
	v, err := c.Version()
	serverPubKey := v.PubKey
	handleError(err)

	// Run vote routes
	if opts.Vote {
		if opts.Admin.Email == "" {
			err = fmt.Errorf("Vote tests require admin credentials")
			handleError(err)
		}

		vote(&opts, c)
		os.Exit(0)
	}

	// Policy - fetch password requirements
	policy, err := c.Policy()
	handleError(err)

	// Create random number strings to be used as new user credentials
	b1, err := util.Random(int(policy.MinPasswordLength))
	handleError(err)
	username1 := hex.EncodeToString(b1)
	email1 := username1 + "@example.com"
	password1 := username1

	b2, err := util.Random(int(policy.MinPasswordLength))
	handleError(err)
	username2 := hex.EncodeToString(b2)
	password2 := username2

	// New user
	token, id, paywallAddress, paywallAmount, err := c.NewUser(email1, username1,
		password1)
	handleError(err)

	// Verify user
	sig := id.SignMessage([]byte(token))
	err = c.VerifyNewUser(email1, token, hex.EncodeToString(sig[:]))
	handleError(err)

	// New proposal failure
	_, err = c.NewProposal(id, mockPayload, nil)
	if err == nil {
		err = fmt.Errorf("/new should only be accessible by logged in users")
		handleError(err)
	}

	// Reset password
	err = c.ResetPassword(email1, password2)
	handleError(err)

	// Login failure
	_, _, err = c.Login(email1, password1)
	if err == nil {
		err = fmt.Errorf("Expected login failure")
		handleError(err)
	}

	// Login success
	lr, _, err := c.Login(email1, password2)
	handleError(err)

	// Admin failure
	if lr.IsAdmin {
		err = fmt.Errorf("Expected non-admin")
		handleError(err)
	}

	// Secret
	err = c.Secret()
	handleError(err)

	// Me
	_, err = c.Me()
	handleError(err)

	// Change password
	_, err = c.ChangePassword(password2, password1)
	handleError(err)

	// Change username
	_, err = c.ChangeUsername(password1, username2)
	handleError(err)

	// Check if the paywall has been turned off.
	paywallIsEnabled := true
	if paywallAddress == "" && paywallAmount == 0 {
		paywallIsEnabled = false
	}

	if paywallIsEnabled {
		// Proposal paywall failure
		_, err := c.ProposalPaywall()
		if err == nil {
			err = fmt.Errorf("proposal paywall should require user registration fee to be paid")
			handleError(err)
		}

		// Use the testnet faucet to satisfy the user registration fee.
		faucetTx, err := util.PayWithTestnetFaucet(faucetURL, paywallAddress,
			paywallAmount, opts.OverrideToken)
		if err != nil {
			err = fmt.Errorf("unable to pay with %v with %v faucet: %v",
				paywallAddress, paywallAmount, err)
			handleError(err)
		}

		fmt.Printf("paid %v Atom to %v with faucet tx %v\n", paywallAmount,
			paywallAddress, faucetTx)

		// Wait for user registration fee confirmations.
		ticker := time.NewTicker(time.Second * timeToPoll)
		for range ticker.C {
			verifyUserPaid, err := c.VerifyUserPayment()
			handleError(err)
			if verifyUserPaid.HasPaid {
				ticker.Stop()
				break
			}
			fmt.Printf("Waiting for user registration fee confirmations...\n")
		}

		// Proposal paywall
		ppdr, err := c.ProposalPaywall()
		handleError(err)

		// The user can only be issued one proposal paywall at a time.  The proposal
		// paywall endpoint should return the same paywall until it has either been
		// paid or has expired.
		ppdr2, err := c.ProposalPaywall()
		handleError(err)
		if ppdr.PaywallTxNotBefore != ppdr2.PaywallTxNotBefore {
			err = fmt.Errorf("Expected proposal paywalls to be the same")
			handleError(err)
		}

		// New proposal failure
		_, err = c.NewProposal(id, mockPayload, nil)
		if err == nil {
			err = fmt.Errorf("new proposal should require proposal credit")
			handleError(err)
		}

		// Use faucet to purchase proposal credits.
		var quantity uint64 = 30
		txAmount := quantity * ppdr.CreditPrice
		faucetTx, err = util.PayWithTestnetFaucet(faucetURL, ppdr.PaywallAddress, txAmount,
			opts.OverrideToken)
		if err != nil {
			err = fmt.Errorf("unable to pay with %v with %v faucet: %v", ppdr.PaywallAddress,
				txAmount, err)
			handleError(err)
		}
		fmt.Printf("paid %v Atom to %v with faucet tx %v\n", txAmount, ppdr.PaywallAddress,
			faucetTx)

		// Wait for proposal paywall confirmations.
		ticker = time.NewTicker(time.Second * timeToPoll)
		for range ticker.C {
			me, err := c.Me()
			handleError(err)
			if me.ProposalCredits > 0 {
				// Check that the correct number of proposal credits were created.
				if me.ProposalCredits < quantity {
					err = fmt.Errorf("Expected %v credits, got %v\n", quantity, me.ProposalCredits)
					handleError(err)
				}
				ticker.Stop()
				break
			}
			fmt.Printf("Waiting for proposal paywall confirmations...\n")
		}

		// Proposal paywall
		ppdr3, err := c.ProposalPaywall()
		handleError(err)
		if ppdr.PaywallTxNotBefore == ppdr3.PaywallTxNotBefore {
			err = fmt.Errorf("Expected a new proposal paywalls to be created")
			handleError(err)
		}
	}

	// New proposal #1 and verify that it exists under the correct user
	prop1, err := c.NewProposal(id, mockPayload, nil)
	handleError(err)

	lr, err = c.Me()
	handleError(err)
	upr, err := c.ProposalsForUser(lr.UserID, serverPubKey)
	handleError(err)

	if len(upr.Proposals) != 1 {
		err = fmt.Errorf("Incorrect number of proposals returned for user")
		handleError(err)
	}
	if upr.Proposals[0].CensorshipRecord.Token != prop1.CensorshipRecord.Token {
		err = fmt.Errorf("Proposal tokens don't match")
		handleError(err)
	}

	// Create new identity
	oldId := id
	id, err = c.CreateNewKey(email1 + "newkey")
	handleError(err)

	// New proposal failure
	_, err = c.NewProposal(oldId, mockPayload, nil)
	if err == nil {
		err = fmt.Errorf("Expected error, user identity should be inactive")
		handleError(err)
	}

	// New proposal #2
	prop2, err := c.NewProposal(id, mockPayload, nil)
	handleError(err)

	// Get prop1 and validate
	pr1, err := c.GetProp(prop1.CensorshipRecord.Token, serverPubKey)
	handleError(err)

	if pr1.Proposal.CensorshipRecord.Token != prop1.CensorshipRecord.Token {
		err = fmt.Errorf("pr1 invalid got %v wanted %v", pr1.Proposal.CensorshipRecord.Token,
			prop1.CensorshipRecord.Token)
		handleError(err)
	}
	if pr1.Proposal.Status != v1.PropStatusNotReviewed {
		err = fmt.Errorf("pr1 invalid status got %v wanted %v", pr1.Proposal.Status,
			v1.PropStatusNotReviewed)
		handleError(err)
	}
	if len(pr1.Proposal.Files) > 0 {
		err = fmt.Errorf("pr1 unexpected proposal data received")
		handleError(err)
	}

	// Get prop2 and validate
	pr2, err := c.GetProp(prop2.CensorshipRecord.Token, serverPubKey)
	handleError(err)

	if pr2.Proposal.CensorshipRecord.Token != prop2.CensorshipRecord.Token {
		err = fmt.Errorf("pr2 invalid got %v wanted %v", pr2.Proposal.CensorshipRecord.Token,
			prop2.CensorshipRecord.Token)
		handleError(err)
	}
	if pr2.Proposal.Status != v1.PropStatusNotReviewed {
		err = fmt.Errorf("pr2 invalid status got %v wanted %v", pr2.Proposal.Status,
			v1.PropStatusNotReviewed)
		handleError(err)
	}
	if len(pr2.Proposal.Files) > 0 {
		err = fmt.Errorf("pr2 unexpected proposal data received")
		handleError(err)
	}

	// Create enough proposals to have 2 pages
	for i := 0; i < int(policy.ProposalListPageSize); i++ {
		_, err = c.NewProposal(id, mockPayload, nil)
		handleError(err)
	}

	// Unvetted proposals failure
	_, err = c.GetUnvetted(v1.GetAllUnvetted{}, serverPubKey)
	if err == nil {
		err = fmt.Errorf("/unvetted should only be accessible by admin users")
		handleError(err)
	}

	// Vetted proposals
	_, err = c.GetVetted(v1.GetAllVetted{}, serverPubKey)
	handleError(err)

	// Assets
	// TODO: test Assets once endpoint is fixed

	// Logout
	err = c.Logout()
	handleError(err)

	// Secret failure
	err = c.Secret()
	if err == nil {
		err = fmt.Errorf("/secret should fail for logged out user")
		handleError(err)
	}

	// Me failure
	_, err = c.Me()
	if err == nil {
		err = fmt.Errorf("/me should fail for logged out user")
		handleError(err)
	}

	// Run admin routes
	if opts.Admin.Email != "" {
		fmt.Printf("Starting Admin routes...\n")

		adminEmail := opts.Admin.Email
		adminPassword := opts.Admin.Password

		//  Login (admin)
		lr, id, err = c.Login(adminEmail, adminPassword)
		handleError(err)

		// Admin success
		if !lr.IsAdmin {
			err = fmt.Errorf("%v is not an admin", adminEmail)
			handleError(err)
		}

		// Me (admin)
		me, err := c.Me()
		handleError(err)
		if me.Email != adminEmail {
			err = fmt.Errorf("/me Email got %v wanted %v", me.Email, adminEmail)
			handleError(err)
		}
		if !me.IsAdmin {
			err = fmt.Errorf("/me IsAdmin got %v wanted %v", me.IsAdmin, true)
			handleError(err)
		}

		// Unvetted paging
		unvettedPage1, err := c.GetUnvetted(v1.GetAllUnvetted{}, serverPubKey)
		handleError(err)

		lastPropPage1 := unvettedPage1.Proposals[len(unvettedPage1.Proposals)-1]
		u := v1.GetAllUnvetted{
			After: lastPropPage1.CensorshipRecord.Token,
		}
		unvettedPage2, err := c.GetUnvetted(u, serverPubKey)
		handleError(err)

		if len(unvettedPage2.Proposals) == 0 {
			err = fmt.Errorf("Empty 2nd page of unvetted proposals")
			handleError(err)
		}

		// Get proposal
		pr1, err := c.GetProp(prop1.CensorshipRecord.Token, serverPubKey)
		handleError(err)

		if len(pr1.Proposal.Files) == 0 {
			err = fmt.Errorf("pr1 expected proposal data")
			handleError(err)
		}

		// Set proposal status - move prop1 to public
		psr1, err := c.SetPropStatus(id, prop1.CensorshipRecord.Token, v1.PropStatusPublic)
		handleError(err)

		if psr1.Proposal.Status != v1.PropStatusPublic {
			err = fmt.Errorf("Invalid status got %v wanted %v", psr1.Proposal.Status,
				v1.PropStatusPublic)
			handleError(err)
		}

		// Set proposal status - move prop2 to censored
		psr2, err := c.SetPropStatus(id, prop2.CensorshipRecord.Token, v1.PropStatusCensored)
		handleError(err)

		if psr2.Proposal.Status != v1.PropStatusCensored {
			err = fmt.Errorf("Invalid status got %v wanted %v", psr2.Proposal.Status,
				v1.PropStatusCensored)
			handleError(err)
		}

		// Get prop - check status of prop1 and prop2
		_pr1, err := c.GetProp(prop1.CensorshipRecord.Token, serverPubKey)
		handleError(err)

		if _pr1.Proposal.CensorshipRecord.Token != prop1.CensorshipRecord.Token {
			err = fmt.Errorf("_pr1 invalid got %v wanted %v", _pr1.Proposal.CensorshipRecord.Token,
				prop1.CensorshipRecord.Token)
			handleError(err)
		}
		if _pr1.Proposal.Status != v1.PropStatusPublic {
			err = fmt.Errorf("_pr1 invalid status got %v wanted %v", _pr1.Proposal.Status,
				v1.PropStatusPublic)
			handleError(err)
		}

		_pr2, err := c.GetProp(prop2.CensorshipRecord.Token, serverPubKey)
		handleError(err)

		if _pr2.Proposal.CensorshipRecord.Token != prop2.CensorshipRecord.Token {
			err = fmt.Errorf("_pr2 invalid got %v wanted %v", _pr2.Proposal.CensorshipRecord.Token,
				prop2.CensorshipRecord.Token)
			handleError(err)
		}
		if _pr2.Proposal.Status != v1.PropStatusCensored {
			err = fmt.Errorf("_pr2 invalid status got %v wanted %v", _pr2.Proposal.Status,
				v1.PropStatusCensored)
			handleError(err)
		}

		// Comment on prop1 without a parent
		cr, err := c.Comment(id, prop1.CensorshipRecord.Token, "I like this prop", "")
		handleError(err)
		// Comment on comment
		cr, err = c.Comment(id, prop1.CensorshipRecord.Token, "you are right!",
			cr.Comment.CommentID)
		handleError(err)
		// Comment on comment
		cr, err = c.Comment(id, prop1.CensorshipRecord.Token, "you are wrong!",
			cr.Comment.CommentID)
		handleError(err)

		// Comment on prop1 without a parent
		cr2, err := c.Comment(id, prop1.CensorshipRecord.Token, "I dont like this prop", "")
		handleError(err)
		// Comment on comment
		cr, err = c.Comment(id, prop1.CensorshipRecord.Token, "you are right!",
			cr2.Comment.CommentID)
		handleError(err)
		// Comment on comment
		cr, err = c.Comment(id, prop1.CensorshipRecord.Token, "you are crazy!",
			cr2.Comment.CommentID)
		handleError(err)

		// Get comments from prop1 and check the number of comments
		gcr, err := c.CommentGet(prop1.CensorshipRecord.Token)
		handleError(err)

		if len(gcr.Comments) != 6 {
			err = fmt.Errorf("Expected 6 comments, got %v", len(gcr.Comments))
			handleError(err)
		}

		// Get prop1 and check number of comments
		_pr1, err = c.GetProp(prop1.CensorshipRecord.Token, serverPubKey)
		handleError(err)
		if _pr1.Proposal.NumComments != uint(len(gcr.Comments)) {
			err = fmt.Errorf("Expected %v comments, got %v", len(gcr.Comments),
				_pr1.Proposal.NumComments)
			handleError(err)
		}

		// Get comments from prop2 and check the number of comments
		gcr2, err := c.CommentGet(prop2.CensorshipRecord.Token)
		handleError(err)
		if len(gcr2.Comments) != 0 {
			err = fmt.Errorf("Expected 0 comments, got %v", len(gcr2.Comments))
			handleError(err)
		}

		// Get prop2 and check number of comments
		_pr2, err = c.GetProp(prop2.CensorshipRecord.Token, serverPubKey)
		handleError(err)
		if _pr2.Proposal.NumComments != uint(len(gcr2.Comments)) {
			err = fmt.Errorf("Expected %v comments, got %v", len(gcr2.Comments),
				_pr2.Proposal.NumComments)
			handleError(err)
		}

		// Upvote first comment of prop1
		lcr, err := c.CommentVote(id, prop1.CensorshipRecord.Token, gcr.Comments[0].CommentID,
			"upvote")
		handleError(err)
		if lcr.Total != 1 {
			err = fmt.Errorf("Expected total: 1, got %v", lcr.Total)
			handleError(err)
		}
		if lcr.Result != 1 {
			err = fmt.Errorf("Expected result: 1, got %v", lcr.Result)
			handleError(err)
		}

		// Unset vote on first comment of prop1 by upvoting it again
		lcr, err = c.CommentVote(id, prop1.CensorshipRecord.Token, gcr.Comments[0].CommentID,
			"upvote")
		handleError(err)
		if lcr.Total != 0 {
			err = fmt.Errorf("Expected total: 0, got %v", lcr.Total)
			handleError(err)
		}
		if lcr.Result != 0 {
			err = fmt.Errorf("Expected result: 0, got %v", lcr.Result)
			handleError(err)
		}

		// Downvote second comment of prop1
		lcr, err = c.CommentVote(id, prop1.CensorshipRecord.Token, gcr.Comments[1].CommentID,
			"downvote")
		handleError(err)
		if lcr.Total != 1 {
			err = fmt.Errorf("Expected total: 1, got %v", lcr.Total)
			handleError(err)
		}
		if lcr.Result != -1 {
			err = fmt.Errorf("Expected result: -1, got %v", lcr.Result)
			handleError(err)
		}

		// Unset vote on second comment of prop1 by downvoting it again
		lcr, err = c.CommentVote(id, prop1.CensorshipRecord.Token, gcr.Comments[1].CommentID,
			"downvote")
		handleError(err)
		if lcr.Total != 0 {
			err = fmt.Errorf("Expected total: 0, got %v", lcr.Total)
			handleError(err)
		}
		if lcr.Result != 0 {
			err = fmt.Errorf("Expected result: 0, got %v", lcr.Result)
			handleError(err)
		}

		// Upvote second comment of prop1
		lcr, err = c.CommentVote(id, prop1.CensorshipRecord.Token, gcr.Comments[1].CommentID,
			"upvote")
		handleError(err)
		if lcr.Total != 1 {
			err = fmt.Errorf("Expected total: 1, got %v", lcr.Total)
			handleError(err)
		}
		if lcr.Result != 1 {
			err = fmt.Errorf("Expected result: 1, got %v", lcr.Result)
			handleError(err)
		}

		// Downvote second comment of prop1 after upvoting it
		lcr, err = c.CommentVote(id, prop1.CensorshipRecord.Token, gcr.Comments[1].CommentID,
			"downvote")
		handleError(err)
		if lcr.Total != 1 {
			err = fmt.Errorf("Expected total: 1, got %v", lcr.Total)
			handleError(err)
		}
		if lcr.Result != -1 {
			err = fmt.Errorf("Expected result: -1, got %v", lcr.Result)
			handleError(err)
		}

		// Upvote second comment of prop1 after downvoting it
		lcr, err = c.CommentVote(id, prop1.CensorshipRecord.Token, gcr.Comments[1].CommentID,
			"upvote")
		handleError(err)
		if lcr.Total != 1 {
			err = fmt.Errorf("Expected total: 1, got %v", lcr.Total)
			handleError(err)
		}
		if lcr.Result != 1 {
			err = fmt.Errorf("Expected result: 1, got %v", lcr.Result)
			handleError(err)
		}

		cvg, err := c.CommentsVotesGet(prop1.CensorshipRecord.Token)
		handleError(err)
		if len(cvg.CommentsVotes) != 2 {
			err = fmt.Errorf("Expected 2 comments votes but got %v", len(cvg.CommentsVotes))
			handleError(err)
		}
		if cvg.CommentsVotes[1].Action != "1" {
			err = fmt.Errorf("Expected action: 1, got %v", cvg.CommentsVotes[1].Action)
			handleError(err)
		}
		if cvg.CommentsVotes[0].Action != "0" {
			err = fmt.Errorf("Expected action: 0, got %v", cvg.CommentsVotes[0].Action)
			handleError(err)
		}

		fmt.Printf("Admin routes complete\n")
	}

	fmt.Printf("politeiawwwtest complete\n")
}
