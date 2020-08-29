// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/decred/dcrwallet/rpc/walletrpc"
	"github.com/decred/politeia/decredplugin"
	v1 "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
	"github.com/decred/politeia/util"
)

// TestRunCmd performs a test run of all the politeiawww routes.
type TestRunCmd struct {
	Args struct {
		AdminEmail    string `positional-arg-name:"adminemail"`
		AdminPassword string `positional-arg-name:"adminpassword"`
	} `positional-args:"true" required:"true"`
}

// testUser stores user details that are used throughout the test run.
type testUser struct {
	ID        string // UUID
	email     string // Email
	username  string // Username
	password  string // Password (not hashed)
	publicKey string // Public key of active identity
}

// login logs in the specified user.
func login(email, password string) error {
	lc := shared.LoginCmd{}
	lc.Args.Email = email
	lc.Args.Password = password
	return lc.Execute(nil)
}

// newRFPProposal is a wrapper func which creates a RFP by calling newProposal
func newRFPProposal() (*v1.NewProposal, error) {
	return newProposal(true, "")
}

// newSubmissionProposal is a wrapper func which creates a RFP submission by
// calling newProposal func with a given linkto token.
func newSubmissionProposal(linkto string) (*v1.NewProposal, error) {
	return newProposal(false, linkto)
}

// newNormalProposal is a wrapper func which creates a proposal by calling
// newProposal
func newNormalProposal() (*v1.NewProposal, error) {
	return newProposal(false, "")
}

// newProposal returns a NewProposal object contains randonly generated
// markdown text and a signature from the logged in user. If given `rfp` bool
// is true it creates an RFP. If given `linkto` it creates a RFP submission.
func newProposal(rfp bool, linkto string) (*v1.NewProposal, error) {
	md, err := createMDFile()
	if err != nil {
		return nil, fmt.Errorf("create MD file: %v", err)
	}
	files := []v1.File{*md}

	pm := v1.ProposalMetadata{
		Name: "Some proposal name",
	}
	if rfp {
		pm.LinkBy = time.Now().Add(time.Hour * 24 * 30).Unix()
	}
	if linkto != "" {
		pm.LinkTo = linkto
	}
	pmb, err := json.Marshal(pm)
	if err != nil {
		return nil, err
	}
	metadata := []v1.Metadata{
		{
			Digest:  hex.EncodeToString(util.Digest(pmb)),
			Hint:    v1.HintProposalMetadata,
			Payload: base64.StdEncoding.EncodeToString(pmb),
		},
	}

	sig, err := shared.SignedMerkleRoot(files, metadata, cfg.Identity)
	if err != nil {
		return nil, fmt.Errorf("sign merkle root: %v", err)
	}

	return &v1.NewProposal{
		Files:     files,
		Metadata:  metadata,
		PublicKey: hex.EncodeToString(cfg.Identity.Public.Key[:]),
		Signature: sig,
	}, nil
}

// castVotes casts votes on a proposal with a given voteId. If it fails it
// returns the error and in case of dcrwallet connection error it returns
// true as first returned value
func castVotes(token string, voteID string) (bool, error) {
	var vc VoteCmd
	vc.Args.Token = token
	vc.Args.VoteID = voteID
	err := vc.Execute(nil)
	if err != nil {
		switch {
		case strings.Contains(err.Error(), "connection refused"):
			// User is not running a dcrwallet instance locally.
			// This is ok. Print a warning and continue.
			fmt.Printf("  WARNING: could not connect to dcrwallet\n")
			return true, err

		case strings.Contains(err.Error(), "no eligible tickets"):
			// User doesn't have any eligible tickets. This is ok.
			// Print a warning and continue.
			fmt.Printf("  WARNING: user has no elibigle tickets\n")
			return true, err

		default:
			return false, err
		}
	}
	return false, err
}

// Execute executes the test run command.
func (cmd *TestRunCmd) Execute(args []string) error {
	const (
		// sleepInterval is the time to wait in between requests
		// when polling politeiawww for paywall tx confirmations
		// or RFP vote results.
		sleepInterval = 15 * time.Second

		// Comment actions
		commentActionUpvote   = "upvote"
		commentActionDownvote = "downvote"
	)

	var (
		// paywallEnabled represents whether the politeiawww paywall
		// has been enabled.  A disabled paywall will have a paywall
		// address of "" and a paywall amount of 0.
		paywallEnabled bool

		// numCredits is the number of proposal credits that will be
		// purchased using the testnet faucet.
		numCredits = v1.ProposalListPageSize * 2

		// Test users
		user  testUser
		admin testUser
	)

	// Suppress output from cli commands
	cfg.Silent = true

	// Policy
	fmt.Printf("Policy\n")
	policy, err := client.Policy()
	if err != nil {
		return err
	}

	// Version (CSRF tokens)
	fmt.Printf("Version\n")
	version, err := client.Version()
	if err != nil {
		return err
	}

	// We only allow this to be run on testnet for right now.
	// Running it on mainnet would require changing the user
	// email verification flow.
	// We ensure vote duration isn't longer than
	// 3 blocks as we need to approve an RFP and it's
	// submission as part of our tests.
	switch {
	case !version.TestNet:
		return fmt.Errorf("this command must be run on testnet")
	case policy.MinVoteDuration > 3:
		return fmt.Errorf("--votedurationmin flag should be <= 3, as the " +
			"tests include RFP & submssions voting")
	}

	// Ensure admin credentials are valid and that the admin has
	// paid their user registration fee.
	fmt.Printf("Validating admin credentials\n")
	admin.email = cmd.Args.AdminEmail
	admin.password = cmd.Args.AdminPassword
	err = login(admin.email, admin.password)
	if err != nil {
		return err
	}

	vupr, err := client.VerifyUserPayment()
	if err != nil {
		return err
	}
	if !vupr.HasPaid {
		return fmt.Errorf("admin has not paid registration fee")
	}

	lc := shared.LogoutCmd{}
	err = lc.Execute(nil)
	if err != nil {
		return err
	}

	// Create user and verify email
	b, err := util.Random(int(policy.MinPasswordLength))
	if err != nil {
		return err
	}

	email := hex.EncodeToString(b) + "@example.com"
	username := hex.EncodeToString(b)
	password := hex.EncodeToString(b)

	fmt.Printf("Creating user: %v\n", email)

	nuc := NewUserCmd{
		Verify: true,
	}
	nuc.Args.Email = email
	nuc.Args.Username = username
	nuc.Args.Password = password
	err = nuc.Execute(nil)
	if err != nil {
		return err
	}

	// Login and store user details
	fmt.Printf("Login user\n")
	lr, err := client.Login(
		&v1.Login{
			Email:    email,
			Password: shared.DigestSHA3(password),
		})
	if err != nil {
		return err
	}

	user = testUser{
		ID:        lr.UserID,
		email:     email,
		username:  username,
		password:  password,
		publicKey: lr.PublicKey,
	}

	// Check if paywall is enabled.  Paywall address and paywall
	// amount will be zero values if paywall has been disabled.
	if lr.PaywallAddress != "" && lr.PaywallAmount != 0 {
		paywallEnabled = true
	} else {
		fmt.Printf("WARNING: politeiawww paywall is disabled\n")
	}

	// Run user routes. These are the routes
	// that reqiure the user to be logged in.
	fmt.Printf("Running user routes\n")

	// Pay user registration fee
	if paywallEnabled {
		// New proposal failure - registration fee not paid
		fmt.Printf("  New proposal failure: registration fee not paid\n")
		npc := NewProposalCmd{
			Random: true,
		}
		err = npc.Execute(nil)
		if err == nil {
			return fmt.Errorf("submited proposal without " +
				"paying registration fee")
		}

		// Pay user registration fee
		fmt.Printf("  Paying user registration fee\n")
		txID, err := util.PayWithTestnetFaucet(cfg.FaucetHost,
			lr.PaywallAddress, lr.PaywallAmount, "")
		if err != nil {
			return err
		}

		dcr := float64(lr.PaywallAmount) / 1e8
		fmt.Printf("  Paid %v DCR to %v with txID %v\n",
			dcr, lr.PaywallAddress, txID)
	}

	// Wait for user registration payment confirmations
	// If the paywall has been disable this will be marked
	// as true. If the paywall has been enabled this will
	// be true once the payment tx has the required number
	// of confirmations.
	for !vupr.HasPaid {
		vupr, err = client.VerifyUserPayment()
		if err != nil {
			return err
		}

		fmt.Printf("  Verify user payment: waiting for tx confirmations...\n")
		time.Sleep(sleepInterval)
	}

	// Purchase proposal credits
	fmt.Printf("  Proposal paywall details\n")
	ppdr, err := client.ProposalPaywallDetails()
	if err != nil {
		return err
	}

	if paywallEnabled {
		// New proposal failure - no proposal credits
		fmt.Printf("  New proposal failure: no proposal credits\n")
		npc := NewProposalCmd{
			Random: true,
		}
		err = npc.Execute(nil)
		if err == nil {
			return fmt.Errorf("submited proposal without " +
				"purchasing any proposal credits")
		}

		// Purchase proposal credits
		fmt.Printf("  Purchasing %v proposal credits\n", numCredits)

		atoms := ppdr.CreditPrice * uint64(numCredits)
		txID, err := util.PayWithTestnetFaucet(cfg.FaucetHost,
			ppdr.PaywallAddress, atoms, "")
		if err != nil {
			return err
		}

		fmt.Printf("  Paid %v DCR to %v with txID %v\n",
			float64(atoms)/1e8, lr.PaywallAddress, txID)
	}

	// Keep track of when the pending proposal credit payment
	// receives the required number of confirmations.
	for {
		pppr, err := client.ProposalPaywallPayment()
		if err != nil {
			return err
		}

		// TxID will be blank if the paywall has been disabled
		// or if the payment is no longer pending.
		if pppr.TxID == "" {
			// Verify that the correct number of proposal credits
			// have been added to the user's account.
			upcr, err := client.UserProposalCredits()
			if err != nil {
				return err
			}

			if !paywallEnabled || len(upcr.UnspentCredits) == numCredits {
				break
			}
		}

		fmt.Printf("  Proposal paywall payment: waiting for tx confirmations...\n")
		time.Sleep(sleepInterval)
	}

	// Me
	fmt.Printf("  Me\n")
	_, err = client.Me()
	if err != nil {
		return err
	}

	// Change password
	fmt.Printf("  Change password\n")
	b, err = util.Random(int(policy.MinPasswordLength))
	if err != nil {
		return err
	}
	cpc := shared.ChangePasswordCmd{}
	cpc.Args.Password = user.password
	cpc.Args.NewPassword = hex.EncodeToString(b)
	err = cpc.Execute(nil)
	if err != nil {
		return err
	}
	user.password = cpc.Args.NewPassword

	// Change username
	fmt.Printf("  Change username\n")
	cuc := shared.ChangeUsernameCmd{}
	cuc.Args.Password = user.password
	cuc.Args.NewUsername = hex.EncodeToString(b)
	err = cuc.Execute(nil)
	if err != nil {
		return err
	}
	user.username = cuc.Args.NewUsername

	// Edit user
	fmt.Printf("  Edit user\n")
	var n uint64 = 1 << 0
	_, err = client.EditUser(
		&v1.EditUser{
			EmailNotifications: &n,
		})
	if err != nil {
		return err
	}

	// Update user key
	fmt.Printf("  Update user key\n")
	var uukc shared.UpdateUserKeyCmd
	err = uukc.Execute(nil)
	if err != nil {
		return err
	}

	// Submit new proposal
	fmt.Printf("  New proposal\n")
	np, err := newNormalProposal()
	if err != nil {
		return err
	}
	npr, err := client.NewProposal(np)
	if err != nil {
		return err
	}

	// Verify proposal censorship record
	pr := v1.ProposalRecord{
		Files:            np.Files,
		Metadata:         np.Metadata,
		PublicKey:        np.PublicKey,
		Signature:        np.Signature,
		CensorshipRecord: npr.CensorshipRecord,
	}
	err = shared.VerifyProposal(pr, version.PubKey)
	if err != nil {
		return fmt.Errorf("verify proposal failed: %v", err)
	}

	// This is the proposal that we'll use for most of the tests
	token := pr.CensorshipRecord.Token
	fmt.Printf("  Proposal submitted: %v\n", token)

	// Edit unvetted proposal
	fmt.Printf("  Edit unvetted proposal\n")
	epc := EditProposalCmd{
		Random: true,
	}
	epc.Args.Token = token
	err = epc.Execute(nil)
	if err != nil {
		return err
	}

	// Login with admin and make the proposal public
	fmt.Printf("  Login admin\n")
	err = login(admin.email, admin.password)
	if err != nil {
		return err
	}

	fmt.Printf("  Set proposal status: public\n")
	spsc := SetProposalStatusCmd{}
	spsc.Args.Token = token
	spsc.Args.Status = strconv.Itoa(int(v1.PropStatusPublic))
	err = spsc.Execute(nil)
	if err != nil {
		return err
	}

	// Log back in with user
	fmt.Printf("  Login user\n")
	err = login(user.email, user.password)
	if err != nil {
		return err
	}

	// Edit vetted proposal
	fmt.Printf("  Edit vetted proposal\n")
	err = epc.Execute(nil)
	if err != nil {
		return err
	}

	// New comment - parent
	fmt.Printf("  New comment: parent\n")
	ncc := shared.NewCommentCmd{}
	ncc.Args.Token = token
	ncc.Args.Comment = "this is a comment"
	ncc.Args.ParentID = "0"
	err = ncc.Execute(nil)
	if err != nil {
		return err
	}

	// New comment - reply
	fmt.Printf("  New comment: reply\n")
	ncc.Args.Token = token
	ncc.Args.Comment = "this is a comment reply"
	ncc.Args.ParentID = "1"
	err = ncc.Execute(nil)
	if err != nil {
		return err
	}

	// Validate comments
	fmt.Printf("  Proposal details\n")
	pdr, err := client.ProposalDetails(token, nil)
	if err != nil {
		return err
	}

	err = shared.VerifyProposal(pdr.Proposal, version.PubKey)
	if err != nil {
		return fmt.Errorf("verify proposal failed: %v", err)
	}

	if pdr.Proposal.NumComments != 2 {
		return fmt.Errorf("proposal num comments got %v, want 2",
			pdr.Proposal.NumComments)
	}

	fmt.Printf("  Proposal comments\n")
	gcr, err := client.GetComments(token)
	if err != nil {
		return fmt.Errorf("GetComments: %v", err)
	}

	if len(gcr.Comments) != 2 {
		return fmt.Errorf("num comments got %v, want 2",
			len(gcr.Comments))
	}

	for _, v := range gcr.Comments {
		// We check the userID because userIDs are not part of
		// the politeiad comment record. UserIDs are stored in
		// in politeiawww and are added to the comments at the
		// time of the request. This introduces the potential
		// for errors.
		if v.UserID != user.ID {
			return fmt.Errorf("comment userID got %v, want %v",
				v.UserID, user.ID)
		}
	}

	// Like comment sequence
	lcc := LikeCommentCmd{}
	lcc.Args.Token = pr.CensorshipRecord.Token
	lcc.Args.CommentID = "1"
	lcc.Args.Action = commentActionUpvote

	fmt.Printf("  Like comment: upvote\n")
	err = lcc.Execute(nil)
	if err != nil {
		return err
	}

	fmt.Printf("  Like comment: upvote\n")
	err = lcc.Execute(nil)
	if err != nil {
		return err
	}

	fmt.Printf("  Like comment: upvote\n")
	err = lcc.Execute(nil)
	if err != nil {
		return err
	}

	fmt.Printf("  Like comment: downvote\n")
	lcc.Args.Action = commentActionDownvote
	err = lcc.Execute(nil)
	if err != nil {
		return err
	}

	// Validate like comments
	fmt.Printf("  Proposal comments\n")
	gcr, err = client.GetComments(token)
	if err != nil {
		return err
	}

	for _, v := range gcr.Comments {
		if v.CommentID == "1" {
			switch {
			case v.Upvotes != 0:
				return fmt.Errorf("comment result up votes got %v, want 0",
					v.Upvotes)
			case v.Downvotes != 1:
				return fmt.Errorf("comment result down votes got %v, want 1",
					v.Downvotes)
			case v.ResultVotes != -1:
				return fmt.Errorf("comment result vote score got %v, want -1",
					v.ResultVotes)
			}
		}
	}

	fmt.Printf("  User like comments\n")
	crv, err := client.UserCommentsLikes(token)
	if err != nil {
		return err
	}

	switch {
	case len(crv.CommentsLikes) != 1:
		return fmt.Errorf("user like comments got %v, want 1",
			len(crv.CommentsLikes))

	case crv.CommentsLikes[0].Action != v1.VoteActionDown:
		return fmt.Errorf("user like comment action got %v, want %v",
			crv.CommentsLikes[0].Action, v1.VoteActionDown)
	}

	// Authorize vote then revoke
	fmt.Printf("  Authorize vote: authorize\n")
	avc := AuthorizeVoteCmd{}
	avc.Args.Token = token
	avc.Args.Action = decredplugin.AuthVoteActionAuthorize
	err = avc.Execute(nil)
	if err != nil {
		return err
	}

	fmt.Printf("  Authorize vote: revoke\n")
	avc.Args.Action = decredplugin.AuthVoteActionRevoke
	err = avc.Execute(nil)
	if err != nil {
		return err
	}

	// Validate vote status
	fmt.Printf("  Vote status\n")
	vsr, err := client.VoteStatus(token)
	if err != nil {
		return err
	}

	if vsr.Status != v1.PropVoteStatusNotAuthorized {
		return fmt.Errorf("vote status got %v, want %v",
			vsr.Status, v1.PropVoteStatusNotAuthorized)
	}

	// Authorize vote
	fmt.Printf("  Authorize vote: authorize\n")
	avc.Args.Action = decredplugin.AuthVoteActionAuthorize
	err = avc.Execute(nil)
	if err != nil {
		return err
	}

	// Validate vote status
	fmt.Printf("  Vote status\n")
	vsr, err = client.VoteStatus(token)
	if err != nil {
		return err
	}

	if vsr.Status != v1.PropVoteStatusAuthorized {
		return fmt.Errorf("vote status got %v, want %v",
			vsr.Status, v1.PropVoteStatusNotAuthorized)
	}

	// Logout
	fmt.Printf("  Logout\n")
	lc = shared.LogoutCmd{}
	err = lc.Execute(nil)
	if err != nil {
		return err
	}

	// Admin routes are routes that only
	// admins can access.
	fmt.Printf("Running admin routes\n")

	// Login
	fmt.Printf("  Login admin\n")
	err = login(admin.email, admin.password)
	if err != nil {
		return err
	}

	// Start vote
	fmt.Printf("  Start vote\n")
	svc := StartVoteCmd{}
	svc.Args.Token = token
	err = svc.Execute(nil)
	if err != nil {
		return err
	}

	// Censor comment
	fmt.Printf("  Censor comment\n")
	ccc := shared.CensorCommentCmd{}
	ccc.Args.Token = token
	ccc.Args.CommentID = "2"
	ccc.Args.Reason = "comment is spam"
	err = ccc.Execute(nil)
	if err != nil {
		return err
	}

	// Validate censored comment
	fmt.Printf("  Get comments\n")
	gcr, err = client.GetComments(token)
	if err != nil {
		return err
	}

	if len(gcr.Comments) != 2 {
		return fmt.Errorf("num comments got %v, want 2",
			len(gcr.Comments))
	}

	c := gcr.Comments[1]
	switch {
	case c.CommentID != "2":
		return fmt.Errorf("commentID got %v, want 2",
			c.CommentID)

	case c.Comment != "":
		return fmt.Errorf("censored comment text got %v, want empty string",
			c.Comment)

	case !c.Censored:
		return fmt.Errorf("censored comment not marked as censored")
	}

	// Login with user in order to submit proposals that we can
	// use to test the set proposal status route.
	fmt.Printf("  Login user\n")
	err = login(user.email, user.password)
	if err != nil {
		return err
	}

	// Submit proposals that can be used to test the set proposal
	// status command.
	fmt.Printf("  Creating proposals for set proposal status test\n")
	var (
		// Censorship tokens
		notReviewed1       string
		notReviewed2       string
		unreviewedChanges1 string
		unreviewedChanges2 string

		// We don't need these now but will need
		// them when we test the public routes.
		censoredPropToken   string
		unreviewedPropToken string
	)

	np, err = newNormalProposal()
	if err != nil {
		return err
	}
	npr, err = client.NewProposal(np)
	if err != nil {
		return err
	}
	notReviewed1 = npr.CensorshipRecord.Token

	np, err = newNormalProposal()
	if err != nil {
		return err
	}
	npr, err = client.NewProposal(np)
	if err != nil {
		return err
	}
	notReviewed2 = npr.CensorshipRecord.Token

	np, err = newNormalProposal()
	if err != nil {
		return err
	}
	npr, err = client.NewProposal(np)
	if err != nil {
		return err
	}
	epc = EditProposalCmd{
		Random: true,
	}
	epc.Args.Token = npr.CensorshipRecord.Token
	err = epc.Execute(nil)
	if err != nil {
		return err
	}
	unreviewedChanges1 = npr.CensorshipRecord.Token

	np, err = newNormalProposal()
	if err != nil {
		return err
	}
	npr, err = client.NewProposal(np)
	if err != nil {
		return err
	}
	epc = EditProposalCmd{
		Random: true,
	}
	epc.Args.Token = npr.CensorshipRecord.Token
	err = epc.Execute(nil)
	if err != nil {
		return err
	}
	unreviewedChanges2 = npr.CensorshipRecord.Token

	np, err = newNormalProposal()
	if err != nil {
		return err
	}
	npr, err = client.NewProposal(np)
	if err != nil {
		return err
	}
	// We don't use this proposal for testing the set
	// proposal status routes, but will need it when
	// we are testing the public routes.
	unreviewedPropToken = npr.CensorshipRecord.Token

	// Log back in with admin
	fmt.Printf("  Login admin\n")
	err = login(admin.email, admin.password)
	if err != nil {
		return err
	}

	// Validate the proposal statuses before we attempt to
	// change them.
	pdr, err = client.ProposalDetails(notReviewed1, nil)
	if err != nil {
		return err
	}

	if pdr.Proposal.Status != v1.PropStatusNotReviewed {
		return fmt.Errorf("Proposal status got %v, want %v",
			pdr.Proposal.Status, v1.PropStatusNotReviewed)
	}

	pdr, err = client.ProposalDetails(unreviewedChanges1, nil)
	if err != nil {
		return err
	}

	if pdr.Proposal.Status != v1.PropStatusUnreviewedChanges {
		return fmt.Errorf("Proposal status got %v, want %v",
			pdr.Proposal.Status, v1.PropStatusUnreviewedChanges)
	}

	// Set proposal status - not reviewed to censored
	fmt.Printf("  Set proposal status: not reviewed to censored\n")
	spsc = SetProposalStatusCmd{}
	spsc.Args.Token = notReviewed1
	spsc.Args.Status = "censored"
	spsc.Args.Message = "proposal is spam"
	err = spsc.Execute(nil)
	if err != nil {
		return err
	}

	pdr, err = client.ProposalDetails(spsc.Args.Token, nil)
	if err != nil {
		return err
	}

	if pdr.Proposal.Status != v1.PropStatusCensored {
		return fmt.Errorf("Proposal status got %v, want %v",
			pdr.Proposal.Status, v1.PropStatusCensored)
	}

	// Save this token. We will need it when
	// we test the public routes.
	censoredPropToken = spsc.Args.Token

	// Set proposal status - not reviewed to public
	fmt.Printf("  Set proposal status: not reviewed to public\n")
	spsc = SetProposalStatusCmd{}
	spsc.Args.Token = notReviewed2
	spsc.Args.Status = strconv.Itoa(int(v1.PropStatusPublic))
	err = spsc.Execute(nil)
	if err != nil {
		return err
	}

	pdr, err = client.ProposalDetails(spsc.Args.Token, nil)
	if err != nil {
		return err
	}

	if pdr.Proposal.Status != v1.PropStatusPublic {
		return fmt.Errorf("Proposal status got %v, want %v",
			pdr.Proposal.Status, v1.PropStatusPublic)
	}

	// Set proposal status - unreviewed changes to censored
	fmt.Printf("  Set proposal status: unreviewed changes to censored\n")
	spsc = SetProposalStatusCmd{}
	spsc.Args.Token = unreviewedChanges1
	spsc.Args.Status = "censored"
	spsc.Args.Message = "this is spam"
	err = spsc.Execute(nil)
	if err != nil {
		return err
	}

	pdr, err = client.ProposalDetails(spsc.Args.Token, nil)
	if err != nil {
		return err
	}

	if pdr.Proposal.Status != v1.PropStatusCensored {
		return fmt.Errorf("Proposal status got %v, want %v",
			pdr.Proposal.Status, v1.PropStatusCensored)
	}

	// Set proposal status - unreviewed changes to public
	fmt.Printf("  Set proposal status: unreviewed changes to public\n")
	spsc = SetProposalStatusCmd{}
	spsc.Args.Token = unreviewedChanges2
	spsc.Args.Status = strconv.Itoa(int(v1.PropStatusPublic))
	err = spsc.Execute(nil)
	if err != nil {
		return err
	}

	pdr, err = client.ProposalDetails(spsc.Args.Token, nil)
	if err != nil {
		return err
	}

	if pdr.Proposal.Status != v1.PropStatusPublic {
		return fmt.Errorf("Proposal status got %v, want %v",
			pdr.Proposal.Status, v1.PropStatusPublic)
	}

	// Set proposal status - public to abandoned
	fmt.Printf("  Set proposal status: public to abandoned\n")
	spsc.Args.Status = "abandoned"
	spsc.Args.Message = "no activity for two weeks"
	err = spsc.Execute(nil)
	if err != nil {
		return err
	}

	pdr, err = client.ProposalDetails(spsc.Args.Token, nil)
	if err != nil {
		return err
	}

	if pdr.Proposal.Status != v1.PropStatusAbandoned {
		return fmt.Errorf("Proposal status got %v, want %v",
			pdr.Proposal.Status, v1.PropStatusAbandoned)
	}

	// Users - filter by email
	fmt.Printf("  Users: filter by email\n")
	ur, err := client.Users(
		&v1.Users{
			Email: user.email,
		})
	if err != nil {
		return err
	}

	switch {
	case ur.TotalMatches != 1:
		return fmt.Errorf("total matches got %v, want 1",
			ur.TotalMatches)

	case ur.Users[0].ID != user.ID:
		return fmt.Errorf("user ID got %v, want %v",
			ur.Users[0].ID, user.ID)
	}

	// Users - filter by username
	fmt.Printf("  Users: filter by username\n")
	ur, err = client.Users(
		&v1.Users{
			Username: user.username,
		})
	if err != nil {
		return err
	}

	switch {
	case ur.TotalMatches != 1:
		return fmt.Errorf("total matches got %v, want 1",
			ur.TotalMatches)

	case ur.Users[0].ID != user.ID:
		return fmt.Errorf("user ID got %v, want %v",
			ur.Users[0].ID, user.ID)
	}

	// Rescan user payments
	fmt.Printf("  Rescan user payments\n")
	rupc := RescanUserPaymentsCmd{}
	rupc.Args.UserID = user.ID
	err = rupc.Execute(nil)
	if err != nil {
		return err
	}

	// Logout
	fmt.Printf("  Logout\n")
	lc = shared.LogoutCmd{}
	err = lc.Execute(nil)
	if err != nil {
		return err
	}

	// Public routes
	fmt.Printf("Running public routes\n")

	// Me failure
	_, err = client.Me()
	if err == nil {
		return fmt.Errorf("admin should be logged out")
	}

	// Proposal details
	fmt.Printf("  Proposal details\n")
	pdr, err = client.ProposalDetails(token, nil)
	if err != nil {
		return err
	}

	if pdr.Proposal.Version != "2" {
		return fmt.Errorf("proposal details version got %v, want 2",
			pdr.Proposal.Version)
	}

	// Proposal details version
	fmt.Printf("  Proposal details version\n")
	pdr, err = client.ProposalDetails(token,
		&v1.ProposalsDetails{
			Version: "1",
		})
	if err != nil {
		return err
	}

	if pdr.Proposal.Version != "1" {
		return fmt.Errorf("proposal details version got %v, want 1",
			pdr.Proposal.Version)
	}

	// Proposal details - unreviewed
	fmt.Printf("  Proposal details: unreviewed proposal\n")
	pdr, err = client.ProposalDetails(unreviewedPropToken, nil)
	if err != nil {
		return err
	}

	switch {
	case pdr.Proposal.Name != "":
		return fmt.Errorf("proposal name should be empty string")

	case len(pdr.Proposal.Files) != 0:
		return fmt.Errorf("proposal files should not be included")
	}

	// Proposal details - censored
	fmt.Printf("  Proposal details: censored proposal\n")
	pdr, err = client.ProposalDetails(censoredPropToken, nil)
	if err != nil {
		return err
	}

	switch {
	case pdr.Proposal.Name != "":
		return fmt.Errorf("proposal name should be empty string")

	case len(pdr.Proposal.Files) != 0:
		return fmt.Errorf("proposal files should not be included")

	case pdr.Proposal.CensoredAt == 0:
		return fmt.Errorf("proposal should have a CensoredAt timestamp")
	}

	// Proposal comments
	fmt.Printf("  Get comments\n")
	gcr, err = client.GetComments(token)
	if err != nil {
		return err
	}

	if len(gcr.Comments) != 2 {
		return fmt.Errorf("num comments got %v, want 2",
			len(gcr.Comments))
	}

	c0 := gcr.Comments[0]
	c1 := gcr.Comments[1]
	switch {
	case c0.CommentID != "1":
		return fmt.Errorf("comment ID got %v, want 1",
			c0.CommentID)

	case c0.Upvotes != 0:
		return fmt.Errorf("comment %v result up votes got %v, want 0",
			c0.CommentID, c0.Upvotes)

	case c0.Downvotes != 1:
		return fmt.Errorf("comment %v result down votes got %v, want 1",
			c0.CommentID, c0.Downvotes)

	case c0.ResultVotes != -1:
		return fmt.Errorf("comment %v result vote score got %v, want -1",
			c0.CommentID, c0.Downvotes)

	case c1.CommentID != "2":
		return fmt.Errorf("comment ID got %v, want 2",
			c1.CommentID)

	case c1.Comment != "":
		return fmt.Errorf("censored comment text got '%v', want ''",
			c1.Comment)

	case !c1.Censored:
		return fmt.Errorf("censored comment not marked as censored")
	}

	// Vetted proposals. We need to submit a page of proposals and
	// make them public first in order to test the vetted route.
	fmt.Printf("  Login admin\n")
	err = login(admin.email, admin.password)
	if err != nil {
		return err
	}

	fmt.Printf("  Submitting a page of proposals to test vetted route\n")
	for i := 0; i < v1.ProposalListPageSize; i++ {
		np, err = newNormalProposal()
		if err != nil {
			return err
		}
		_, err = client.NewProposal(np)
		if err != nil {
			return err
		}
	}

	fmt.Printf("  Token inventory\n")
	tir, err := client.TokenInventory()
	if err != nil {
		return err
	}

	fmt.Printf("  Batch proposals\n")
	bpr, err := client.BatchProposals(&v1.BatchProposals{
		Tokens: tir.Unreviewed[:v1.ProposalListPageSize],
	})
	if err != nil {
		return err
	}

	fmt.Printf("  Making unvetted proposals public\n")
	for _, v := range bpr.Proposals {
		spsc := SetProposalStatusCmd{}
		spsc.Args.Token = v.CensorshipRecord.Token
		spsc.Args.Status = strconv.Itoa(int(v1.PropStatusPublic))
		err = spsc.Execute(nil)
		if err != nil {
			return err
		}
	}

	fmt.Printf("  Logout\n")
	lc = shared.LogoutCmd{}
	err = lc.Execute(nil)
	if err != nil {
		return err
	}

	fmt.Printf("  Vetted\n")
	gavr, err := client.GetAllVetted(&v1.GetAllVetted{})
	if err != nil {
		return err
	}

	if len(gavr.Proposals) != v1.ProposalListPageSize {
		return fmt.Errorf("proposals page size got %v, want %v",
			len(gavr.Proposals), v1.ProposalListPageSize)
	}

	for _, v := range gavr.Proposals {
		err = shared.VerifyProposal(v, version.PubKey)
		if err != nil {
			return fmt.Errorf("verify proposal failed %v: %v",
				v.CensorshipRecord.Token, err)
		}
	}

	// User details
	fmt.Printf("  User details\n")
	udr, err := client.UserDetails(user.ID)
	if err != nil {
		return err
	}

	if udr.User.ID != user.ID {
		return fmt.Errorf("user ID got %v, want %v",
			udr.User.ID, user.ID)
	}

	// User proposals
	fmt.Printf("  User proposals\n")
	upr, err := client.UserProposals(
		&v1.UserProposals{
			UserId: user.ID,
		})
	if err != nil {
		return err
	}

	// userPropCount is the total number of proposals that we've
	// submitted with the test user during the test run that are
	// public.
	userPropCount := 3
	if upr.NumOfProposals != userPropCount {
		return fmt.Errorf("user proposal count got %v, want %v",
			upr.NumOfProposals, userPropCount)
	}

	for _, v := range upr.Proposals {
		err := shared.VerifyProposal(v, version.PubKey)
		if err != nil {
			return fmt.Errorf("verify proposal failed %v: %v",
				v.CensorshipRecord.Token, err)
		}
	}

	// Vote details
	fmt.Printf("  Vote details\n")
	vdr, err := client.VoteDetailsV2(token)
	if err != nil {
		return err
	}
	switch vdr.Version {
	case 2:
		// Validate signature
		vote, err := decredplugin.DecodeVoteV2([]byte(vdr.Vote))
		if err != nil {
			return err
		}
		dsv := decredplugin.StartVoteV2{
			PublicKey: vdr.PublicKey,
			Vote:      *vote,
			Signature: vdr.Signature,
		}
		err = dsv.VerifySignature()
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown start vote version %v", vdr.Version)
	}

	// Vote status
	fmt.Printf("  Vote status\n")
	vsr, err = client.VoteStatus(token)
	if err != nil {
		return err
	}

	if vsr.Status != v1.PropVoteStatusStarted {
		return fmt.Errorf("vote status got %v, want %v",
			vsr.Status, v1.PropVoteStatusStarted)
	}

	// Active votes
	fmt.Printf("  Active votes\n")
	avr, err := client.ActiveVotes()
	if err != nil {
		return err
	}

	var found bool
	for _, v := range avr.Votes {
		if v.Proposal.CensorshipRecord.Token == token {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("proposal %v not found in active votes",
			token)
	}

	// Cast votes
	fmt.Printf("  Cast votes\n")
	dcrwalletFailed, err := castVotes(token, vsr.OptionsResult[0].Option.Id)

	// Find how many votes the user cast so that
	// we can compare it against the vote results.
	var voteCount int
	if !dcrwalletFailed {
		// Get proposal vote details
		var pvt v1.ProposalVoteTuple
		for _, v := range avr.Votes {
			if v.Proposal.CensorshipRecord.Token == token {
				pvt = v
				break
			}
		}

		// Get the number of eligible tickets the user had
		ticketPool, err := convertTicketHashes(pvt.StartVoteReply.EligibleTickets)
		if err != nil {
			return err
		}

		err = client.LoadWalletClient()
		if err != nil {
			return err
		}
		defer client.Close()

		ctr, err := client.CommittedTickets(
			&walletrpc.CommittedTicketsRequest{
				Tickets: ticketPool,
			})
		if err != nil {
			return err
		}

		voteCount = len(ctr.TicketAddresses)
	}

	// Vote results
	fmt.Printf("  Vote results\n")
	vrr, err := client.VoteResults(token)
	if err != nil {
		return err
	}

	if len(vrr.CastVotes) != voteCount {
		return fmt.Errorf("num cast votes got %v, want %v",
			len(vrr.CastVotes), voteCount)
	}

	// RFP routes
	fmt.Println("Running RFP routes")

	// Login with admin to create an RFP
	// and make it public.
	fmt.Printf("  Login admin\n")
	err = login(admin.email, admin.password)
	if err != nil {
		return err
	}

	// Create RFP
	fmt.Println("  Create a RFP")
	np, err = newRFPProposal()
	if err != nil {
		return err
	}
	npr, err = client.NewProposal(np)
	if err != nil {
		return err
	}

	// Verify RFP censorship record
	rpr := v1.ProposalRecord{
		Files:            np.Files,
		Metadata:         np.Metadata,
		PublicKey:        np.PublicKey,
		Signature:        np.Signature,
		CensorshipRecord: npr.CensorshipRecord,
	}
	err = shared.VerifyProposal(rpr, version.PubKey)
	if err != nil {
		return fmt.Errorf("verify RFP failed: %v", err)
	}

	token = rpr.CensorshipRecord.Token
	fmt.Printf("  RFP submitted: %v\n", token)

	// Make RFP public
	fmt.Printf("  Set RFP status: not reviewed to public\n")
	spsc = SetProposalStatusCmd{}
	spsc.Args.Token = token
	spsc.Args.Status = strconv.Itoa(int(v1.PropStatusPublic))
	err = spsc.Execute(nil)
	if err != nil {
		return err
	}

	pdr, err = client.ProposalDetails(spsc.Args.Token, nil)
	if err != nil {
		return err
	}

	if pdr.Proposal.Status != v1.PropStatusPublic {
		return fmt.Errorf("RFP status got %v, want %v",
			pdr.Proposal.Status, v1.PropStatusPublic)
	}

	// Try to submit a RFP submission before RFP approval & expect to fail
	fmt.Println("  Try submitting a submission before RFP voting")
	np, err = newSubmissionProposal(token)
	if err != nil {
		return err
	}
	npr, err = client.NewProposal(np)
	if err != nil {
		switch {
		case strings.Contains(err.Error(), "rfp proposal vote did not pass"):
			fmt.Println("  Submission failed with expected error")
		default:
			return err
		}
	}

	// Authorize vote
	fmt.Printf("  Authorize vote: authorize\n")
	avc = AuthorizeVoteCmd{}
	avc.Args.Token = token
	avc.Args.Action = decredplugin.AuthVoteActionAuthorize
	err = avc.Execute(nil)
	if err != nil {
		return err
	}

	// Start RFP vote
	fmt.Printf("  Start RFP vote\n")
	svc = StartVoteCmd{}
	svc.Args.Token = token
	svc.Args.Duration = policy.MinVoteDuration
	svc.Args.PassPercentage = "1"
	svc.Args.QuorumPercentage = "1"
	err = svc.Execute(nil)
	if err != nil {
		return err
	}

	// Wait to RFP to finish voting
	var vs v1.VoteSummary
	for vs.Status != v1.PropVoteStatusFinished {
		bvs := v1.BatchVoteSummary{
			Tokens: []string{token},
		}
		bvsr, err := client.BatchVoteSummary(&bvs)
		if err != nil {
			return err
		}

		vs = bvsr.Summaries[token]

		fmt.Printf("  RFP voting still going on, block %v\\%v \n",
			bvsr.BestBlock, vs.EndHeight)
		time.Sleep(sleepInterval)
	}
	if !vs.Approved {
		fmt.Println("  RFP rejected")
	} else {
		return fmt.Errorf("RFP approved? %v, want false",
			vs.Approved)
	}

	// Try to submit a RFP submission on rejected RFP
	fmt.Println("  Try submitting a submission on rejected RFP")
	np, err = newSubmissionProposal(token)
	if err != nil {
		return err
	}
	npr, err = client.NewProposal(np)
	if err != nil {
		switch {
		case strings.Contains(err.Error(), "rfp proposal vote did not pass"):
			fmt.Println("  Submission failed with expected error")
		default:
			return err
		}
	}

	// Create another RFP
	fmt.Println("  Create another RFP")
	np, err = newRFPProposal()
	if err != nil {
		return err
	}
	npr, err = client.NewProposal(np)
	if err != nil {
		return err
	}
	token = npr.CensorshipRecord.Token

	// Make second RFP public
	fmt.Printf("  Set RFP status: not reviewed to public\n")
	spsc = SetProposalStatusCmd{}
	spsc.Args.Token = token
	spsc.Args.Status = strconv.Itoa(int(v1.PropStatusPublic))
	err = spsc.Execute(nil)
	if err != nil {
		return err
	}

	// Authorize vote
	fmt.Printf("  Authorize vote: authorize\n")
	avc = AuthorizeVoteCmd{}
	avc.Args.Token = token
	avc.Args.Action = decredplugin.AuthVoteActionAuthorize
	err = avc.Execute(nil)
	if err != nil {
		return err
	}

	// Start RFP vote
	fmt.Printf("  Start RFP vote\n")
	svc = StartVoteCmd{}
	svc.Args.Token = token
	svc.Args.Duration = policy.MinVoteDuration
	svc.Args.PassPercentage = "0"
	svc.Args.QuorumPercentage = "0"
	err = svc.Execute(nil)
	if err != nil {
		return err
	}

	// Cast RFP votes
	fmt.Printf("  Cast 'Yes' votes\n")
	dcrwalletFailed, err = castVotes(token, vsr.OptionsResult[0].Option.Id)

	if !dcrwalletFailed {
		// Wait to RFP to finish voting
		var vs v1.VoteSummary
		for vs.Status != v1.PropVoteStatusFinished {
			bvs := v1.BatchVoteSummary{
				Tokens: []string{token},
			}
			bvsr, err := client.BatchVoteSummary(&bvs)
			if err != nil {
				return err
			}

			vs = bvsr.Summaries[token]

			fmt.Printf("  RFP voting still going on, block %v\\%v \n",
				bvsr.BestBlock, vs.EndHeight)
			time.Sleep(sleepInterval)
		}
		if !vs.Approved {
			return fmt.Errorf("RFP approved? %v, want true",
				vs.Approved)
		}

		fmt.Printf("  RFP approved successfully\n")
		// Create 4 RFP submissions.
		// 1 Unreviewd
		fmt.Println("  Create unreviewed RFP submission")
		np, err = newSubmissionProposal(token)
		if err != nil {
			return err
		}
		npr, err = client.NewProposal(np)
		if err != nil {
			return err
		}
		// 2 Public
		fmt.Println("  Create 2 more submissions & make them public")
		np, err = newSubmissionProposal(token)
		if err != nil {
			return err
		}
		npr, err = client.NewProposal(np)
		if err != nil {
			return err
		}
		firststoken := npr.CensorshipRecord.Token
		fmt.Printf("  Set first submission status: not reviewed to" +
			" public\n")
		spsc = SetProposalStatusCmd{}
		spsc.Args.Token = firststoken
		spsc.Args.Status = strconv.Itoa(int(v1.PropStatusPublic))
		err = spsc.Execute(nil)
		if err != nil {
			return err
		}
		np, err = newSubmissionProposal(token)
		if err != nil {
			return err
		}
		npr, err = client.NewProposal(np)
		if err != nil {
			return err
		}
		secondstoken := npr.CensorshipRecord.Token
		fmt.Printf("  Set second submission status: not reviewed to" +
			" public\n")
		spsc = SetProposalStatusCmd{}
		spsc.Args.Token = secondstoken
		spsc.Args.Status = strconv.Itoa(int(v1.PropStatusPublic))
		err = spsc.Execute(nil)
		if err != nil {
			return err
		}
		// 1 Abandoned, first make public
		// then abandon
		np, err = newSubmissionProposal(token)
		if err != nil {
			return err
		}
		npr, err = client.NewProposal(np)
		if err != nil {
			return err
		}
		thirdstoken := npr.CensorshipRecord.Token
		fmt.Printf("  Set third submission status: not reviewed to" +
			" abandoned\n")
		spsc = SetProposalStatusCmd{}
		spsc.Args.Token = thirdstoken
		spsc.Args.Status = strconv.Itoa(int(v1.PropStatusPublic))
		err = spsc.Execute(nil)
		if err != nil {
			return err
		}
		spsc.Args.Status = "abandoned"
		spsc.Args.Message = "this is spam"
		err = spsc.Execute(nil)
		if err != nil {
			return err
		}
		// Start runoff vote
		fmt.Printf("  Start RFP submissions runoff vote\n")
		svrc := StartVoteRunoffCmd{}
		svrc.Args.TokenRFP = token
		svrc.Args.Duration = policy.MinVoteDuration
		svrc.Args.PassPercentage = "0"
		svrc.Args.QuorumPercentage = "0"
		err = svrc.Execute(nil)
		if err != nil {
			return err
		}
		// Cast first submission votes
		fmt.Printf("  Cast first submission votes\n")
		dcrwalletFailed, err = castVotes(firststoken, vsr.OptionsResult[0].Option.Id)
		if err != nil {
			return err
		}
		if !dcrwalletFailed {
			// Try cast votes on abandoned & expect error
			fmt.Println("  Try casting votes on abandoned RFP submission")
			_, err = castVotes(thirdstoken, vsr.OptionsResult[0].Option.Id)
			if err != nil {
				switch {
				case strings.Contains(err.Error(), "proposal not found"):
					fmt.Println("  Casting votes on abandoned submission failed")
				default:
					return err
				}
			}

			// Wait to runoff vote finish
			var vs v1.VoteSummary
			for vs.Status != v1.PropVoteStatusFinished {
				bvs := v1.BatchVoteSummary{
					Tokens: []string{firststoken},
				}
				bvsr, err := client.BatchVoteSummary(&bvs)
				if err != nil {
					return err
				}

				vs = bvsr.Summaries[firststoken]

				fmt.Printf("  Runoff vote still going on, block %v\\%v \n",
					bvsr.BestBlock, vs.EndHeight)
				time.Sleep(sleepInterval)
			}
			if !vs.Approved {
				return fmt.Errorf("First submission approved? %v, want true",
					vs.Approved)
			}
			fmt.Printf("  First submission approved successfully\n")
		}
	}

	// Logout
	fmt.Printf("  Logout\n")
	lc = shared.LogoutCmd{}
	err = lc.Execute(nil)
	if err != nil {
		return err
	}

	// Websockets
	fmt.Printf("Running websocket routes\n")

	// Websocket - unauthenticated ping
	fmt.Printf("  Websocket: unauthenticated ping: ")
	sc := SubscribeCmd{
		Close: true,
	}
	err = sc.Execute([]string{"ping"})
	if err != nil {
		return err
	}

	// Login with user
	fmt.Printf("  Login user\n")
	err = login(user.email, user.password)
	if err != nil {
		return err
	}

	// Websocket - authenticated ping
	fmt.Printf("  Websocket: authenticated ping: ")
	err = sc.Execute([]string{"auth", "ping"})
	if err != nil {
		return err
	}

	// Logout
	fmt.Printf("  Logout\n")
	lc = shared.LogoutCmd{}
	err = lc.Execute(nil)
	if err != nil {
		return err
	}

	fmt.Printf("Test run successful!\n")
	return nil
}

const testRunHelpMsg = `testrun "adminusername" "adminpassword"

Run a series of tests on the politeiawww routes.  This command can only be run
on testnet.

Paywall: 
If the politeiawww paywall is enabled the test run will use the Decred tesnet
faucet to pay the user registration fee and to purchase proposal credits.  If
the politeiawww paywall has been disabled a warning will be logged and the
payments will be skipped.

Voting:
The test run will attempt to vote on a proposal.  If a dcrwallet instance is
not being run locally or if the wallet does not contain any eligible tickets
a warning will be logged and voting will be skipped.

Arguments:
1. adminusername   (string, required)   Admin username
2. adminpassword   (string, required)   Admin password
`
