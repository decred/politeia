// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/decred/politeia/politeiad/api/v1/identity"
	pi "github.com/decred/politeia/politeiawww/api/pi/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
	"github.com/decred/politeia/util"
)

// testRunCmd performs a test run of all the politeiawww routes.
type testRunCmd struct {
	Args struct {
		AdminEmail    string `positional-arg-name:"adminemail"`
		AdminPassword string `positional-arg-name:"adminpassword"`
	} `positional-args:"true" required:"true"`
}

var (
	minPasswordLength int
	publicKey         string
)

// testUser stores user details that are used throughout the test run.
type testUser struct {
	ID             string // UUID
	Email          string // Email
	Username       string // Username
	Password       string // Password (not hashed)
	PublicKey      string // Public key of active identity
	PaywallAddress string // Paywall address
	PaywallAmount  uint64 // Paywall amount
}

// login logs in the specified user.
func login(u testUser) error {
	lc := shared.LoginCmd{}
	lc.Args.Email = u.Email
	lc.Args.Password = u.Password
	return lc.Execute(nil)
}

// logout logs out current logged in user.
func logout() error {
	// Logout admin
	lc := shared.LogoutCmd{}
	err := lc.Execute(nil)
	if err != nil {
		return err
	}
	return nil
}

// userRegistrationPayment ensures current logged in user has paid registration fee
func userRegistrationPayment() (www.UserRegistrationPaymentReply, error) {
	urvr, err := client.UserRegistrationPayment()
	if err != nil {
		return www.UserRegistrationPaymentReply{}, err
	}
	return *urvr, nil
}

// randomString generates a random string
func randomString(length int) (string, error) {
	b, err := util.Random(length)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// userNew creates a new user and returnes user's public key.
func userNew(email, password, username string) (*identity.FullIdentity, string, error) {
	fmt.Printf("  Creating user: %v\n", email)

	// Create user identity and save it to disk
	id, err := shared.NewIdentity()
	if err != nil {
		return nil, "", err
	}

	// Setup new user request
	nu := &www.NewUser{
		Email:     email,
		Username:  username,
		Password:  shared.DigestSHA3(password),
		PublicKey: hex.EncodeToString(id.Public.Key[:]),
	}
	nur, err := client.NewUser(nu)
	if err != nil {
		return nil, "", err
	}

	return id, nur.VerificationToken, nil
}

// userManage sends a usermanage command
func userManage(userID, action, reason string) error {
	muc := shared.UserManageCmd{}
	muc.Args.UserID = userID
	muc.Args.Action = action
	muc.Args.Reason = reason
	err := muc.Execute(nil)
	if err != nil {
		return err
	}
	return nil
}

// userEmailVerify verifies user's email
func userEmailVerify(vt, email string, id *identity.FullIdentity) error {
	fmt.Printf("  Verify user's email\n")
	sig := id.SignMessage([]byte(vt))
	_, err := client.VerifyNewUser(
		&www.VerifyNewUser{
			Email:             email,
			VerificationToken: vt,
			Signature:         hex.EncodeToString(sig[:]),
		})
	if err != nil {
		return err
	}
	return nil
}

// userCreate creates new user & returns the created testUser
func userCreate() (*testUser, *identity.FullIdentity, string, error) {
	// Create user and verify email
	randomStr, err := randomString(minPasswordLength)
	if err != nil {
		return nil, nil, "", err
	}
	email := randomStr + "@example.com"
	username := randomStr
	password := randomStr
	id, vt, err := userNew(email, password, username)
	if err != nil {
		return nil, nil, "", err
	}

	return &testUser{
		Email:    email,
		Username: username,
		Password: password,
	}, id, vt, nil
}

// testUser tests piwww user specific routes.
func testUserRoutes(admin testUser) error {
	// sleepInterval is the time to wait in between requests
	// when polling politeiawww for paywall tx confirmations.
	const sleepInterval = 15 * time.Second

	var (
		// paywallEnabled represents whether the politeiawww paywall
		// has been enabled.  A disabled paywall will have a paywall
		// address of "" and a paywall amount of 0.
		paywallEnabled bool

		// numCredits is the number of proposal credits that will be
		// purchased using the testnet faucet.
		numCredits = 1

		// Test user
		user *testUser
	)
	// Run user routes.
	fmt.Printf("Running user routes\n")

	// Create new user
	user, id, _, err := userCreate()
	if err != nil {
		return err
	}

	// Resed email verification
	fmt.Printf("  Resend email Verification\n")
	rvr, err := client.ResendVerification(www.ResendVerification{
		PublicKey: hex.EncodeToString(id.Public.Key[:]),
		Email:     user.Email,
	})
	if err != nil {
		return err
	}

	// Verify email
	err = userEmailVerify(rvr.VerificationToken, user.Email, id)
	if err != nil {
		return err
	}

	// Login and store user details
	fmt.Printf("  Login user\n")
	lr, err := client.Login(&www.Login{
		Email:    user.Email,
		Password: shared.DigestSHA3(user.Password),
	})
	if err != nil {
		return err
	}

	user.PublicKey = lr.PublicKey
	user.PaywallAddress = lr.PaywallAddress
	user.ID = lr.UserID
	user.PaywallAmount = lr.PaywallAmount

	// Logout user
	fmt.Printf("  Logout user\n")
	err = logout()
	if err != nil {
		return err
	}

	// Update user key
	err = userKeyUpdate(*user)
	if err != nil {
		return err
	}

	// Log back in
	err = login(*user)
	if err != nil {
		return err
	}

	// Me
	fmt.Printf("  Me\n")
	_, err = client.Me()
	if err != nil {
		return err
	}

	// Edit user
	fmt.Printf("  Edit user\n")
	var n uint64 = 1 << 0
	_, err = client.EditUser(
		&www.EditUser{
			EmailNotifications: &n,
		})
	if err != nil {
		return err
	}

	// Change username
	fmt.Printf("  Change username\n")
	randomStr, err := randomString(minPasswordLength)
	if err != nil {
		return err
	}
	cuc := shared.UserUsernameChangeCmd{}
	cuc.Args.Password = user.Password
	cuc.Args.NewUsername = randomStr
	err = cuc.Execute(nil)
	if err != nil {
		return err
	}
	user.Username = cuc.Args.NewUsername

	// Change password
	fmt.Printf("  Change password\n")
	cpc := shared.UserPasswordChangeCmd{}
	cpc.Args.Password = user.Password
	cpc.Args.NewPassword = randomStr
	err = cpc.Execute(nil)
	if err != nil {
		return err
	}
	user.Password = cpc.Args.NewPassword

	// Reset user password
	fmt.Printf("  Reset user password\n")
	// Generate new random password
	randomStr, err = randomString(minPasswordLength)
	if err != nil {
		return err
	}
	uprc := shared.UserPasswordResetCmd{}
	uprc.Args.Email = user.Email
	uprc.Args.Username = user.Username
	uprc.Args.NewPassword = randomStr
	err = uprc.Execute(nil)
	if err != nil {
		return err
	}
	user.Password = randomStr

	// Login with new password
	err = login(*user)
	if err != nil {
		return err
	}

	// Check if paywall is enabled.  Paywall address and paywall
	// amount will be zero values if paywall has been disabled.
	if user.PaywallAddress != "" && user.PaywallAmount != 0 {
		paywallEnabled = true
	} else {
		fmt.Printf("WARNING: politeiawww paywall is disabled\n")
	}

	// Pay user registration fee
	if paywallEnabled {
		// Pay user registration fee
		fmt.Printf("  Paying user registration fee\n")
		txID, err := util.PayWithTestnetFaucet(context.Background(),
			cfg.FaucetHost, user.PaywallAddress, user.PaywallAmount, "")
		if err != nil {
			return err
		}

		dcr := float64(user.PaywallAmount) / 1e8
		fmt.Printf("  Paid %v DCR to %v with txID %v\n",
			dcr, user.PaywallAddress, txID)
	}

	// Wait for user registration payment confirmations
	// If the paywall has been disable this will be marked
	// as true. If the paywall has been enabled this will
	// be true once the payment tx has the required number
	// of confirmations.
	upvr, err := userRegistrationPayment()
	if err != nil {
		return err
	}
	for !upvr.HasPaid {
		upvr, err = userRegistrationPayment()
		if err != nil {
			return err
		}

		fmt.Printf("  Verify user payment: waiting for tx confirmations...\n")
		time.Sleep(sleepInterval)
	}

	// Purchase proposal credits
	fmt.Printf("  User proposal paywall\n")
	ppdr, err := client.UserProposalPaywall()
	if err != nil {
		return err
	}

	if paywallEnabled {
		// Purchase proposal credits
		fmt.Printf("  Purchasing %v proposal credits\n", numCredits)

		atoms := ppdr.CreditPrice * uint64(numCredits)
		txID, err := util.PayWithTestnetFaucet(context.Background(),
			cfg.FaucetHost, ppdr.PaywallAddress, atoms, "")
		if err != nil {
			return err
		}

		fmt.Printf("  Paid %v DCR to %v with txID %v\n",
			float64(atoms)/1e8, user.PaywallAddress, txID)
	}

	// Keep track of when the pending proposal credit payment
	// receives the required number of confirmations.
	for {
		pppr, err := client.UserProposalPaywallTx()
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

	// Fetch user by usernam
	fmt.Printf("  Fetch user by username\n")
	usersr, err := client.Users(&www.Users{
		Username: user.Username,
	})
	if err != nil {
		return err
	}
	if usersr.TotalMatches != 1 {
		return fmt.Errorf("Wrong matching users: want %v, got %v", 1,
			usersr.TotalMatches)
	}

	// Fetch user by public key
	fmt.Printf("  Fetch user by public key\n")
	usersr, err = client.Users(&www.Users{
		PublicKey: user.PublicKey,
	})
	if err != nil {
		return err
	}
	if usersr.TotalMatches != 1 {
		return fmt.Errorf("Wrong matching users: want %v, got %v", 1,
			usersr.TotalMatches)
	}

	// User details
	fmt.Printf("  User details\n")
	udc := userDetailsCmd{}
	udc.Args.UserID = user.ID
	err = udc.Execute(nil)
	if err != nil {
		return err
	}

	// Login admin
	fmt.Printf("  Login as admin\n")
	err = login(admin)
	if err != nil {
		return err
	}

	// Rescan user credits
	fmt.Printf("  Rescan user credits\n")
	upayrc := userPaymentsRescanCmd{}
	upayrc.Args.UserID = user.ID
	err = upayrc.Execute(nil)
	if err != nil {
		return err
	}

	// Deactivate user
	fmt.Printf("  Deactivate user\n")
	const userDeactivateAction = "deactivate"
	err = userManage(user.ID, userDeactivateAction, "testing")
	if err != nil {
		return err
	}

	// Reactivate user
	fmt.Printf("  Reactivate user\n")
	const userReactivateAction = "reactivate"
	err = userManage(user.ID, userReactivateAction, "testing")
	if err != nil {
		return err
	}

	// Fetch user by email
	fmt.Printf("  Fetch user by email\n")
	usersr, err = client.Users(&www.Users{
		Email: user.Email,
	})
	if err != nil {
		return err
	}
	if usersr.TotalMatches != 1 {
		return fmt.Errorf("Wrong matching users: want %v, got %v", 1,
			usersr.TotalMatches)
	}

	return nil
}

// proposalNewNormal is a wrapper func which creates a proposal by calling
// proposalNew
func proposalNewNormal() (*pi.ProposalNew, error) {
	return proposalNew(false, "")
}

// proposalNew returns a NewProposal object contains randonly generated
// markdown text and a signature from the logged in user. If given `rfp` bool
// is true it creates an RFP. If given `linkto` it creates a RFP submission.
func proposalNew(rfp bool, linkto string) (*pi.ProposalNew, error) {
	md, err := createMDFile()
	if err != nil {
		return nil, fmt.Errorf("create MD file: %v", err)
	}
	files := []pi.File{*md}

	pm := www.ProposalMetadata{
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
	metadata := []pi.Metadata{
		{
			Digest:  hex.EncodeToString(util.Digest(pmb)),
			Hint:    pi.HintProposalMetadata,
			Payload: base64.StdEncoding.EncodeToString(pmb),
		},
	}

	sig, err := signedMerkleRoot(files, metadata, cfg.Identity)
	if err != nil {
		return nil, fmt.Errorf("sign merkle root: %v", err)
	}

	return &pi.ProposalNew{
		Files:     files,
		Metadata:  metadata,
		PublicKey: hex.EncodeToString(cfg.Identity.Public.Key[:]),
		Signature: sig,
	}, nil
}

// submitNewPropsal submits new proposal and verifies it
//
// This function returns with the user logged out
func submitNewProposal(user testUser) (string, error) {
	// Login user
	err := login(user)
	if err != nil {
		return "", err
	}

	fmt.Printf("  New proposal\n")
	pn, err := proposalNewNormal()
	if err != nil {
		return "", err
	}
	pnr, err := client.ProposalNew(*pn)
	if err != nil {
		return "", err
	}

	// Verify proposal censorship record
	pr := &pi.ProposalRecord{
		Files:            pn.Files,
		Metadata:         pn.Metadata,
		PublicKey:        pn.PublicKey,
		Signature:        pn.Signature,
		CensorshipRecord: pnr.Proposal.CensorshipRecord,
	}
	err = verifyProposal(*pr, publicKey)
	if err != nil {
		return "", fmt.Errorf("verify proposal failed: %v", err)
	}

	token := pr.CensorshipRecord.Token
	fmt.Printf("  Proposal submitted: %v\n", token)

	// Logout
	err = logout()
	if err != nil {
		return "", err
	}

	return token, nil
}

// proposalSetStatus calls proposal set status command
//
// This function returns with user logged out
func proposalSetStatus(user testUser, state pi.PropStateT, token, reason string, status pi.PropStatusT) error {
	// Login user
	err := login(user)
	if err != nil {
		return err
	}

	pssc := proposalStatusSetCmd{
		Unvetted: state == pi.PropStateUnvetted,
	}
	pssc.Args.Token = token
	pssc.Args.Status = strconv.Itoa(int(status))
	pssc.Args.Reason = reason
	err = pssc.Execute(nil)
	if err != nil {
		return err
	}

	return logout()
}

// proposalCensor censors given proposal
//
// This function returns with user logged out
func proposalCensor(user testUser, state pi.PropStateT, token, reason string) error {
	err := proposalSetStatus(user, state, token, reason, pi.PropStatusCensored)
	if err != nil {
		return err
	}
	return nil
}

// proposalPublic makes given proposal public
//
// This function returns with user logged out
func proposalPublic(user testUser, token string) error {
	err := proposalSetStatus(user, pi.PropStateUnvetted, token, "", pi.PropStatusPublic)
	if err != nil {
		return err
	}
	return nil
}

// proposalAbandon abandons given proposal
//
// This function returns with user logged out
func proposalAbandon(user testUser, token, reason string) error {
	err := proposalSetStatus(user, pi.PropStateVetted, token, reason,
		pi.PropStatusAbandoned)
	if err != nil {
		return err
	}
	return nil
}

// proposalEdit edits given proposal
//
// This function returns with user logged out
func proposalEdit(user testUser, state pi.PropStateT, token string) error {
	// Login user
	err := login(user)
	if err != nil {
		return err
	}

	epc := proposalEditCmd{
		Random:   true,
		Unvetted: state == pi.PropStateUnvetted,
	}
	epc.Args.Token = token
	err = epc.Execute(nil)
	if err != nil {
		return err
	}

	// Logout
	return logout()
}

// proposals fetchs requested proposals and verifies returned map length
//
// This function returns with user logged out
func proposals(user testUser, ps pi.Proposals) (map[string]pi.ProposalRecord, error) {
	// Login user
	err := login(user)
	if err != nil {
		return nil, err
	}
	psr, err := client.Proposals(ps)
	if err != nil {
		return nil, err
	}

	if len(psr.Proposals) != len(ps.Requests) {
		return nil, fmt.Errorf("Received wrong number of proposals: want %v,"+
			" got %v", len(ps.Requests), len(psr.Proposals))
	}

	// Logout
	err = logout()
	if err != nil {
		return nil, err
	}

	return psr.Proposals, nil
}

// userKeyUpdate updates user's key
//
// This function returns with the user logged out
func userKeyUpdate(user testUser) error {
	// Login user
	err := login(user)
	if err != nil {
		return err
	}

	fmt.Printf("  Update user key\n")
	ukuc := shared.UserKeyUpdateCmd{}
	err = ukuc.Execute(nil)
	if err != nil {
		return err
	}

	return logout()
}

// testProposalRoutes tests the propsal routes
func testProposalRoutes(admin testUser) error {
	// Run proposal routes.
	fmt.Printf("Running proposal routes\n")

	// Create test user
	fmt.Printf("Creating test user\n")
	user, id, vt, err := userCreate()
	if err != nil {
		return err
	}

	// Verify email
	err = userEmailVerify(vt, user.Email, id)
	if err != nil {
		return err
	}

	// Update user key
	err = userKeyUpdate(*user)
	if err != nil {
		return err
	}

	// Submit new proposal
	censoredToken1, err := submitNewProposal(*user)
	if err != nil {
		return err
	}

	// Edit unvetted proposal
	fmt.Printf("  Edit unvetted proposal\n")
	err = proposalEdit(*user, pi.PropStateUnvetted, censoredToken1)
	if err != nil {
		return err
	}

	// Censor unvetted proposal
	fmt.Printf("  Censor unvetted proposal\n")
	const reason = "because!"
	err = proposalCensor(admin, pi.PropStateUnvetted, censoredToken1, reason)
	if err != nil {
		return err
	}

	// Submit new proposal
	censoredToken2, err := submitNewProposal(*user)
	if err != nil {
		return err
	}

	// Make the proposal public
	fmt.Printf("  Set proposal status: public\n")
	err = proposalPublic(admin, censoredToken2)
	if err != nil {
		return err
	}

	// Edit vetted proposal
	fmt.Printf("  Edit vetted proposal\n")
	err = proposalEdit(*user, pi.PropStateVetted, censoredToken2)
	if err != nil {
		return err
	}

	// Censor public proposal
	fmt.Printf("  Censor public proposal\n")
	err = proposalCensor(admin, pi.PropStateVetted, censoredToken2, reason)
	if err != nil {
		return err
	}

	// Submit new proposal
	abandonedToken, err := submitNewProposal(*user)
	if err != nil {
		return err
	}

	// Make the proposal public
	fmt.Printf("  Set proposal status: public\n")
	err = proposalPublic(admin, abandonedToken)
	if err != nil {
		return err
	}

	// Abandon public proposal
	fmt.Printf("  Abandon proposal\n")
	err = proposalAbandon(admin, abandonedToken, reason)
	if err != nil {
		return err
	}

	// Submit new proposal and leave it unvetted
	unvettedToken, err := submitNewProposal(*user)
	if err != nil {
		return err
	}

	// Submit new proposal and make it public
	publicToken, err := submitNewProposal(*user)
	if err != nil {
		return err
	}

	// Make the proposal public
	fmt.Printf("  Set proposal status: public\n")
	err = proposalPublic(admin, publicToken)
	if err != nil {
		return err
	}

	// Login admin
	err = login(admin)
	if err != nil {
		return err
	}

	// Proposal inventory
	var publicExists, censoredExists, abandonedExists, unvettedExists bool
	fmt.Printf("  Proposal inventory\n")
	pir, err := client.ProposalInventory(pi.ProposalInventory{})
	if err != nil {
		return err
	}
	// Vetted proposals map
	vettedProps := pir.Vetted

	// Ensure public proposal token received
	publicProps, ok := vettedProps[pi.PropStatus[pi.PropStatusPublic]]
	if !ok {
		return fmt.Errorf("No public proposals returned")
	}
	for _, t := range publicProps {
		if t == publicToken {
			publicExists = true
		}
	}
	if !publicExists {
		return fmt.Errorf("Proposal inventory missing public proposal: %v",
			publicToken)
	}

	// Ensure vetted censored proposal token received
	vettedCensored, ok := vettedProps[pi.PropStatus[pi.PropStatusCensored]]
	if !ok {
		return fmt.Errorf("No vetted censrored proposals returned")
	}
	for _, t := range vettedCensored {
		if t == censoredToken2 {
			censoredExists = true
		}
	}
	if !censoredExists {
		return fmt.Errorf("Proposal inventory missing vetted censored proposal"+
			": %v",
			censoredToken1)
	}

	// Ensure abandoned proposal token received
	abandonedProps, ok := vettedProps[pi.PropStatus[pi.PropStatusAbandoned]]
	if !ok {
		return fmt.Errorf("No abandoned proposals returned")
	}
	for _, t := range abandonedProps {
		if t == abandonedToken {
			abandonedExists = true
		}
	}
	if !abandonedExists {
		return fmt.Errorf("Proposal inventory missing abandoned proposal: %v",
			abandonedToken)
	}

	// Unvetted propsoals
	unvettedProps := pir.Unvetted

	// Ensure unvetted proposal token received
	unreviewedProps, ok := unvettedProps[pi.PropStatus[pi.PropStatusUnreviewed]]
	if !ok {
		return fmt.Errorf("No unreviewed proposals returned")
	}
	for _, t := range unreviewedProps {
		if t == unvettedToken {
			unvettedExists = true
		}
	}
	if !unvettedExists {
		return fmt.Errorf("Proposal inventory missing unvetted proposal: %v",
			unvettedToken)
	}

	// Ensure unvetted censored proposal token received
	unvettedCensored, ok := unvettedProps["censored"]
	if !ok {
		return fmt.Errorf("No unvetted censrored proposals returned")
	}
	for _, t := range unvettedCensored {
		if t == censoredToken1 {
			censoredExists = true
		}
	}
	if !censoredExists {
		return fmt.Errorf("Proposal inventory missing unvetted censored proposal"+
			": %v",
			censoredToken1)
	}

	// Get vetted proposals
	fmt.Printf("  Fetch vetted proposals\n")
	props, err := proposals(*user, pi.Proposals{
		State: pi.PropStateVetted,
		Requests: []pi.ProposalRequest{
			{
				Token: publicToken,
			},
			{
				Token: abandonedToken,
			},
		},
	})
	if err != nil {
		return err
	}
	_, publicExists = props[publicToken]
	_, abandonedExists = props[abandonedToken]
	if !publicExists || !abandonedExists {
		return fmt.Errorf("Proposal batch missing requested vetted proposals")
	}

	// Get vetted proposals with short tokens
	fmt.Printf("  Fetch vetted proposals with short tokens\n")
	shortPublicToken := publicToken[0:7]
	shortAbandonedToken := abandonedToken[0:7]
	props, err = proposals(*user, pi.Proposals{
		State: pi.PropStateVetted,
		Requests: []pi.ProposalRequest{
			{
				Token: shortPublicToken,
			},
			{
				Token: shortAbandonedToken,
			},
		},
	})
	if err != nil {
		return err
	}
	_, publicExists = props[publicToken]
	_, abandonedExists = props[abandonedToken]
	if !publicExists || !abandonedExists {
		return fmt.Errorf("Proposal batch missing requested vetted proposals")
	}

	// Get unvetted proposal
	fmt.Printf("  Fetch unvetted proposal\n")
	props, err = proposals(*user, pi.Proposals{
		State: pi.PropStateUnvetted,
		Requests: []pi.ProposalRequest{
			{
				Token: unvettedToken,
			},
		},
	})
	if err != nil {
		return err
	}
	_, unvettedExists = props[unvettedToken]
	if !unvettedExists {
		return fmt.Errorf("Proposal batch missing requested unvetted proposals")
	}

	// Get unvetted proposal with short token
	fmt.Printf("  Fetch unvetted proposal with short token\n")
	shortUnvettedToken := unvettedToken[0:7]
	props, err = proposals(*user, pi.Proposals{
		State: pi.PropStateUnvetted,
		Requests: []pi.ProposalRequest{
			{
				Token: shortUnvettedToken,
			},
		},
	})
	if err != nil {
		return err
	}
	_, unvettedExists = props[unvettedToken]
	if !unvettedExists {
		return fmt.Errorf("Proposal batch missing requested unvetted proposals")
	}

	return nil
}

// Execute executes the test run command.
func (cmd *testRunCmd) Execute(args []string) error {
	// Suppress output from cli commands
	cfg.Silent = true

	fmt.Printf("Running pre-testrun validation\n")

	// Policy
	fmt.Printf("  Policy\n")
	policy, err := client.Policy()
	if err != nil {
		return err
	}
	minPasswordLength = int(policy.MinPasswordLength)

	// Version (CSRF tokens)
	fmt.Printf("  Version\n")
	version, err := client.Version()
	if err != nil {
		return err
	}
	publicKey = version.PubKey

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

	// Ensure admin credentials are valid
	admin := testUser{
		Email:    cmd.Args.AdminEmail,
		Password: cmd.Args.AdminPassword,
	}
	err = login(admin)
	if err != nil {
		return err
	}

	// Ensure admin paid registration free
	urpr, err := userRegistrationPayment()
	if err != nil {
		return err
	}
	if !urpr.HasPaid {
		return fmt.Errorf("admin has not paid registration fee")
	}

	// Logout admin
	err = logout()
	if err != nil {
		return err
	}

	// Test user routes
	err = testUserRoutes(admin)
	if err != nil {
		return err
	}

	// Test proposal routes
	err = testProposalRoutes(admin)
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
