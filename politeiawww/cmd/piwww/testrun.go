// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/decred/politeia/politeiad/api/v1/identity"
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

// testUser stores user details that are used throughout the test run.
type testUser struct {
	ID        string // UUID
	Email     string // Email
	Username  string // Username
	Password  string // Password (not hashed)
	PublicKey string // Public key of active identity
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
func userNew(email, password, username string) (*identity.FullIdentity, error) {
	fmt.Printf("  Creating user: %v\n", email)

	// Create user identity and save it to disk
	id, err := shared.NewIdentity()
	if err != nil {
		return nil, err
	}

	// Setup new user request
	nu := &www.NewUser{
		Email:     email,
		Username:  username,
		Password:  shared.DigestSHA3(password),
		PublicKey: hex.EncodeToString(id.Public.Key[:]),
	}
	_, err = client.NewUser(nu)
	if err != nil {
		return nil, err
	}

	return id, nil
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

// testUser tests piwww user specific routes.
func testUserRoutes(admin testUser, minPasswordLength int) error {
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

		// Test users
		user testUser
	)
	// Run user routes.
	fmt.Printf("Running user routes\n")

	// Create user and verify email
	randomStr, err := randomString(minPasswordLength)
	if err != nil {
		return err
	}
	email := randomStr + "@example.com"
	username := randomStr
	password := randomStr
	id, err := userNew(email, password, username)
	if err != nil {
		return err
	}

	// Resed email verification
	fmt.Printf("  Resend email Verification\n")
	rvr, err := client.ResendVerification(www.ResendVerification{
		PublicKey: hex.EncodeToString(id.Public.Key[:]),
		Email:     email,
	})
	if err != nil {
		return err
	}

	// Verify email
	fmt.Printf("  Verify user's email\n")
	vt := rvr.VerificationToken
	sig := id.SignMessage([]byte(vt))
	_, err = client.VerifyNewUser(
		&www.VerifyNewUser{
			Email:             email,
			VerificationToken: vt,
			Signature:         hex.EncodeToString(sig[:]),
		})
	if err != nil {
		return err
	}

	// Login and store user details
	fmt.Printf("  Login user\n")
	lr, err := client.Login(&www.Login{
		Email:    email,
		Password: shared.DigestSHA3(password),
	})
	if err != nil {
		return err
	}

	user = testUser{
		ID:        lr.UserID,
		Email:     email,
		Username:  username,
		Password:  password,
		PublicKey: lr.PublicKey,
	}

	// Logout user
	fmt.Printf("  Logout user\n")
	err = logout()
	if err != nil {
		return err
	}

	// Log back in
	err = login(user)
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

	// Update user key
	fmt.Printf("  Update user key\n")
	ukuc := shared.UserKeyUpdateCmd{}
	err = ukuc.Execute(nil)
	if err != nil {
		return err
	}

	// Change username
	fmt.Printf("  Change username\n")
	randomStr, err = randomString(minPasswordLength)
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
	err = login(user)
	if err != nil {
		return err
	}
	// Check if paywall is enabled.  Paywall address and paywall
	// amount will be zero values if paywall has been disabled.
	if lr.PaywallAddress != "" && lr.PaywallAmount != 0 {
		paywallEnabled = true
	} else {
		fmt.Printf("WARNING: politeiawww paywall is disabled\n")
	}

	// Pay user registration fee
	if paywallEnabled {
		// Pay user registration fee
		fmt.Printf("  Paying user registration fee\n")
		txID, err := util.PayWithTestnetFaucet(context.Background(),
			cfg.FaucetHost, lr.PaywallAddress, lr.PaywallAmount, "")
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
			float64(atoms)/1e8, lr.PaywallAddress, txID)
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

// Execute executes the test run command.
func (cmd *testRunCmd) Execute(args []string) error {

	const (
		// Comment actions
		commentActionUpvote   = "upvote"
		commentActionDownvote = "downvote"
	)

	// Suppress output from cli commands
	cfg.Silent = true

	fmt.Printf("Running pre-testrun validation\n")

	// Policy
	fmt.Printf("  Policy\n")
	policy, err := client.Policy()
	if err != nil {
		return err
	}

	// Version (CSRF tokens)
	fmt.Printf("  Version\n")
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
	err = testUserRoutes(admin, int(policy.MinPasswordLength))
	if err != nil {
		return err
	}

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
