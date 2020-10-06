// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// testRunCmd performs a test run of all the politeiawww routes.
type testRunCmd struct {
	Args struct {
		AdminEmail    string `positional-arg-name:"adminemail"`
		AdminPassword string `positional-arg-name:"adminpassword"`
	} `positional-args:"true" required:"true"`
}

// user stores user details that are used throughout the test run.
type user struct {
	ID        string // UUID
	Email     string // Email
	Username  string // Username
	Password  string // Password (not hashed)
	PublicKey string // Public key of active identity
}

// login logs in the specified user.
func login(email, password string) error {
	lc := shared.LoginCmd{}
	lc.Args.Email = email
	lc.Args.Password = password
	return lc.Execute(nil)
}

// castVotes casts votes on a proposal with a given voteId. If it fails it
// returns the error and in case of dcrwallet connection error it returns
// true as first returned value
func castVotes(token string, voteID string) (bool, error) {
	/* var vc VoteCmd
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
	return false, err*/
	return false, nil
}

// Execute executes the test run command.
func (cmd *testRunCmd) Execute(args []string) error {
	/*
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
			user  user
			admin user
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

		user = user{
			ID:        lr.UserID,
			Email:     email,
			Username:  username,
			Password:  password,
			PublicKey: lr.PublicKey,
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
		ppdr, err := client.UserProposalPaywall()
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
	*/
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
