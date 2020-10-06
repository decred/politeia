// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// helpCmd prints a detailed help message for the specified command.
type helpCmd struct {
	Args struct {
		Topic string `positional-arg-name:"topic"` // Topic to print help message for
	} `positional-args:"true"`
}

// Execute executes the help command.
func (cmd *helpCmd) Execute(args []string) error {
	if cmd.Args.Topic == "" {
		return fmt.Errorf("Specify a command to print a detailed help " +
			"message for.  Example: piwww help login")
	}

	switch cmd.Args.Topic {
	// Server commands
	case "version":
		fmt.Printf("%s\n", shared.VersionHelpMsg)
	case "policy":
		fmt.Printf("%s\n", policyHelpMsg)
	case "login":
		fmt.Printf("%s\n", shared.LoginHelpMsg)
	case "logout":
		fmt.Printf("%s\n", shared.LogoutHelpMsg)
	case "me":
		fmt.Printf("%s\n", shared.MeHelpMsg)

	// Proposal commands
	case "proposalnew":
		fmt.Printf("%s\n", proposalNewHelpMsg)
	case "proposaledit":
		fmt.Printf("%s\n", proposalEditHelpMsg)
	case "proposalsetstatus":
		fmt.Printf("%s\n", proposalSetStatusHelpMsg)
	case "proposals":
		fmt.Printf("%s\n", proposalsHelpMsg)
	case "proposalinventory":
		fmt.Printf("%s\n", proposalInventoryHelpMsg)

	// Comment commands
	case "commentnew":
		fmt.Printf("%s\n", commentNewHelpMsg)
	case "commentvote":
		fmt.Printf("%s\n", commentVoteHelpMsg)
	case "commentcensor":
		fmt.Printf("%s\n", commentCensorHelpMsg)
	case "comments":
		fmt.Printf("%s\n", commentsHelpMsg)
	case "commentvotes":
		fmt.Printf("%s\n", commentVotesHelpMsg)

	// Vote commands
	case "voteauthorize":
		fmt.Printf("%s\n", voteAuthorizeHelpMsg)
	case "votestart":
		fmt.Printf("%s\n", voteStartHelpMsg)
	case "votestartrunoff":
		fmt.Printf("%s\n", voteStartRunoffHelpMsg)
	case "voteballot":
		fmt.Printf("%s\n", voteInventoryHelpMsg)
	case "votes":
		fmt.Printf("%s\n", votesHelpMsg)
	case "voteresults":
		fmt.Printf("%s\n", voteResultsHelpMsg)
	case "votesummaries":
		fmt.Printf("%s\n", voteSummariesHelpMsg)
	case "voteinventory":
		fmt.Printf("%s\n", voteInventoryHelpMsg)

		// User commands
	case "usernew":
		fmt.Printf("%s\n", userNewHelpMsg)
	case "useredit":
		fmt.Printf("%s\n", userEditHelpMsg)
	case "userdetails":
		fmt.Printf("%s\n", userDetailsHelpMsg)
	case "userpaymentsrescan":
		fmt.Printf("%s\n", userPaymentsRescanHelpMsg)
	case "userpendingpayment":
		fmt.Printf("%s\n", userPendingPaymentHelpMsg)
	case "useremailverify":
		fmt.Printf("%s\n", userEmailVerifyHelpMsg)
	case "userpaymentverify":
		fmt.Printf("%s\n", userPaymentVerifyHelpMsg)
	case "userproposalpaywall":
		fmt.Printf("%s\n", userProposalPaywallHelpMsg)
	case "usermanage":
		fmt.Printf("%s\n", shared.UserManageHelpMsg)
	case "userkeyupdate":
		fmt.Printf("%s\n", shared.UserKeyUpdateHelpMsg)
	case "userverificationresend":
		fmt.Printf("%s\n", userVerificationResendHelpMsg)
	case "userusernamechange":
		fmt.Printf("%s\n", shared.UserUsernameChangeHelpMsg)
	case "userpasswordchange":
		fmt.Printf("%s\n", shared.UserPasswordChangeHelpMsg)
	case "userpasswordreset":
		fmt.Printf("%s\n", shared.UserPasswordResetHelpMsg)
	case "users":
		fmt.Printf("%s\n", shared.UsersHelpMsg)

	// Websocket commands
	case "subscribe":
		fmt.Printf("%s\n", subscribeHelpMsg)

	// Dev commands
	case "testrun":
		fmt.Printf("%s\n", testRunHelpMsg)
	case "sendfaucettx":
		fmt.Printf("%s\n", sendFaucetTxHelpMsg)

	default:
		fmt.Printf("invalid command: use 'piwww -h' " +
			"to view a list of valid commands\n")
	}

	return nil
}
