// Copyright (c) 2017-2021 The Decred developers
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
		Command string `positional-arg-name:"command"`
	} `positional-args:"true" required:"true"`
}

// Execute executes the helpCmd command.
//
// This function satisfies the go-flags Commander interface.
func (cmd *helpCmd) Execute(args []string) error {
	switch cmd.Args.Command {
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
	case "proposalpolicy":
		fmt.Printf("%s\n", proposalPolicyHelpMsg)
	case "proposalnew":
		fmt.Printf("%s\n", proposalNewHelpMsg)
	case "proposaledit":
		fmt.Printf("%s\n", proposalEditHelpMsg)
	case "proposalstatusset":
		fmt.Printf("%s\n", proposalSetStatusHelpMsg)
	case "proposals":
		fmt.Printf("%s\n", proposalsHelpMsg)
	case "proposalinventory":
		fmt.Printf("%s\n", proposalInvHelpMsg)

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
	case "votepolicy":
		fmt.Printf("%s\n", votePolicyHelpMsg)
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
	case "useremailverify":
		fmt.Printf("%s\n", userEmailVerifyHelpMsg)
	case "userregistrationpayment":
		fmt.Printf("%s\n", userRegistrationPaymentHelpMsg)
	case "userproposalpaywall":
		fmt.Printf("%s\n", userProposalPaywallHelpMsg)
	case "userproposalpaywalltx":
		fmt.Printf("%s\n", userProposalPaywallTxHelpMsg)
	case "userproposalcredits":
		fmt.Printf("%s\n", userProposalCreditsHelpMsg)
	case "userpaymentsrescan":
		fmt.Printf("%s\n", userPaymentsRescanHelpMsg)
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
		fmt.Printf("invalid command: use the -h,--help flag to view the " +
			"full list of valid commands\n")
	}

	return nil
}
