// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// HelpCmd prints a detailed help message for the specified command.
type HelpCmd struct {
	Args struct {
		Topic string `positional-arg-name:"topic"` // Topic to print help message for
	} `positional-args:"true"`
}

// Execute executes the help command.
func (cmd *HelpCmd) Execute(args []string) error {
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

	// User commands
	case "login":
		fmt.Printf("%s\n", shared.LoginHelpMsg)
	case "logout":
		fmt.Printf("%s\n", shared.LogoutHelpMsg)
	case "newuser":
		fmt.Printf("%s\n", newUserHelpMsg)
	case "changepassword":
		fmt.Printf("%s\n", shared.ChangePasswordHelpMsg)
	case "changeusername":
		fmt.Printf("%s\n", shared.ChangeUsernameHelpMsg)
	case "userdetails":
		fmt.Printf("%s\n", userDetailsHelpMsg)
	case "manageuser":
		fmt.Printf("%s\n", shared.ManageUserHelpMsg)
	case "users":
		fmt.Printf("%s\n", shared.UsersHelpMsg)
	case "verifyuseremail":
		fmt.Printf("%s\n", verifyUserEmailHelpMsg)
	case "edituser":
		fmt.Printf("%s\n", editUserHelpMsg)
	case "me":
		fmt.Printf("%s\n", shared.MeHelpMsg)
	case "resetpassword":
		fmt.Printf("%s\n", shared.ResetPasswordHelpMsg)
	case "updateuserkey":
		fmt.Printf("%s\n", shared.UpdateUserKeyHelpMsg)
	case "userpendingpayment":
		fmt.Printf("%s\n", userPendingPaymentHelpMsg)
	case "proposalpaywall":
		fmt.Printf("%s\n", proposalPaywallHelpMsg)
	case "rescanuserpayments":
		fmt.Printf("%s\n", rescanUserPaymentsHelpMsg)
	case "verifyuserpayment":
		fmt.Printf("%s\n", verifyUserPaymentHelpMsg)
	case "resendverification":
		fmt.Printf("%s\n", resendVerificationHelpMsg)

	// Proposal commands
	case "proposalnew":
		fmt.Printf("%s\n", proposalNewHelpMsg)
	case "proposaledit":
		fmt.Printf("%s\n", proposalEditHelpMsg)
	case "proposalsetstatus":
		fmt.Printf("%s\n", proposalSetStatusHelpMsg)

	case "proposaldetails":
		fmt.Printf("%s\n", proposalDetailsHelpMsg)
	case "userproposals":
		fmt.Printf("%s\n", userProposalsHelpMsg)
	case "vettedproposals":
		fmt.Printf("%s\n", vettedProposalsHelpMsg)
	case "batchproposals":
		fmt.Printf("%s\n", shared.BatchProposalsHelpMsg)

	// Comment commands
	case "commentnew":
		fmt.Printf("%s\n", commentNewHelpMsg)
	case "proposalcomments":
		fmt.Printf("%s\n", proposalCommentsHelpMsg)
	case "commentcensor":
		fmt.Printf("%s\n", commentCensorHelpMsg)
	case "commentvote":
		fmt.Printf("%s\n", commentVoteHelpMsg)
	case "userlikecomments":
		fmt.Printf("%s\n", userLikeCommentsHelpMsg)

	// Vote commands
	case "authorizevote":
		fmt.Printf("%s\n", authorizeVoteHelpMsg)
	case "startvote":
		fmt.Printf("%s\n", startVoteHelpMsg)
	case "startvoterunoff":
		fmt.Printf("%s\n", startVoteRunoffHelpMsg)
	case "voteresults":
		fmt.Printf("%s\n", voteResultsHelpMsg)
	case "activevotes":
		fmt.Printf("%s\n", activeVotesHelpMsg)
	case "votestatus":
		fmt.Printf("%s\n", voteStatusHelpMsg)
	case "votestatuses":
		fmt.Printf("%s\n", voteStatusesHelpMsg)
	case "batchvotesummary":
		fmt.Printf("%s\n", batchVoteSummaryHelpMsg)
	case "votedetails":
		fmt.Printf("%s\n", voteDetailsHelpMsg)

	// Websocket commands
	case "subscribe":
		fmt.Printf("%s\n", subscribeHelpMsg)

	// Other commands
	case "testrun":
		fmt.Printf("%s\n", testRunHelpMsg)
	case "sendfaucettx":
		fmt.Printf("%s\n", sendFaucetTxHelpMsg)

	// politeiavoter mock commands
	case "inventory":
		fmt.Printf("%s\n", inventoryHelpMsg)
	case "tally":
		fmt.Printf("%s\n", tallyHelpMsg)
	case "vote":
		fmt.Printf("%s\n", voteHelpMsg)

	default:
		fmt.Printf("invalid command: use 'piwww -h' " +
			"to view a list of valid commands\n")
	}

	return nil
}
