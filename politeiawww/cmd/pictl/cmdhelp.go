// Copyright (c) 2017-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/decred/politeia/politeiawww/cmd/shared"
)

// cmdHelp prints a detailed help message for the specified command.
type cmdHelp struct {
	Args struct {
		Command string `positional-arg-name:"command"`
	} `positional-args:"true" required:"true"`
}

// Execute executes the cmdHelp command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdHelp) Execute(args []string) error {
	switch c.Args.Command {
	// Basic commands
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

		// Proposal commands
	case "proposalpolicy":
		fmt.Printf("%s\n", proposalPolicyHelpMsg)
	case "proposalnew":
		fmt.Printf("%s\n", proposalNewHelpMsg)
	case "proposaledit":
		fmt.Printf("%s\n", proposalEditHelpMsg)
	case "proposalsetstatus":
		fmt.Printf("%s\n", proposalSetStatusHelpMsg)
	case "proposaldetails":
		fmt.Printf("%s\n", proposalDetailsHelpMsg)
	case "proposaltimestamps":
		fmt.Printf("%s\n", proposalTimestampsHelpMsg)
	case "proposals":
		fmt.Printf("%s\n", proposalsHelpMsg)
	case "proposalinv":
		fmt.Printf("%s\n", proposalInvHelpMsg)
	case "proposalinvordered":
		fmt.Printf("%s\n", proposalInvOrderedHelpMsg)
	case "userproposals":
		fmt.Printf("%s\n", userProposalsHelpMsg)

		// Comment commands
	case "commentpolicy":
		fmt.Printf("%s\n", commentPolicyHelpMsg)
	case "commentnew":
		fmt.Printf("%s\n", commentNewHelpMsg)
	case "commentvote":
		fmt.Printf("%s\n", commentVoteHelpMsg)
	case "commentcensor":
		fmt.Printf("%s\n", commentCensorHelpMsg)
	case "commentcount":
		fmt.Printf("%s\n", commentCountHelpMsg)
	case "comments":
		fmt.Printf("%s\n", commentsHelpMsg)
	case "commentvotes":
		fmt.Printf("%s\n", commentVotesHelpMsg)
	case "commenttimestamps":
		fmt.Printf("%s\n", commentTimestampsHelpMsg)

	// Vote commands
	case "votepolicy":
		fmt.Printf("%s\n", votePolicyHelpMsg)
	case "voteauthorize":
		fmt.Printf("%s\n", voteAuthorizeHelpMsg)
	case "votestart":
		fmt.Printf("%s\n", voteStartHelpMsg)
	case "castballot":
		fmt.Printf("%s\n", castBallotHelpMsg)
	case "votedetails":
		fmt.Printf("%s\n", voteDetailsHelpMsg)
	case "voteresults":
		fmt.Printf("%s\n", voteResultsHelpMsg)
	case "votesummaries":
		fmt.Printf("%s\n", voteSummariesHelpMsg)
	case "votesubmissions":
		fmt.Printf("%s\n", voteSubmissionsHelpMsg)
	case "voteinv":
		fmt.Printf("%s\n", voteInvHelpMsg)
	case "votetimestamps":
		fmt.Printf("%s\n", voteTimestampsHelpMsg)

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
