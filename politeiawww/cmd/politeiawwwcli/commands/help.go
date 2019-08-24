// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package commands

import "fmt"

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
			"message for.  Example: politeiawwwcli help login")
	}

	switch cmd.Args.Topic {
	case "login":
		fmt.Printf("%s\n", loginHelpMsg)
	case "logout":
		fmt.Printf("%s\n", logoutHelpMsg)
	case "authorizevote":
		fmt.Printf("%s\n", authorizeVoteHelpMsg)
	case "newuser":
		fmt.Printf("%s\n", newUserHelpMsg)
	case "newproposal":
		fmt.Printf("%s\n", newProposalHelpMsg)
	case "changepassword":
		fmt.Printf("%s\n", changePasswordHelpMsg)
	case "changeusername":
		fmt.Printf("%s\n", changeUsernameHelpMsg)
	case "sendfaucettx":
		fmt.Printf("%s\n", sendFaucetTxHelpMsg)
	case "userdetails":
		fmt.Printf("%s\n", userDetailsHelpMsg)
	case "proposaldetails":
		fmt.Printf("%s\n", proposalDetailsHelpMsg)
	case "userproposals":
		fmt.Printf("%s\n", userProposalsHelpMsg)
	case "vettedproposals":
		fmt.Printf("%s\n", vettedProposalsHelpMsg)
	case "setproposalstatus":
		fmt.Printf("%s\n", setProposalStatusHelpMsg)
	case "newcomment":
		fmt.Printf("%s\n", newCommentHelpMsg)
	case "proposalcomments":
		fmt.Printf("%s\n", proposalCommentsHelpMsg)
	case "censorcomment":
		fmt.Printf("%s\n", censorCommentHelpMsg)
	case "likecomment":
		fmt.Printf("%s\n", likeCommentHelpMsg)
	case "editproposal":
		fmt.Printf("%s\n", editProposalHelpMsg)
	case "manageuser":
		fmt.Printf("%s\n", manageUserHelpMsg)
	case "users":
		fmt.Printf("%s\n", usersHelpMsg)
	case "verifyuseremail":
		fmt.Printf("%s\n", verifyUserEmailHelpMsg)
	case "version":
		fmt.Printf("%s\n", versionHelpMsg)
	case "edituser":
		fmt.Printf("%s\n", editUserHelpMsg)
	case "subscribe":
		fmt.Printf("%s\n", subscribeHelpMsg)
	case "me":
		fmt.Printf("%s\n", meHelpMsg)
	case "policy":
		fmt.Printf("%s\n", policyHelpMsg)
	case "resetpassword":
		fmt.Printf("%s\n", resetPasswordHelpMsg)
	case "updateuserkey":
		fmt.Printf("%s\n", updateUserKeyHelpMsg)
	case "userpendingpayment":
		fmt.Printf("%s\n", userPendingPaymentHelpMsg)
	case "proposalpaywall":
		fmt.Printf("%s\n", proposalPaywallHelpMsg)
	case "rescanuserpayments":
		fmt.Printf("%s\n", rescanUserPaymentsHelpMsg)
	case "verifyuserpayment":
		fmt.Printf("%s\n", verifyUserPaymentHelpMsg)
	case "startvote":
		fmt.Printf("%s\n", startVoteHelpMsg)
	case "voteresults":
		fmt.Printf("%s\n", voteResultsHelpMsg)
	case "inventory":
		fmt.Printf("%s\n", inventoryHelpMsg)
	case "tally":
		fmt.Printf("%s\n", tallyHelpMsg)
	case "userlikecomments":
		fmt.Printf("%s\n", userLikeCommentsHelpMsg)
	case "activevotes":
		fmt.Printf("%s\n", activeVotesHelpMsg)
	case "votestatus":
		fmt.Printf("%s\n", voteStatusHelpMsg)
	case "votestatuses":
		fmt.Printf("%s\n", voteStatusesHelpMsg)
	case "vote":
		fmt.Printf("%s\n", voteHelpMsg)
	case "testrun":
		fmt.Printf("%s\n", testRunHelpMsg)
	case "resendverification":
		fmt.Printf("%s\n", resendVerificationHelpMsg)
	case "batchproposals":
		fmt.Printf("%s\n", batchProposalsHelpMsg)
	case "batchvotesummary":
		fmt.Printf("%s\n", batchVoteSummaryHelpMsg)

		// CMS commands
	case "newinvoice":
		fmt.Printf("%s\n", newInvoiceHelpMsg)
	case "invoicedetails":
		fmt.Printf("%s\n", invoiceDetailsHelpMsg)
	case "editinvoice":
		fmt.Printf("%s\n", editInvoiceHelpMsg)
	case "setinvoicestatus":
		fmt.Printf("%s\n", setInvoiceStatusHelpMsg)
	case "invoicecomments":
		fmt.Printf("%s\n", invoiceCommentsHelpMsg)
	case "admininvoices":
		fmt.Printf("%s\n", adminInvoicesHelpMsg)
	case "userinvoices":
		fmt.Printf("%s\n", userInvoicesHelpMsg)
	case "invoiceexchangerate":
		fmt.Printf("%s\n", invoiceExchangeRateHelpMsg)

	default:
		fmt.Printf("invalid command: use 'politeiawwwcli -h' " +
			"to view a list of valid commands\n")
	}

	return nil
}
