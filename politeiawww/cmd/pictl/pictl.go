// Copyright (c) 2017-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"
	"os"

	flags "github.com/jessevdk/go-flags"

	"github.com/decred/dcrd/dcrutil/v3"
	"github.com/decred/politeia/politeiawww/cmd/shared"
)

const (
	// Config settings
	defaultHomeDirname    = "pictl"
	defaultDataDirname    = "data"
	defaultConfigFilename = "pictl.conf"
)

var (
	// Global variables for pictl commands
	cfg    *shared.Config
	client *shared.Client

	// Config settings
	defaultHomeDir = dcrutil.AppDataDir(defaultHomeDirname, false)
)

type pictl struct {
	// This is here to prevent parsing errors caused by config flags.
	Config shared.Config

	// Basic commands
	Help helpCmd `command:"help"`

	// Server commands
	Version shared.VersionCmd `command:"version"`
	Policy  policyCmd         `command:"policy"`
	Login   shared.LoginCmd   `command:"login"`
	Logout  shared.LogoutCmd  `command:"logout"`
	Me      shared.MeCmd      `command:"me"`

	// User commands
	UserNew                 userNewCmd                   `command:"usernew"`
	UserEdit                userEditCmd                  `command:"useredit"`
	UserManage              shared.UserManageCmd         `command:"usermanage"`
	UserEmailVerify         userEmailVerifyCmd           `command:"useremailverify"`
	UserVerificationResend  userVerificationResendCmd    `command:"userverificationresend"`
	UserPasswordReset       shared.UserPasswordResetCmd  `command:"userpasswordreset"`
	UserPasswordChange      shared.UserPasswordChangeCmd `command:"userpasswordchange"`
	UserUsernameChange      shared.UserUsernameChangeCmd `command:"userusernamechange"`
	UserKeyUpdate           shared.UserKeyUpdateCmd      `command:"userkeyupdate"`
	UserRegistrationPayment userRegistrationPaymentCmd   `command:"userregistrationpayment"`
	UserPaymentsRescan      userPaymentsRescanCmd        `command:"userpaymentsrescan"`
	UserProposalPaywall     userProposalPaywallCmd       `command:"userproposalpaywall"`
	UserProposalPaywallTx   userProposalPaywallTxCmd     `command:"userproposalpaywalltx"`
	UserProposalCredits     userProposalCreditsCmd       `command:"userproposalcredits"`
	UserDetails             userDetailsCmd               `command:"userdetails"`
	Users                   shared.UsersCmd              `command:"users"`

	// Proposal commands
	ProposalPolicy     cmdProposalPolicy     `command:"proposalpolicy"`
	ProposalNew        cmdProposalNew        `command:"proposalnew"`
	ProposalEdit       cmdProposalEdit       `command:"proposaledit"`
	ProposalSetStatus  cmdProposalSetStatus  `command:"proposalsetstatus"`
	ProposalDetails    cmdProposalDetails    `command:"proposaldetails"`
	Proposals          cmdProposals          `command:"proposals"`
	ProposalInv        cmdProposalInv        `command:"proposalinv"`
	ProposalTimestamps cmdProposalTimestamps `command:"proposaltimestamps"`

	// Comments commands
	CommentsPolicy    cmdCommentPolicy     `command:"commentpolicy"`
	CommentNew        cmdCommentNew        `command:"commentnew"`
	CommentVote       cmdCommentVote       `command:"commentvote"`
	CommentCensor     cmdCommentCensor     `command:"commentcensor"`
	Comments          cmdComments          `command:"comments"`
	CommentVotes      cmdCommentVotes      `command:"commentvotes"`
	CommentTimestamps cmdCommentTimestamps `command:"commenttimestamps"`

	// Vote commands
	VotePolicy      votePolicyCmd      `command:"votepolicy"`
	VoteAuthorize   voteAuthorizeCmd   `command:"voteauthorize"`
	VoteStart       voteStartCmd       `command:"votestart"`
	VoteStartRunoff voteStartRunoffCmd `command:"votestartrunoff"`
	CastBallot      castBallotCmd      `command:"castballot"`
	Votes           votesCmd           `command:"votes"`
	VoteResults     voteResultsCmd     `command:"voteresults"`
	VoteSummaries   voteSummariesCmd   `command:"votesummaries"`
	VoteInventory   voteInventoryCmd   `command:"voteinv"`
	VoteTimestamps  voteTimestampsCmd  `command:"votetimestamps"`

	// Websocket commands
	Subscribe subscribeCmd `command:"subscribe"`

	// Dev commands
	TestRun      testRunCmd      `command:"testrun"`
	SendFaucetTx sendFaucetTxCmd `command:"sendfaucettx"`
}

const helpMsg = `Application Options:
      --appdata=    Path to application home directory
      --host=       politeiawww host
  -j, --json        Print raw JSON output
      --version     Display version information and exit
      --skipverify  Skip verifying the server's certifcate chain and host name
  -v, --verbose     Print verbose output
      --silent      Suppress all output

Help commands
  help                    Print detailed help message for a command

Basic commands
  version                 (public) Get politeiawww server version and CSRF
  policy                  (public) Get politeiawww server policy
  secret                  (public) Ping the server
  login                   (public) Login to politeiawww
  logout                  (user)   Logout from politeiawww
  me                      (user)   Get details of the logged in user

User commands
  usernew                 (public) Create a new user
  useredit                (user)   Edit the logged in user
  usermanage              (admin)  Edit a user as an admin
  useremailverify         (public) Verify email address
  userverificationresend  (public) Resend verification email
  userpasswordreset       (public) Reset password 
  userpasswordchange      (user)   Change password
  userusernamechange      (user)   Change username
  userkeyupdate           (user)   Update user key (i.e. identity)
  userregistrationpayment (user)   Verify registration payment
  userpaymentsrescan      (user)   Rescan all user payments
  userproposalpaywall     (user)   Get user paywall details
  userproposalpaywalltx   (user)   Get pending user payments
  userproposalcredits     (user)   Get user proposal credits
  userdetails             (public) Get user details
  users                   (public) Get users

Proposal commands
  proposalpolicy          (public) Get the pi api policy
  proposalnew             (user)   Submit a new proposal
  proposaledit            (user)   Edit an existing proposal
  proposalstatusset       (admin)  Set the status of a proposal
  proposaldetials         (public) Get a full proposal record
  proposals               (public) Get proposals without their files
  proposalinv             (public) Get inventory by proposal status
  proposaltimestamps      (public) Get timestamps for a proposal

Comment commands
  commentpolicy           (public) Get the comments api policy
  commentnew              (user)   Submit a new comment
  commentvote             (user)   Upvote/downvote a comment
  commentcensor           (admin)  Censor a comment
  comments                (public) Get comments
  commentvotes            (public) Get comment votes

Vote commands
  votepolicy              (public) Get the ticketvote api policy
  voteauthorize           (user)   Authorize a proposal vote
  votestart               (admin)  Start a proposal vote
  votestartrunoff         (admin)  Start a runoff vote
  castballot              (public) Cast a ballot of votes
  votes                   (public) Get vote details
  voteresults             (public) Get full vote results
  votesummaries           (public) Get vote summaries
  voteinv                 (public) Get proposal inventory by vote status

Websocket commands
  subscribe               (public) Subscribe/unsubscribe to websocket event

Dev commands
  sendfaucettx            Send a dcr faucet tx
  testrun                 Execute a test run of pi routes
`

func _main() error {
	// Load config. The config variable is aglobal variable.
	var err error
	cfg, err = shared.LoadConfig(defaultHomeDir,
		defaultDataDirname, defaultConfigFilename)
	if err != nil {
		return fmt.Errorf("load config: %v", err)
	}

	// Load client. The client variable is a global variable.
	client, err = shared.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("load client: %v", err)
	}

	// Setup global variables for shared commands
	shared.SetConfig(cfg)
	shared.SetClient(client)

	// Check for a help flag. This is done separately so that we can
	// print our own custom help message.
	var opts flags.Options = flags.HelpFlag | flags.IgnoreUnknown |
		flags.PassDoubleDash
	parser := flags.NewParser(&struct{}{}, opts)
	_, err = parser.Parse()
	if err != nil {
		var flagsErr *flags.Error
		if errors.As(err, &flagsErr) && flagsErr.Type == flags.ErrHelp {
			// The -h, --help flag was used. Print the custom help message
			// and exit gracefully.
			fmt.Printf("%v\n", helpMsg)
			os.Exit(0)
		}
		return fmt.Errorf("parse help flag: %v", err)
	}

	// Parse CLI args and execute command
	parser = flags.NewParser(&pictl{Config: *cfg}, flags.Default)
	_, err = parser.Parse()
	if err != nil {
		// An error has occurred during command execution. go-flags will
		// have already printed the error to os.Stdout. Exit with an
		// error code.
		os.Exit(1)
	}

	return nil
}

func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
