// Copyright (c) 2017-2020 The Decred developers
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
	defaultHomeDirname    = "piwww"
	defaultDataDirname    = "data"
	defaultConfigFilename = "piwww.conf"
)

var (
	// Global variables for piwww commands
	cfg    *shared.Config
	client *shared.Client

	// Config settings
	defaultHomeDir = dcrutil.AppDataDir(defaultHomeDirname, false)
)

type piwww struct {
	// Basic commands
	Help helpCmd `command:"help"`

	// Server commands
	Version shared.VersionCmd `command:"version"`
	Policy  policyCmd         `command:"policy"`
	Secret  shared.SecretCmd  `command:"secret"`
	Login   shared.LoginCmd   `command:"login"`
	Logout  shared.LogoutCmd  `command:"logout"`
	Me      shared.MeCmd      `command:"me"`

	// User commands
	UserNew                userNewCmd                   `command:"usernew"`
	UserEdit               userEditCmd                  `command:"useredit"`
	UserManage             shared.UserManageCmd         `command:"usermanage"`
	UserEmailVerify        userEmailVerifyCmd           `command:"useremailverify"`
	UserVerificationResend userVerificationResendCmd    `command:"userverificationresend"`
	UserPasswordReset      shared.UserPasswordResetCmd  `command:"userpasswordreset"`
	UserPasswordChange     shared.UserPasswordChangeCmd `command:"userpasswordchange"`
	UserUsernameChange     shared.UserUsernameChangeCmd `command:"userusernamechange"`
	UserKeyUpdate          shared.UserKeyUpdateCmd      `command:"userkeyupdate"`
	UserTOTPSet            shared.UserTOTPSetCmd        `command:"usertotpset"`
	UserTOTPVerify         shared.UserTOTPVerifyCmd     `command:"usertotpverify"`
	UserProposalPaywall    userProposalPaywallCmd       `command:"userproposalpaywall"`
	UserPaymentVerify      userPaymentVerifyCmd         `command:"userpaymentverify"`
	UserPaymentsRescan     userPaymentsRescanCmd        `command:"userpaymentsrescan"`
	UserPendingPayment     userPendingPaymentCmd        `command:"userpendingpayment"`
	UserDetails            userDetailsCmd               `command:"userdetails"`
	Users                  shared.UsersCmd              `command:"users"`

	// TODO some of the proposal commands use both the --unvetted and
	// --vetted flags. Let make them all use only the --unvetted flag.
	// If --unvetted is not included then its assumed to be a vetted
	// request.
	// TODO replace www policies with pi policies
	// Proposal commands
	ProposalNew       proposalNewCmd       `command:"proposalnew"`
	ProposalEdit      proposalEditCmd      `command:"proposaledit"`
	ProposalStatusSet proposalStatusSetCmd `command:"proposalstatusset"`
	Proposals         proposalsCmd         `command:"proposals"`
	ProposalInventory proposalInventoryCmd `command:"proposalinventory"`

	// Comments commands
	CommentNew    commentNewCmd    `command:"commentnew"`
	CommentVote   commentVoteCmd   `command:"commentvote"`
	CommentCensor commentCensorCmd `command:"commentcensor"`
	Comments      commentsCmd      `command:"comments"`
	CommentVotes  commentVotesCmd  `command:"commentvotes"`

	// Vote commands
	VoteAuthorize   voteAuthorizeCmd   `command:"voteauthorize"`
	VoteStart       voteStartCmd       `command:"votestart"`
	VoteStartRunoff voteStartRunoffCmd `command:"votestartrunoff"`
	VoteBallot      voteBallotCmd      `command:"voteballot"`
	Votes           votesCmd           `command:"votes"`
	VoteResults     voteResultsCmd     `command:"voteresults"`
	VoteSummaries   voteSummariesCmd   `command:"votesummaries"`
	VoteInventory   voteInventoryCmd   `command:"voteinventory"`

	// Websocket commands
	Subscribe subscribeCmd `command:"subscribe"`

	// Dev commands
	TestRun      testRunCmd      `command:"testrun"`
	SendFaucetTx sendFaucetTxCmd `command:"sendfaucettx"`
}

// TODO add proposalpaywall to this once the command is updated
const helpMsg = `Application Options:
      --appdata=    Path to application home directory
      --host=       politeiawww host
  -j, --json        Print raw JSON output
      --version     Display version information and exit
      --skipverify  Skip verifying the server's certifcate chain and host name
  -v, --verbose     Print verbose output
      --silent      Suppress all output

Help commands
  help                   Print detailed help message for a command

Basic commands
  version                (public) Get politeiawww server version
  policy                 (public) Get politeiawww server policy
  secret                 (public) Ping the server
  login                  (public) Login to politeiawww
  logout                 (user)   Logout from politeiawww
  me                     (user)   Get details of the logged in user

User commands
  usernew                (public) Create a new user
  useredit               (user)   Edit the logged in user
  usermanage             (admin)  Edit a user as an admin
  useremailverify        (public) Verify email address
  userverificationresend (public) Resend verification email
  userpasswordreset      (public) Reset password 
  userpasswordchange     (user)   Change password
  userusernamechange     (user)   Change username
  userkeyupdate          (user)   Update user key (i.e. identity)
  usertotpset            (user)   Set a TOTP method
  usertotpverify         (user)   Verify a TOTP method
  userpaymentverify      (user)   Verify registration payment
  userpaymentsrescan     (user)   Rescan all user payments
  userpendingpayment     (user)   Get pending user payments
  userdetails            (public) Get user details
  users                  (public) Get users

Proposal commands
  proposalnew            (user)   Submit a new proposal
  proposaledit           (user)   Edit an existing proposal
  proposalsetstatus      (admin)  Set the status of a proposal
  proposals              (public) Get proposals
  proposalinventory      (public) Get proposals inventory by proposal status

Comment commands
  commentnew             (user)   Submit a new comment
  commentvote            (user)   Upvote/downvote a comment
  commentcensor          (admin)  Censor a comment
  comments               (public) Get comments
  commentvotes           (public) Get comment votes

Vote commands
  voteauthorize          (user)   Authorize a proposal vote
  votestart              (admin)  Start a proposal vote
  votestartrunoff        (admin)  Start a runoff vote
  voteballot             (public) Cast a ballot of votes
  votes                  (public) Get vote details
  voteresults            (public) Get full vote results
  votesummaries          (public) Get vote summaries
  voteinventory          (public) Get proposal inventory by vote status

Websocket commands
  subscribe              (public) Subscribe/unsubscribe to websocket event

Dev commands
  sendfaucettx           Send a dcr faucet tx
  testrun                Execute a test run of pi routes
`

func _main() error {
	// Load config. The config variable is a CLI global variable.
	var err error
	cfg, err = shared.LoadConfig(defaultHomeDir,
		defaultDataDirname, defaultConfigFilename)
	if err != nil {
		return fmt.Errorf("load config: %v", err)
	}

	// Load client. The client variable is a CLI global variable.
	client, err = shared.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("load client: %v", err)
	}

	// Setup global variables for shared commands
	shared.SetConfig(cfg)
	shared.SetClient(client)

	// Check for a help flag. This is done separately so that we can
	// print our own custom help message
	var opts flags.Options = flags.HelpFlag | flags.IgnoreUnknown |
		flags.PassDoubleDash
	parser := flags.NewParser(&struct{}{}, opts)
	_, err = parser.Parse()
	if err != nil {
		var flagsErr *flags.Error
		if errors.As(err, &flagsErr) && flagsErr.Type == flags.ErrHelp {
			fmt.Printf("%v\n", helpMsg)
			return nil
		}
		return fmt.Errorf("parse help flags: %v", err)
	}

	// Get politeiawww CSRF token
	if cfg.CSRF == "" {
		_, err := client.Version()
		if err != nil {
			return fmt.Errorf("Version: %v", err)
		}
	}

	// Parse subcommand and execute
	parser = flags.NewParser(&piwww{}, flags.Default)
	_, err = parser.Parse()
	if err != nil {
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
