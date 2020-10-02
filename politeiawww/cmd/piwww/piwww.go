// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"
	"net/url"
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
	// XXX the config does not need to be a part of this struct, but
	// is included so that the config cli flags print as part of the
	// piwww help message. This is handled by go-flags.
	Config shared.Config

	// Basic commands
	Help helpCmd `command:"help"`

	// Server commands
	Version shared.VersionCmd `command:"version"`
	Policy  policyCmd         `command:"policy"`
	Secret  shared.SecretCmd  `command:"secret"`
	Login   shared.LoginCmd   `command:"login"`
	Logout  shared.LogoutCmd  `command:"logout"`
	Me      shared.MeCmd      `command:"me"`

	// TODO some of the proposal commands use both the --unvetted and
	// --vetted flags. Let make them all use only the --unvetted flag.
	// If --unvetted is not included then its assumed to be a vetted
	// request.
	// TODO replace www policies with pi policies
	// Proposal commands
	ProposalNew       proposalNewCmd       `command:"proposalnew"`
	ProposalEdit      proposalEditCmd      `command:"proposaledit"`
	ProposalSetStatus proposalSetStatusCmd `command:"proposalsetstatus"`
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

	// User commands
	UserNew                userNewCmd                   `command:"usernew"`
	UserEdit               userEditCmd                  `command:"useredit"`
	UserDetails            userDetailsCmd               `command:"userdetails"`
	UserPaymentsRescan     userPaymentsRescanCmd        `command:"userpaymentsrescan"`
	UserPendingPayment     userPendingPaymentCmd        `command:"userpendingpayment"`
	UserEmailVerify        userEmailVerifyCmd           `command:"useremailverify"`
	UserPaymentVerify      userPaymentVerifyCmd         `command:"userpaymentverify"`
	UserVerificationResend userVerificationResendCmd    `command:"userverificationresend"`
	UserManage             shared.UserManageCmd         `command:"usermanage"`
	UserKeyUpdate          shared.UserKeyUpdateCmd      `command:"userkeyupdate"`
	UserUsernameChange     shared.UserUsernameChangeCmd `command:"userusernamechange"`
	UserPasswordChange     shared.UserPasswordChangeCmd `command:"userpasswordchange"`
	UserPasswordReset      shared.UserPasswordResetCmd  `command:"userpasswordreset"`
	UserTOTPSet            shared.UserTOTPSetCmd        `command:"usertotpset"`
	UserTOTPVerify         shared.UserTOTPVerifyCmd     `command:"usertotpverify"`
	Users                  shared.UsersCmd              `command:"users"`

	// TODO rename to reflect that its a users route
	ProposalPaywall proposalPaywallCmd `command:"proposalpaywall"`

	// Websocket commands
	Subscribe subscribeCmd `command:"subscribe"`

	// Dev commands
	TestRun      testRunCmd      `command:"testrun"`
	SendFaucetTx sendFaucetTxCmd `command:"sendfaucettx"`
}

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

	// Get politeiawww CSRF token
	if cfg.CSRF == "" {
		_, err := client.Version()
		if err != nil {
			var e *url.Error
			if !errors.As(err, &e) {
				// A url error likely means that politeiawww is not
				// running. The user may just be trying to print the
				// help message so only return an error if its not
				// a url error.
				return fmt.Errorf("Version: %v", err)
			}
		}
	}

	// Parse subcommand and execute
	var cli piwww
	var parser = flags.NewParser(&cli, flags.Default)
	if _, err := parser.Parse(); err != nil {
		var flagsErr *flags.Error
		if errors.As(err, &flagsErr) && flagsErr.Type == flags.ErrHelp {
			os.Exit(0)
		} else {
			os.Exit(1)
		}
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
