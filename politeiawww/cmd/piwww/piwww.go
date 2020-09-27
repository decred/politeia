// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"

	flags "github.com/jessevdk/go-flags"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrutil"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	pi "github.com/decred/politeia/politeiawww/api/pi/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
	wwwutil "github.com/decred/politeia/politeiawww/util"
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

	// Proposal commands
	ProposalNew       proposalNewCmd       `command:"proposalnew"`
	ProposalEdit      proposalEditCmd      `command:"proposaledit"`
	ProposalSetStatus proposalSetStatusCmd `command:"proposalsetstatus"`
	Proposals         proposalsCmd         `command:"proposals"`
	ProposalInventory proposalInventoryCmd `command:"proposalinventory"`

	// Comments commands
	CommentNew    commentNewCmd    `command:"commentnew" description:"(user) create a new comment"`
	CommentVote   commentVoteCmd   `command:"commentvote" description:"(user) upvote/downvote a comment"`
	CommentCensor commentCensorCmd `command:"commentcensor" description:"(admin) censor a comment"`
	Comments      commentsCmd      `command:"comments" description:"(public) get the comments for a proposal"`
	CommentVotes  commentVotesCmd  `command:"commentvotes" description:"(user) get comment upvotes/downvotes for a proposal from the provided user"`

	// Vote commands
	VoteAuthorize   voteAuthorizeCmd   `command:"voteauthorize" description:"(user) authorize a proposal vote (must be proposal author)"`
	VoteStart       voteStartCmd       `command:"votestart" description:"(admin) start the voting period on a proposal"`
	VoteStartRunoff voteStartRunoffCmd `command:"votestartrunoff" description:"(admin)  start a runoff using the submissions to an RFP"`
	VoteBallot      voteBallotCmd      `command:"voteballot" description:"(public) cast ballot of votes for a proposal"`
	Votes           votesCmd           `command:"votes" description:"(public) get the vote tally for a proposal"`
	VoteResults     voteResultsCmd     `command:"voteresults" description:"(public) get vote results for a proposal"`
	VoteSummaries   voteSummariesCmd   `command:"votesummaries" description:"(public) retrieve the vote summary for a set of proposals"`
	VoteInventory   voteInventoryCmd   `command:"voteinventory" description:"(public) retrieve the tokens of all public, non-abandoned proposal separated by vote status"`
	// XXX www vote routes
	VoteDetails  voteDetailsCmd  `command:"votedetails" description:"(public) get the details for a proposal vote"`
	VoteStatus   voteStatusCmd   `command:"votestatus" description:"(public) get the vote status of a proposal"`
	VoteStatuses voteStatusesCmd `command:"votestatuses" description:"(public) get the vote status for all public proposals"`

	// User commands
	UserNew                userNewCmd                   `command:"usernew" description:"(public) create a new user"`
	UserEdit               userEditCmd                  `command:"useredit" description:"(user) edit the preferences of the logged in user"`
	UserDetails            userDetailsCmd               `command:"userdetails" description:"(public) get the details of a user profile"`
	UserPaymentsRescan     userPaymentsRescanCmd        `command:"userpaymentsrescan" description:"(admin) rescan a user's payments to check for missed payments"`
	UserPendingPayment     userPendingPaymentCmd        `command:"userpendingpayment" description:"(user) get details for a pending payment for the logged in user"`
	UserEmailVerify        userEmailVerifyCmd           `command:"useremailverify" description:"(public) verify a user's email address"`
	UserPaymentVerify      userPaymentVerifyCmd         `command:"userpaymentverify" description:"(user) check if the logged in user has paid their user registration fee"`
	UserVerificationResend userVerificationResendCmd    `command:"userverificationresend" description:"(public) resend the user verification email"`
	UserManage             shared.UserManageCmd         `command:"usermanage" description:"(admin) edit certain properties of the specified user"`
	UserKeyUpdate          shared.UserKeyUpdateCmd      `command:"userkeyupdate" description:"(user) generate a new identity for the logged in user"`
	UserUsernameChange     shared.UserUsernameChangeCmd `command:"userusernamechange" description:"(user) change the username for the logged in user"`
	UserPasswordChange     shared.UserPasswordChangeCmd `command:"userpasswordchange" description:"(user) change the password for the logged in user"`
	UserPasswordReset      shared.UserPasswordResetCmd  `command:"userpasswordreset" description:"(public) reset the password for a user that is not logged in"`
	UserTOTPSet            shared.UserTOTPSetCmd        `command:"usertotpset" description:"(user) set the key for TOTP"`
	UserTOTPVerify         shared.UserTOTPVerifyCmd     `command:"usertotpverify" description:"(user) verify the set code for TOTP"`
	Users                  shared.UsersCmd              `command:"users" description:"(public) get a list of users"`

	// XXX will be factored to a user route
	ProposalPaywall proposalPaywallCmd `command:"proposalpaywall" description:"(user)   get proposal paywall details for the logged in user"`

	// Basic commands
	Login   shared.LoginCmd   `command:"login" description:"(public) login to Politeia"`
	Logout  shared.LogoutCmd  `command:"logout" description:"(public) logout of Politeia"`
	Me      shared.MeCmd      `command:"me" description:"(user) get user details for the logged in user"`
	Secret  shared.SecretCmd  `command:"secret" description:"(user) ping politeiawww"`
	Version shared.VersionCmd `command:"version" description:"(public) get server info and CSRF token"`
	Policy  policyCmd         `command:"policy" description:"(public) get the server policy"`
	Help    helpCmd           `command:"help" description:" print a detailed help message for a specific command"`

	// Websocket commands
	Subscribe subscribeCmd `command:"subscribe" description:"(public) subscribe to all websocket commands and do not exit tool"`

	// Dev commands
	TestRun      testRunCmd      `command:"testrun" description:"(dev) run a series of tests on the politeiawww routes"`
	SendFaucetTx sendFaucetTxCmd `command:"sendfaucettx" description:"(dev) send a DCR transaction using the Decred testnet faucet"`
}

// signedMerkleRoot calculates the merkle root of the passed in list of files
// and metadata, signs the merkle root with the passed in identity and returns
// the signature.
func signedMerkleRoot(files []pi.File, md []pi.Metadata, id *identity.FullIdentity) (string, error) {
	if len(files) == 0 {
		return "", fmt.Errorf("no proposal files found")
	}
	mr, err := wwwutil.MerkleRoot(files, md)
	if err != nil {
		return "", err
	}
	sig := id.SignMessage([]byte(mr))
	return hex.EncodeToString(sig[:]), nil
}

// convertTicketHashes converts a slice of hexadecimal ticket hashes into
// a slice of byte slices.
func convertTicketHashes(h []string) ([][]byte, error) {
	hashes := make([][]byte, 0, len(h))
	for _, v := range h {
		h, err := chainhash.NewHashFromStr(v)
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, h[:])
	}
	return hashes, nil
}

// proposalRecord returns the ProposalRecord for the provided token and
// version.
func proposalRecord(state pi.PropStateT, token, version string) (*pi.ProposalRecord, error) {
	ps := pi.Proposals{
		State: state,
		Requests: []pi.ProposalRequest{
			{
				Token: token,
			},
		},
		IncludeFiles: false,
	}
	psr, err := client.Proposals(ps)
	if err != nil {
		return nil, err
	}
	pr, ok := psr.Proposals[token]
	if !ok {
		return nil, fmt.Errorf("proposal not found")
	}

	return &pr, nil
}

// proposalRecord returns the latest ProposalRecrord version for the provided
// token.
func proposalRecordLatest(state pi.PropStateT, token string) (*pi.ProposalRecord, error) {
	return proposalRecord(state, token, "")
}

// decodeProposalMetadata decodes and returns a ProposalMetadata given the
// metadata array from a ProposalRecord.
func decodeProposalMetadata(metadata []pi.Metadata) (*pi.ProposalMetadata, error) {
	var pm *pi.ProposalMetadata
	for _, v := range metadata {
		if v.Hint == pi.HintProposalMetadata {
			b, err := base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				return nil, err
			}
			err = json.Unmarshal(b, pm)
			if err != nil {
				return nil, err
			}
		}
	}
	if pm == nil {
		return nil, fmt.Errorf("proposal metadata not found")
	}
	return pm, nil
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
			if _, ok := err.(*url.Error); !ok {
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
		flagsErr, ok := err.(*flags.Error)
		if ok && flagsErr.Type == flags.ErrHelp {
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
