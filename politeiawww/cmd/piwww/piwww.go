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
	ProposalNew       ProposalNewCmd       `command:"proposalnew"`
	ProposalEdit      ProposalEditCmd      `command:"proposaledit"`
	ProposalSetStatus ProposalSetStatusCmd `command:"proposalsetstatus"`
	Proposals         ProposalsCmd         `command:"proposals"`
	ProposalInventory ProposalInventoryCmd `command:"proposalinventory"`

	// Comments commands
	CommentNew    CommentNewCmd    `command:"commentnew" description:"(user) create a new comment"`
	CommentVote   CommentVoteCmd   `command:"commentvote" description:"(user) upvote/downvote a comment"`
	CommentCensor CommentCensorCmd `command:"commentcensor" description:"(admin) censor a comment"`
	Comments      CommentsCmd      `command:"comments" description:"(public) get the comments for a proposal"`
	CommentVotes  CommentVotesCmd  `command:"commentvotes" description:"(user) get comment upvotes/downvotes for a proposal from the provided user"`

	// Vote commands
	VoteStartRunoff VoteStartRunoffCmd `command:"votestartrunoff" description:"(admin)  start a runoff using the submissions to an RFP"`
	VoteStart       VoteStartCmd       `command:"votestart" description:"(admin) start the voting period on a proposal"`
	VoteAuthorize   VoteAuthorizeCmd   `command:"voteauthorize" description:"(user) authorize a proposal vote (must be proposal author)"`
	Votes           VotesCmd           `command:"votes" description:"(public) get the vote tally for a proposal"`
	VoteResults     VoteResultsCmd     `command:"voteresults" description:"(public) get vote results for a proposal"`
	VoteSummaries   VoteSummariesCmd   `command:"votesummaries" description:"(public) retrieve the vote summary for a set of proposals"`
	VoteInventory   VoteInventoryCmd   `command:"voteinventory" description:"(public) retrieve the tokens of all public, non-abandoned proposal separated by vote status"`
	VoteBallot      VoteBallotCmd      `command:"voteballot" description:"(public) cast ballot of votes for a proposal"`

	// Commands
	BatchProposals     shared.BatchProposalsCmd `command:"batchproposals" description:"(user)   retrieve a set of proposals"`
	ChangePassword     shared.ChangePasswordCmd `command:"changepassword" description:"(user)   change the password for the logged in user"`
	ChangeUsername     shared.ChangeUsernameCmd `command:"changeusername" description:"(user)   change the username for the logged in user"`
	EditUser           EditUserCmd              `command:"edituser" description:"(user)   edit the  preferences of the logged in user"`
	Help               HelpCmd                  `command:"help" description:"         print a detailed help message for a specific command"`
	Login              shared.LoginCmd          `command:"login" description:"(public) login to Politeia"`
	Logout             shared.LogoutCmd         `command:"logout" description:"(public) logout of Politeia"`
	ManageUser         shared.ManageUserCmd     `command:"manageuser" description:"(admin)  edit certain properties of the specified user"`
	Me                 shared.MeCmd             `command:"me" description:"(user)   get user details for the logged in user"`
	NewUser            NewUserCmd               `command:"newuser" description:"(public) create a new user"`
	Policy             PolicyCmd                `command:"policy" description:"(public) get the server policy"`
	ProposalDetails    ProposalDetailsCmd       `command:"proposaldetails" description:"(public) get the details of a proposal"`
	ProposalPaywall    ProposalPaywallCmd       `command:"proposalpaywall" description:"(user)   get proposal paywall details for the logged in user"`
	RescanUserPayments RescanUserPaymentsCmd    `command:"rescanuserpayments" description:"(admin)  rescan a user's payments to check for missed payments"`
	ResendVerification ResendVerificationCmd    `command:"resendverification" description:"(public) resend the user verification email"`
	ResetPassword      shared.ResetPasswordCmd  `command:"resetpassword" description:"(public) reset the password for a user that is not logged in"`
	Secret             shared.SecretCmd         `command:"secret" description:"(user)   ping politeiawww"`
	SendFaucetTx       SendFaucetTxCmd          `command:"sendfaucettx" description:"         send a DCR transaction using the Decred testnet faucet"`
	SetTOTP            shared.SetTOTPCmd        `command:"settotp" description:"(user)  set the key for TOTP"`
	Subscribe          SubscribeCmd             `command:"subscribe" description:"(public) subscribe to all websocket commands and do not exit tool"`
	TestRun            TestRunCmd               `command:"testrun" description:"         run a series of tests on the politeiawww routes (dev use only)"`
	TokenInventory     shared.TokenInventoryCmd `command:"tokeninventory" description:"(public) get the censorship record tokens of all proposals"`
	UpdateUserKey      shared.UpdateUserKeyCmd  `command:"updateuserkey" description:"(user)   generate a new identity for the logged in user"`
	UserDetails        UserDetailsCmd           `command:"userdetails" description:"(public) get the details of a user profile"`
	UserPendingPayment UserPendingPaymentCmd    `command:"userpendingpayment" description:"(user)   get details for a pending payment for the logged in user"`
	UserProposals      UserProposalsCmd         `command:"userproposals" description:"(public) get all proposals submitted by a specific user"`
	Users              shared.UsersCmd          `command:"users" description:"(public) get a list of users"`
	VerifyUserEmail    VerifyUserEmailCmd       `command:"verifyuseremail" description:"(public) verify a user's email address"`
	VerifyUserPayment  VerifyUserPaymentCmd     `command:"verifyuserpayment" description:"(user)   check if the logged in user has paid their user registration fee"`
	VerifyTOTP         shared.VerifyTOTPCmd     `command:"verifytotp" description:"(user)  verify the set code for TOTP"`
	Version            shared.VersionCmd        `command:"version" description:"(public) get server info and CSRF token"`
	VettedProposals    VettedProposalsCmd       `command:"vettedproposals" description:"(public) get a page of vetted proposals"`
	VoteDetails        VoteDetailsCmd           `command:"votedetails" description:"(public) get the details for a proposal vote"`
	VoteStatus         VoteStatusCmd            `command:"votestatus" description:"(public) get the vote status of a proposal"`
	VoteStatuses       VoteStatusesCmd          `command:"votestatuses" description:"(public) get the vote status for all public proposals"`
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
