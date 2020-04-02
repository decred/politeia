// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"

	flags "github.com/jessevdk/go-flags"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrutil"
	"github.com/thi4go/politeia/politeiad/api/v1/mime"
	v1 "github.com/thi4go/politeia/politeiawww/api/www/v1"
	"github.com/thi4go/politeia/politeiawww/cmd/shared"
	"github.com/thi4go/politeia/util"
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

	// errProposalMDNotFound is emitted when a proposal markdown file
	// is required but has not been provided.
	errProposalMDNotFound = errors.New("proposal markdown file not " +
		"found; you must either provide a markdown file or use the " +
		"flag --random")
)

type piwww struct {
	// XXX the config does not need to be a part of this struct, but
	// is included so that the config cli flags print as part of the
	// piwww help message. This is handled by go-flags.
	Config shared.Config

	// Commands
	ActiveVotes        ActiveVotesCmd           `command:"activevotes" description:"(public) get the proposals that are being voted on"`
	AuthorizeVote      AuthorizeVoteCmd         `command:"authorizevote" description:"(user)   authorize a proposal vote (must be proposal author)"`
	BatchProposals     BatchProposalsCmd        `command:"batchproposals" description:"(user)   retrieve a set of proposals"`
	BatchVoteSummary   BatchVoteSummaryCmd      `command:"batchvotesummary" description:"(user)   retrieve the vote summary for a set of proposals"`
	CensorComment      shared.CensorCommentCmd  `command:"censorcomment" description:"(admin)  censor a comment"`
	ChangePassword     shared.ChangePasswordCmd `command:"changepassword" description:"(user)   change the password for the logged in user"`
	ChangeUsername     shared.ChangeUsernameCmd `command:"changeusername" description:"(user)   change the username for the logged in user"`
	EditProposal       EditProposalCmd          `command:"editproposal" description:"(user)   edit a proposal"`
	EditUser           EditUserCmd              `command:"edituser" description:"(user)   edit the  preferences of the logged in user"`
	Help               HelpCmd                  `command:"help" description:"         print a detailed help message for a specific command"`
	Inventory          InventoryCmd             `command:"inventory" description:"(public) get the proposals that are being voted on"`
	LikeComment        LikeCommentCmd           `command:"likecomment" description:"(user)   upvote/downvote a comment"`
	Login              shared.LoginCmd          `command:"login" description:"(public) login to Politeia"`
	Logout             shared.LogoutCmd         `command:"logout" description:"(public) logout of Politeia"`
	ManageUser         shared.ManageUserCmd     `command:"manageuser" description:"(admin)  edit certain properties of the specified user"`
	Me                 shared.MeCmd             `command:"me" description:"(user)   get user details for the logged in user"`
	NewComment         shared.NewCommentCmd     `command:"newcomment" description:"(user)   create a new comment"`
	NewProposal        NewProposalCmd           `command:"newproposal" description:"(user)   create a new proposal"`
	NewUser            NewUserCmd               `command:"newuser" description:"(public) create a new user"`
	Policy             PolicyCmd                `command:"policy" description:"(public) get the server policy"`
	ProposalComments   ProposalCommentsCmd      `command:"proposalcomments" description:"(public) get the comments for a proposal"`
	ProposalDetails    ProposalDetailsCmd       `command:"proposaldetails" description:"(public) get the details of a proposal"`
	ProposalPaywall    ProposalPaywallCmd       `command:"proposalpaywall" description:"(user)   get proposal paywall details for the logged in user"`
	RescanUserPayments RescanUserPaymentsCmd    `command:"rescanuserpayments" description:"(admin)  rescan a user's payments to check for missed payments"`
	ResendVerification ResendVerificationCmd    `command:"resendverification" description:"(public) resend the user verification email"`
	ResetPassword      shared.ResetPasswordCmd  `command:"resetpassword" description:"(public) reset the password for a user that is not logged in"`
	Secret             shared.SecretCmd         `command:"secret" description:"(user)   ping politeiawww"`
	SendFaucetTx       SendFaucetTxCmd          `command:"sendfaucettx" description:"         send a DCR transaction using the Decred testnet faucet"`
	SetProposalStatus  SetProposalStatusCmd     `command:"setproposalstatus" description:"(admin)  set the status of a proposal"`
	StartVote          StartVoteCmd             `command:"startvote" description:"(admin)  start the voting period on a proposal"`
	Subscribe          SubscribeCmd             `command:"subscribe" description:"(public) subscribe to all websocket commands and do not exit tool"`
	Tally              TallyCmd                 `command:"tally" description:"(public) get the vote tally for a proposal"`
	TestRun            TestRunCmd               `command:"testrun" description:"         run a series of tests on the politeiawww routes (dev use only)"`
	TokenInventory     TokenInventoryCmd        `command:"tokeninventory" description:"(public) get the censorship record tokens of all proposals"`
	UpdateUserKey      shared.UpdateUserKeyCmd  `command:"updateuserkey" description:"(user)   generate a new identity for the logged in user"`
	UserDetails        UserDetailsCmd           `command:"userdetails" description:"(public) get the details of a user profile"`
	UserLikeComments   UserLikeCommentsCmd      `command:"userlikecomments" description:"(user)   get the logged in user's comment upvotes/downvotes for a proposal"`
	UserPendingPayment UserPendingPaymentCmd    `command:"userpendingpayment" description:"(user)   get details for a pending payment for the logged in user"`
	UserProposals      UserProposalsCmd         `command:"userproposals" description:"(public) get all proposals submitted by a specific user"`
	Users              shared.UsersCmd          `command:"users" description:"(public) get a list of users"`
	VerifyUserEmail    VerifyUserEmailCmd       `command:"verifyuseremail" description:"(public) verify a user's email address"`
	VerifyUserPayment  VerifyUserPaymentCmd     `command:"verifyuserpayment" description:"(user)   check if the logged in user has paid their user registration fee"`
	Version            shared.VersionCmd        `command:"version" description:"(public) get server info and CSRF token"`
	VettedProposals    VettedProposalsCmd       `command:"vettedproposals" description:"(public) get a page of vetted proposals"`
	Vote               VoteCmd                  `command:"vote" description:"(public) cast votes for a proposal"`
	VoteDetails        VoteDetailsCmd           `command:"votedetails" description:"(public) get the details for a proposal vote"`
	VoteResults        VoteResultsCmd           `command:"voteresults" description:"(public) get vote results for a proposal"`
	VoteStatus         VoteStatusCmd            `command:"votestatus" description:"(public) get the vote status of a proposal"`
	VoteStatuses       VoteStatusesCmd          `command:"votestatuses" description:"(public) get the vote status for all public proposals"`
}

// createMDFile returns a File object that was created using a markdown file
// filled with random text.
func createMDFile() (*v1.File, error) {
	var b bytes.Buffer
	b.WriteString("This is the proposal title\n")

	for i := 0; i < 10; i++ {
		r, err := util.Random(32)
		if err != nil {
			return nil, err
		}
		b.WriteString(base64.StdEncoding.EncodeToString(r) + "\n")
	}

	return &v1.File{
		Name:    "index.md",
		MIME:    mime.DetectMimeType(b.Bytes()),
		Digest:  hex.EncodeToString(util.Digest(b.Bytes())),
		Payload: base64.StdEncoding.EncodeToString(b.Bytes()),
	}, nil
}

// verifyProposal verifies a proposal's merkle root, author signature, and
// censorship record.
func verifyProposal(p v1.ProposalRecord, serverPubKey string) error {
	// Verify merkle root
	if len(p.Files) > 0 {
		mr, err := shared.MerkleRoot(p.Files)
		if err != nil {
			return err
		}
		if mr != p.CensorshipRecord.Merkle {
			return fmt.Errorf("merkle roots do not match")
		}
	}

	// Verify proposal signature
	pid, err := util.IdentityFromString(p.PublicKey)
	if err != nil {
		return err
	}
	sig, err := util.ConvertSignature(p.Signature)
	if err != nil {
		return err
	}
	if !pid.VerifyMessage([]byte(p.CensorshipRecord.Merkle), sig) {
		return fmt.Errorf("could not verify proposal signature")
	}

	// Verify censorship record signature
	id, err := util.IdentityFromString(serverPubKey)
	if err != nil {
		return err
	}
	s, err := util.ConvertSignature(p.CensorshipRecord.Signature)
	if err != nil {
		return err
	}
	msg := []byte(p.CensorshipRecord.Merkle + p.CensorshipRecord.Token)
	if !id.VerifyMessage(msg, s) {
		return fmt.Errorf("could not verify censorship record signature")
	}

	return nil
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

func _main() error {
	// Load config
	_cfg, err := shared.LoadConfig(defaultHomeDir,
		defaultDataDirname, defaultConfigFilename)
	if err != nil {
		return fmt.Errorf("load config: %v", err)
	}

	// Load client
	_client, err := shared.NewClient(_cfg)
	if err != nil {
		return fmt.Errorf("load client: %v", err)
	}

	// Setup global variables for piwww commands
	cfg = _cfg
	client = _client

	// Setup global variables for shared commands
	shared.SetConfig(_cfg)
	shared.SetClient(_client)

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
