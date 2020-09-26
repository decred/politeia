// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/decred/dcrd/dcrutil"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	pi "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
	wwwutil "github.com/decred/politeia/politeiawww/util"
	"github.com/decred/politeia/util"
	flags "github.com/jessevdk/go-flags"
)

const (
	// Config settings
	defaultHomeDirname    = "cmswww"
	defaultDataDirname    = "data"
	defaultConfigFilename = "cmswww.conf"
)

var (
	// Global variables for cmswww commands
	cfg    *shared.Config
	client *shared.Client

	// Config settings
	defaultHomeDir = dcrutil.AppDataDir(defaultHomeDirname, false)

	// errInvoiceCSVNotFound is emitted when a invoice csv file is
	// required but has not been passed into the command.
	errInvoiceCSVNotFound = errors.New("invoice csv file not found. " +
		"You must either provide a csv file or use the --random flag.")

	// errInvalidDCCType is emitted if there is a bad dcc type used.
	errInvalidDCCType = errors.New("submitted dcc type is invalid," +
		"must be 1 (Issuance) or 2 (Revocation)")
)

type cmswww struct {
	// XXX the config does not need to be a part of this struct, but
	// is included so that the config cli flags print as part of the
	// cmswww help message. This is handled by go-flags.
	Config shared.Config

	// Commands
	ActiveVotes            ActiveVotesCmd            `command:"activevotes" description:"(user) get the dccs that are being voted on"`
	BatchProposals         BatchProposalsCmd         `command:"batchproposals" description:"(user)   retrieve a set of proposals"`
	NewComment             NewCommentCmd             `command:"newcomment" description:"(user)   create a new comment"`
	CensorComment          CensorCommentCmd          `command:"censorcomment" description:"(admin)  censor a comment"`
	ChangePassword         shared.ChangePasswordCmd  `command:"changepassword" description:"(user)   change the password for the logged in user"`
	ChangeUsername         shared.ChangeUsernameCmd  `command:"changeusername" description:"(user)   change the username for the logged in user"`
	CMSUsers               CMSUsersCmd               `command:"cmsusers" description:"(user)   get a list of cms users"`
	DCCComments            DCCCommentsCmd            `command:"dcccomments" description:"(user)   get the comments for a dcc proposal"`
	DCCDetails             DCCDetailsCmd             `command:"dccdetails" description:"(user)   get the details of a dcc"`
	EditInvoice            EditInvoiceCmd            `command:"editinvoice" description:"(user)   edit a invoice"`
	EditUser               EditUserCmd               `command:"edituser" description:"(user)   edit current cms user information"`
	GeneratePayouts        GeneratePayoutsCmd        `command:"generatepayouts" description:"(admin)  generate a list of payouts with addresses and amounts to pay"`
	GetDCCs                GetDCCsCmd                `command:"getdccs" description:"(user)   get all dccs (optional by status)"`
	Help                   HelpCmd                   `command:"help" description:"         print a detailed help message for a specific command"`
	InvoiceComments        InvoiceCommentsCmd        `command:"invoicecomments" description:"(user)   get the comments for a invoice"`
	InvoiceExchangeRate    InvoiceExchangeRateCmd    `command:"invoiceexchangerate" description:"(user)   get exchange rate for a given month/year"`
	InviteNewUser          InviteNewUserCmd          `command:"invite" description:"(admin)  invite a new user"`
	InvoiceDetails         InvoiceDetailsCmd         `command:"invoicedetails" description:"(public) get the details of a proposal"`
	InvoicePayouts         InvoicePayoutsCmd         `command:"invoicepayouts" description:"(admin)  generate paid invoice list for a given date range"`
	Invoices               InvoicesCmd               `command:"invoices" description:"(user)  get all invoices (optional with optional parameters)"`
	Login                  shared.LoginCmd           `command:"login" description:"(public) login to Politeia"`
	Logout                 shared.LogoutCmd          `command:"logout" description:"(public) logout of Politeia"`
	CMSManageUser          CMSManageUserCmd          `command:"cmsmanageuser" description:"(admin)  edit certain properties of the specified user"`
	ManageUser             shared.ManageUserCmd      `command:"manageuser" description:"(admin)  edit certain properties of the specified user"`
	Me                     shared.MeCmd              `command:"me" description:"(user)   get user details for the logged in user"`
	NewDCC                 NewDCCCmd                 `command:"newdcc" description:"(user)   creates a new dcc proposal"`
	NewDCCComment          NewDCCCommentCmd          `command:"newdcccomment" description:"(user)   creates a new comment on a dcc proposal"`
	NewInvoice             NewInvoiceCmd             `command:"newinvoice" description:"(user)   create a new invoice"`
	PayInvoices            PayInvoicesCmd            `command:"payinvoices" description:"(admin)  set all approved invoices to paid"`
	Policy                 PolicyCmd                 `command:"policy" description:"(public) get the server policy"`
	ProposalOwner          ProposalOwnerCmd          `command:"proposalowner" description:"(user) get owners of a proposal"`
	ProposalBilling        ProposalBillingCmd        `command:"proposalbilling" description:"(user) get billing information for a proposal"`
	ProposalBillingDetails ProposalBillingDetailsCmd `command:"proposalbillingdetails" description:"(admin) get billing information for a proposal"`
	ProposalBillingSummary ProposalBillingSummaryCmd `command:"proposalbillingsummary" description:"(admin) get all approved proposal billing information"`
	RegisterUser           RegisterUserCmd           `command:"register" description:"(public) register an invited user to cms"`
	ResetPassword          shared.ResetPasswordCmd   `command:"resetpassword" description:"(public) reset the password for a user that is not logged in"`
	SetDCCStatus           SetDCCStatusCmd           `command:"setdccstatus" description:"(admin)  set the status of a DCC"`
	SetInvoiceStatus       SetInvoiceStatusCmd       `command:"setinvoicestatus" description:"(admin)  set the status of an invoice"`
	SetTOTP                shared.SetTOTPCmd         `command:"settotp" description:"(user)  set the key for TOTP"`
	StartVote              StartVoteCmd              `command:"startvote" description:"(admin)  start the voting period on a dcc"`
	SupportOpposeDCC       SupportOpposeDCCCmd       `command:"supportopposedcc" description:"(user)   support or oppose a given DCC"`
	TestRun                TestRunCmd                `command:"testrun" description:"         test cmswww routes"`
	TokenInventory         TokenInventoryCmd         `command:"tokeninventory" description:"(user) get the censorship record tokens of all proposals (passthrough)"`
	UpdateUserKey          shared.UpdateUserKeyCmd   `command:"updateuserkey" description:"(user)   generate a new identity for the logged in user"`
	UserDetails            UserDetailsCmd            `command:"userdetails" description:"(user)   get current cms user details"`
	UserInvoices           UserInvoicesCmd           `command:"userinvoices" description:"(user)   get all invoices submitted by a specific user"`
	UserSubContractors     UserSubContractorsCmd     `command:"usersubcontractors" description:"(user)   get all users that are linked to the user"`
	Users                  shared.UsersCmd           `command:"users" description:"(user)   get a list of users"`
	Secret                 shared.SecretCmd          `command:"secret" description:"(user)   ping politeiawww"`
	VerifyTOTP             shared.VerifyTOTPCmd      `command:"verifytotp" description:"(user)  verify the set code for TOTP"`
	Version                shared.VersionCmd         `command:"version" description:"(public) get server info and CSRF token"`
	VoteDCC                VoteDCCCmd                `command:"votedcc" description:"(user) vote for a given DCC during an all contractor vote"`
	VoteDetails            VoteDetailsCmd            `command:"votedetails" description:"(user) get the details for a dcc vote"`
}

// signedMerkleRoot calculates the merkle root of the passed in list of files
// and metadata, signs the merkle root with the passed in identity and returns
// the signature.
func signedMerkleRoot(files []pi.File, md []pi.Metadata, id *identity.FullIdentity) (string, error) {
	if len(files) == 0 {
		return "", fmt.Errorf("no proposal files found")
	}
	mr, err := wwwutil.MerkleRootWWW(files, md)
	if err != nil {
		return "", err
	}
	sig := id.SignMessage([]byte(mr))
	return hex.EncodeToString(sig[:]), nil
}

// verifyInvoice verifies a invoice's merkle root, author signature, and
// censorship record.
func verifyInvoice(p cms.InvoiceRecord, serverPubKey string) error {
	if len(p.Files) > 0 {
		// Verify file digests
		err := shared.ValidateDigests(p.Files, nil)
		if err != nil {
			return err
		}
		// Verify merkle root
		mr, err := wwwutil.MerkleRootWWW(p.Files, nil)
		if err != nil {
			return err
		}
		if mr != p.CensorshipRecord.Merkle {
			return fmt.Errorf("merkle roots do not match")
		}
	}

	// Verify invoice signature
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

// promptList prompts the user with the given prefix, list of valid responses,
// and default list entry to use. The function will repeat the prompt to the
// user until they enter a valid response.
func promptList(reader *bufio.Reader, prefix string, validResponses []string, defaultEntry string) (string, error) {
	// Setup the prompt according to the parameters.
	validStrings := strings.Join(validResponses, "/")
	var prompt string
	if defaultEntry != "" {
		prompt = fmt.Sprintf("%s (%s) [%s]: ", prefix, validStrings,
			defaultEntry)
	} else {
		prompt = fmt.Sprintf("%s (%s): ", prefix, validStrings)
	}

	// Prompt the user until one of the valid responses is given.
	for {
		fmt.Print(prompt)
		reply, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		reply = strings.TrimSpace(strings.ToLower(reply))
		if reply == "" {
			reply = defaultEntry
		}

		for _, validResponse := range validResponses {
			if reply == validResponse {
				return reply, nil
			}
		}
	}
}

// promptListBool prompts the user for a boolean (yes/no) with the given
// prefix. The function will repeat the prompt to the user until they enter a
// valid response.
func promptListBool(reader *bufio.Reader, prefix string, defaultEntry string) (bool, error) {
	// Setup the valid responses.
	valid := []string{"n", "no", "y", "yes"}
	response, err := promptList(reader, prefix, valid, defaultEntry)
	if err != nil {
		return false, err
	}
	return response == "yes" || response == "y", nil
}

func validateParseCSV(data []byte) (*cms.InvoiceInput, error) {
	LineItemType := map[string]cms.LineItemTypeT{
		"labor":   cms.LineItemTypeLabor,
		"expense": cms.LineItemTypeExpense,
		"misc":    cms.LineItemTypeMisc,
		"sub":     cms.LineItemTypeSubHours,
	}
	invInput := &cms.InvoiceInput{}

	// Validate that the invoice is CSV-formatted.
	csvReader := csv.NewReader(strings.NewReader(string(data)))
	csvReader.Comma = cms.PolicyInvoiceFieldDelimiterChar
	csvReader.Comment = cms.PolicyInvoiceCommentChar
	csvReader.TrimLeadingSpace = true

	csvFields, err := csvReader.ReadAll()
	if err != nil {
		return invInput, err
	}

	lineItems := make([]cms.LineItemsInput, 0, len(csvFields))
	// Validate that line items are the correct length and contents in
	// field 4 and 5 are parsable to integers
	for i, lineContents := range csvFields {
		lineItem := cms.LineItemsInput{}
		if len(lineContents) != cms.PolicyInvoiceLineItemCount {
			return invInput,
				fmt.Errorf("invalid number of line items on line: %v want: %v got: %v",
					i, cms.PolicyInvoiceLineItemCount, len(lineContents))
		}
		hours, err := strconv.Atoi(lineContents[5])
		if err != nil {
			return invInput,
				fmt.Errorf("invalid line item hours entered on line: %v", i)
		}
		cost, err := strconv.Atoi(lineContents[6])
		if err != nil {
			return invInput,
				fmt.Errorf("invalid cost entered on line: %v", i)
		}
		rate, err := strconv.Atoi(lineContents[8])
		if err != nil {
			return invInput,
				fmt.Errorf("invalid subrate hours entered on line: %v", i)
		}
		lineItemType, ok := LineItemType[strings.ToLower(lineContents[0])]
		if !ok {
			return invInput,
				fmt.Errorf("invalid line item type on line: %v", i)
		}

		lineItem.Type = lineItemType
		lineItem.Domain = lineContents[1]
		lineItem.Subdomain = lineContents[2]
		lineItem.Description = lineContents[3]
		lineItem.ProposalToken = lineContents[4]
		lineItem.SubUserID = lineContents[7]
		lineItem.SubRate = uint(rate * 100)
		lineItem.Labor = uint(hours * 60)
		lineItem.Expenses = uint(cost * 100)
		lineItems = append(lineItems, lineItem)
	}
	invInput.LineItems = lineItems

	return invInput, nil
}

// verifyDCC verifies a dcc's merkle root, author signature, and censorship
// record.
func verifyDCC(p cms.DCCRecord, serverPubKey string) error {
	files := make([]pi.File, 0, 1)
	files = append(files, p.File)
	// Verify digests
	err := shared.ValidateDigests(files, nil)
	if err != nil {
		return err
	}
	// Verify merkel root
	mr, err := wwwutil.MerkleRootWWW(files, nil)
	if err != nil {
		return err
	}
	if mr != p.CensorshipRecord.Merkle {
		return fmt.Errorf("merkle roots do not match")
	}

	// Verify dcc signature
	pid, err := util.IdentityFromString(p.PublicKey)
	if err != nil {
		return err
	}
	sig, err := util.ConvertSignature(p.Signature)
	if err != nil {
		return err
	}
	if !pid.VerifyMessage([]byte(p.CensorshipRecord.Merkle), sig) {
		return fmt.Errorf("could not verify dcc signature")
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

func _main() error {
	// Load config
	_cfg, err := shared.LoadConfig(defaultHomeDir,
		defaultDataDirname, defaultConfigFilename)
	if err != nil {
		return fmt.Errorf("loading config: %v", err)
	}

	// Load client
	_client, err := shared.NewClient(_cfg)
	if err != nil {
		return fmt.Errorf("loading client: %v", err)
	}

	// Setup global variables for cmswww commands
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
	var cli cmswww
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
