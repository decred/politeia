// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/decred/politeia/politeiad/api/v1/mime"
	piv1 "github.com/decred/politeia/politeiawww/api/pi/v1"
	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
	pclient "github.com/decred/politeia/politeiawww/client"
	"github.com/decred/politeia/politeiawww/cmd/shared"
	"github.com/decred/politeia/util"
)

// cmdProposalEdit edits an existing proposal.
type cmdProposalEdit struct {
	Args struct {
		Token       string   `positional-arg-name:"token" required:"true"`
		IndexFile   string   `positional-arg-name:"indexfile"`
		Attachments []string `positional-arg-name:"attachmets"`
	} `positional-args:"true" optional:"true"`

	// UseMD is a flag that is intended to make editing proposal
	// metadata easier by using exisiting proposal metadata values
	// instead of having to pass in specific values.
	UseMD bool `long:"usemd" optional:"true"`

	// Metadata fields that can be set by the user
	Name   string `long:"name" optional:"true"`
	LinkTo string `long:"linkto" optional:"true"`
	LinkBy string `long:"linkby" optional:"true"`

	// RFP is a flag that is intended to make submitting an RFP easier
	// by calculating and inserting a linkby timestamp automatically
	// instead of having to pass in a timestamp using the --linkby
	// flag.
	RFP bool `long:"rfp" optional:"true"`

	// Random generates a random index file. The IndexFile argument is
	// not allowed when using this flag.
	Random bool `long:"random" optional:"true"`

	// RandomImages generates random image attachments. The Attachments
	// argument is not allowed when using this flag.
	RandomImages bool `long:"randomimages" optional:"true"`
}

// Execute executes the cmdProposalEdit command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdProposalEdit) Execute(args []string) error {
	_, err := proposalEdit(c)
	if err != nil {
		return err
	}
	return nil
}

// proposalEdit edits a proposal. This function has been pulled out of the
// Execute method so that is can be used in the test commands.
func proposalEdit(c *cmdProposalEdit) (*rcv1.Record, error) {
	// Unpack args
	token := c.Args.Token
	indexFile := c.Args.IndexFile
	attachments := c.Args.Attachments

	// Verify args and flags
	switch {
	case !c.Random && indexFile == "":
		return nil, fmt.Errorf("index file not found; you must either " +
			"provide an index.md file or use --random")

	case c.RandomImages && len(attachments) > 0:
		return nil, fmt.Errorf("you cannot provide attachment files and " +
			"use the --randomimages flag at the same time")

	case c.RFP && c.LinkBy != "":
		return nil, fmt.Errorf("you cannot use both the --rfp and --linkby " +
			"flags at the same time")
	}

	// Check for user identity. A user identity is required to sign
	// the proposal files.
	if cfg.Identity == nil {
		return nil, shared.ErrUserIdentityNotFound
	}

	// Setup client
	opts := pclient.Opts{
		HTTPSCert:  cfg.HTTPSCert,
		Cookies:    cfg.Cookies,
		HeaderCSRF: cfg.CSRF,
		Verbose:    cfg.Verbose,
		RawJSON:    cfg.RawJSON,
	}
	pc, err := pclient.New(cfg.Host, opts)
	if err != nil {
		return nil, err
	}

	// Get the pi policy. It contains the proposal requirements.
	pr, err := pc.PiPolicy()
	if err != nil {
		return nil, err
	}

	// Setup proposal files
	indexFileSize := 10000 // In bytes
	var files []rcv1.File
	switch {
	case c.Random && c.RandomImages:
		// Create a random index file and random attachments
		files, err = proposalFilesRandom(indexFileSize,
			int(pr.ImageFileCountMax))
		if err != nil {
			return nil, err
		}
	case c.Random:
		// Create a random index file
		files, err = proposalFilesRandom(indexFileSize, 0)
		if err != nil {
			return nil, err
		}
	default:
		// Read files from disk
		files, err = proposalFilesFromDisk(indexFile, attachments)
		if err != nil {
			return nil, err
		}
	}

	// Get current proposal if we are using the existing metadata
	var curr *rcv1.Record
	if c.UseMD {
		d := rcv1.Details{
			Token: token,
		}
		curr, err = pc.RecordDetails(d)
		if err != nil {
			return nil, err
		}
	}

	// Setup proposal metadata
	switch {
	case c.UseMD:
		// Use the existing proposal name
		pm, err := pclient.ProposalMetadataDecode(curr.Files)
		if err != nil {
			return nil, err
		}
		c.Name = pm.Name
	case c.Random && c.Name == "":
		// Create a random proposal name
		r, err := util.Random(int(pr.NameLengthMin))
		if err != nil {
			return nil, err
		}
		c.Name = hex.EncodeToString(r)
	}
	pm := piv1.ProposalMetadata{
		Name: c.Name,
	}
	pmb, err := json.Marshal(pm)
	if err != nil {
		return nil, err
	}
	files = append(files, rcv1.File{
		Name:    piv1.FileNameProposalMetadata,
		MIME:    mime.DetectMimeType(pmb),
		Digest:  hex.EncodeToString(util.Digest(pmb)),
		Payload: base64.StdEncoding.EncodeToString(pmb),
	})

	// Setup vote metadata
	var linkBy int64
	switch {
	case c.UseMD:
		// Use existing vote metadata values
		vm, err := pclient.VoteMetadataDecode(curr.Files)
		if err != nil {
			return nil, err
		}
		linkBy = vm.LinkBy
		c.LinkTo = vm.LinkTo
	case c.RFP:
		// Set linkby to a month from now
		linkBy = time.Now().Add(time.Hour * 24 * 30).Unix()
	case c.LinkBy != "":
		// Parse the provided linkby
		d, err := time.ParseDuration(c.LinkBy)
		if err != nil {
			return nil, fmt.Errorf("unable to parse linkby: %v", err)
		}
		linkBy = time.Now().Add(d).Unix()
	}
	if linkBy != 0 || c.LinkTo != "" {
		vm := piv1.VoteMetadata{
			LinkTo: c.LinkTo,
			LinkBy: linkBy,
		}
		vmb, err := json.Marshal(vm)
		if err != nil {
			return nil, err
		}
		files = append(files, rcv1.File{
			Name:    piv1.FileNameVoteMetadata,
			MIME:    mime.DetectMimeType(vmb),
			Digest:  hex.EncodeToString(util.Digest(vmb)),
			Payload: base64.StdEncoding.EncodeToString(vmb),
		})
	}

	// Edit record
	sig, err := signedMerkleRoot(files, cfg.Identity)
	if err != nil {
		return nil, err
	}
	e := rcv1.Edit{
		Token:     token,
		Files:     files,
		PublicKey: cfg.Identity.Public.String(),
		Signature: sig,
	}
	er, err := pc.RecordEdit(e)
	if err != nil {
		return nil, err
	}

	// Verify record
	vr, err := client.Version()
	if err != nil {
		return nil, err
	}
	err = pclient.RecordVerify(er.Record, vr.PubKey)
	if err != nil {
		return nil, fmt.Errorf("unable to verify record: %v", err)
	}

	// Print proposal to stdout
	printf("Proposal editted\n")
	err = printProposal(er.Record)
	if err != nil {
		return nil, err
	}

	return &er.Record, nil
}

// proposalEditHelpMsg is the printed to stdout by the help command.
const proposalEditHelpMsg = `editproposal [flags] "token" "indexfile" "attachments" 

Edit an existing proposal.

A proposal can be submitted as an RFP (Request for Proposals) by using either
the --rfp flag or by manually specifying a link by deadline using the --linkby
flag. Only one of these flags can be used at a time.

A proposal can be submitted as an RFP submission by using the --linkto flag
to link to and an existing RFP proposal.

Arguments:
1. token       (string, required) Proposal censorship token.
2. indexfile   (string, optional) Index file.
3. attachments (string, optional) Attachment files.

Flags:
 --usemd        (bool)   Use the existing proposal metadata.

 --name         (string) Name of the proposal.

 --linkto       (string) Token of an existing public proposal to link to.

 --linkby       (string) Make the proposal and RFP by setting the linkby
                         deadline. Other proposals must be entered as RFP
                         submissions by this linkby deadline. The provided
                         string should be a duration that will be added onto
                         the current time. Valid duration units are:
                         s (seconds), m (minutes), h (hours).

 --rfp          (bool)   Make the proposal an RFP by setting the linkby to one
                         month from the current time. This is intended to be
                         used in place of --linkby.

 --random       (bool)   Generate random proposal data, not including
                         attachments. The indexFile argument is not allowed
                         when using this flag.

 --randomimages (bool)   Generate random attachments. The attachments argument
                         is not allowed when using this flag.
`
