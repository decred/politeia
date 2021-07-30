// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"time"

	"github.com/decred/politeia/politeiad/api/v1/mime"
	piv1 "github.com/decred/politeia/politeiawww/api/pi/v1"
	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
	pclient "github.com/decred/politeia/politeiawww/client"
	"github.com/decred/politeia/politeiawww/cmd/shared"
	"github.com/decred/politeia/util"
)

// cmdProposalNew submits a new proposal.
type cmdProposalNew struct {
	Args struct {
		IndexFile   string   `positional-arg-name:"indexfile"`
		Attachments []string `positional-arg-name:"attachments"`
	} `positional-args:"true" optional:"true"`

	// Metadata fields that can be set by the user
	Name      string `long:"name" optional:"true"`
	LinkTo    string `long:"linkto" optional:"true"`
	LinkBy    string `long:"linkby" optional:"true"`
	Amount    uint64 `long:"amount" optional:"true"`
	StartDate string `long:"startdate" optional:"true"`
	EndDate   string `long:"enddate" optional:"true"`
	Domain    string `long:"domain" optional:"true"`

	// RFP is a flag that is intended to make submitting an RFP easier
	// by calculating and inserting a linkby timestamp automatically
	// instead of having to pass in a timestamp using the --linkby
	// flag.
	RFP bool `long:"rfp" optional:"true"`

	// Random generate random proposal data. The IndexFile argument is
	// not allowed when using this flag.
	Random bool `long:"random" optional:"true"`

	// RandomImages generates random image attachments. The Attachments
	// argument is not allowed when using this flag.
	RandomImages bool `long:"randomimages" optional:"true"`
}

// Execute executes the cmdProposalNew command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdProposalNew) Execute(args []string) error {
	_, err := proposalNew(c)
	if err != nil {
		return err
	}
	return nil
}

// proposalNew creates a new proposal. This function has been pulled out of the
// Execute method so that it can be used in the test commands.
func proposalNew(c *cmdProposalNew) (*rcv1.Record, error) {
	// Unpack args
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
		// Create a index file and random attachments
		files, err = proposalFilesRandom(indexFileSize,
			int(pr.ImageFileCountMax))
		if err != nil {
			return nil, err
		}
	case c.Random:
		// Create a index file
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

	// Setup proposal metadata
	if c.Random {
		if c.Name == "" {
			r, err := util.Random(int(pr.NameLengthMin))
			if err != nil {
				return nil, err
			}
			c.Name = fmt.Sprintf("A Proposal Name %x", r)
		}
		// Set proposal domain if not provided
		if c.Domain == "" {
			// Pick random domain from the pi policy domains.
			randomIndex := rand.Intn(len(pr.Domains))
			c.Domain = pr.Domains[randomIndex]
		}
		// In case of RFP no need to populate startdate, enddate &
		// amount metadata fields.
		if !c.RFP && c.LinkBy == "" {
			// Set start date one month from now if not provided
			if c.StartDate == "" {
				c.StartDate = dateFromUnix(defaultStartDate)
			}
			// Set end date 4 months from now if not provided
			if c.EndDate == "" {
				c.EndDate = dateFromUnix(defaultEndDate)
			}
			if c.Amount == 0 {
				c.Amount = defaultAmount
			}
		}
	}

	pm := piv1.ProposalMetadata{
		Name:   c.Name,
		Amount: c.Amount,
		Domain: c.Domain,
	}
	// Parse start & end dates string timestamps.
	if c.StartDate != "" {
		pm.StartDate, err = unixFromTimestamp(c.StartDate)
		if err != nil {
			return nil, err
		}
	}
	if c.EndDate != "" {
		pm.EndDate, err = unixFromTimestamp(c.EndDate)
		if err != nil {
			return nil, err
		}
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

	// Print proposal to stdout
	printf("Files\n")
	err = printProposalFiles(files)
	if err != nil {
		return nil, err
	}

	// Submit proposal
	sig, err := signedMerkleRoot(files, cfg.Identity)
	if err != nil {
		return nil, err
	}
	n := rcv1.New{
		Files:     files,
		PublicKey: cfg.Identity.Public.String(),
		Signature: sig,
	}
	nr, err := pc.RecordNew(n)
	if err != nil {
		return nil, err
	}

	// Verify record
	vr, err := client.Version()
	if err != nil {
		return nil, err
	}
	err = pclient.RecordVerify(nr.Record, vr.PubKey)
	if err != nil {
		return nil, fmt.Errorf("unable to verify record: %v", err)
	}

	// Print censorship record
	printf("Token  : %v\n", nr.Record.CensorshipRecord.Token)
	printf("Merkle : %v\n", nr.Record.CensorshipRecord.Merkle)
	printf("Receipt: %v\n", nr.Record.CensorshipRecord.Signature)

	return &nr.Record, nil
}

// proposalNewHelpMsg is the printed to stdout by the help command.
const proposalNewHelpMsg = `proposalnew [flags] "indexfile" "attachments" 

Submit a new proposal to Politeia.

A proposal can be submitted as an RFP (Request for Proposals) by using either
the --rfp flag or by manually specifying a link by deadline using the --linkby
flag. Only one of these flags can be used at a time.

A proposal can be submitted as an RFP submission by using the --linkto flag
to link to and an existing RFP proposal.

Arguments:
1. indexfile   (string, optional) Index file.
2. attachments (string, optional) Attachment files.

Flags:
 --name         (string) Name of the proposal.
 
 --amount       (int)    Funding amount in cents.

 --startdate    (string) Start Date, Format: "01/02/2006"

 --enddate      (string) End Date, Format: "01/02/2006"

 --domain       (string) Default supported domains: ["development", 
                         "research", "design", "marketing"]

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

Examples:

# Set linkby 24 hours from current time
$ pictl proposalnew --random --linkby=24h

# Use --rfp to set the linky 1 month from current time
$ pictl proposalnew --rfp index.md proposalmetadata.json
`
