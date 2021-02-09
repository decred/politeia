// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"time"

	"github.com/decred/politeia/politeiad/api/v1/mime"
	piplugin "github.com/decred/politeia/politeiad/plugins/pi"
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
	Name   string `long:"name" optional:"true"`
	LinkTo string `long:"linkto" optional:"true"`
	LinkBy string `long:"linkby" optional:"true"`

	// Random generates random proposal data. An IndexFile and
	// Attachments are not required when using this flag.
	Random bool `long:"random" optional:"true"`

	// RFP is a flag that is intended to make submitting an RFP easier
	// by calculating and inserting a linkby timestamp automatically
	// instead of having to pass in a timestamp using the --linkby
	// flag.
	RFP bool `long:"rfp" optional:"true"`
}

// Execute executes the cmdProposalNew command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdProposalNew) Execute(args []string) error {
	// Unpack args
	indexFile := c.Args.IndexFile
	attachments := c.Args.Attachments

	// Verify args and flags
	switch {
	case !c.Random && indexFile == "":
		return fmt.Errorf("index file not found; you must either " +
			"provide an index.md file or use --random")

	case c.Random && indexFile != "":
		return fmt.Errorf("you cannot provide file arguments and use " +
			"the --random flag at the same time")

	case c.RFP && c.LinkBy != "":
		return fmt.Errorf("you cannot use both the --rfp and --linkby " +
			"flags at the same time")
	}

	// Check for user identity. A user identity is required to sign
	// the proposal files.
	if cfg.Identity == nil {
		return shared.ErrUserIdentityNotFound
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
		return err
	}

	// Get the pi policy. It contains the proposal requirements.
	pr, err := pc.PiPolicy()
	if err != nil {
		return err
	}

	// Setup index file
	files := make([]rcv1.File, 0, 16)
	if c.Random {
		// Generate random text for the index file
		f, err := indexFileRandom(1024)
		if err != nil {
			return err
		}
		files = append(files, *f)
	} else {
		// Read index file from disk
		fp := util.CleanAndExpandPath(indexFile)
		var err error
		payload, err := ioutil.ReadFile(fp)
		if err != nil {
			return fmt.Errorf("ReadFile %v: %v", fp, err)
		}
		files = append(files, rcv1.File{
			Name:    piplugin.FileNameIndexFile,
			MIME:    mime.DetectMimeType(payload),
			Digest:  hex.EncodeToString(util.Digest(payload)),
			Payload: base64.StdEncoding.EncodeToString(payload),
		})
	}

	// Setup attachment files
	for _, fn := range attachments {
		fp := util.CleanAndExpandPath(fn)
		payload, err := ioutil.ReadFile(fp)
		if err != nil {
			return fmt.Errorf("ReadFile %v: %v", fp, err)
		}

		files = append(files, rcv1.File{
			Name:    filepath.Base(fn),
			MIME:    mime.DetectMimeType(payload),
			Digest:  hex.EncodeToString(util.Digest(payload)),
			Payload: base64.StdEncoding.EncodeToString(payload),
		})
	}

	// Setup proposal metadata
	if c.Random && c.Name == "" {
		r, err := util.Random(int(pr.NameLengthMin))
		if err != nil {
			return err
		}
		c.Name = fmt.Sprintf("A Proposal Name %x", r)
	}
	pm := piv1.ProposalMetadata{
		Name: c.Name,
	}
	pmb, err := json.Marshal(pm)
	if err != nil {
		return err
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
			return fmt.Errorf("unable to parse linkby: %v", err)
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
			return err
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
		return err
	}

	// Setup request
	sig, err := signedMerkleRoot(files, cfg.Identity)
	if err != nil {
		return err
	}
	n := rcv1.New{
		Files:     files,
		PublicKey: cfg.Identity.Public.String(),
		Signature: sig,
	}

	// Send request
	nr, err := pc.RecordNew(n)
	if err != nil {
		return err
	}

	// Verify record
	vr, err := client.Version()
	if err != nil {
		return err
	}
	err = pclient.RecordVerify(nr.Record, vr.PubKey)
	if err != nil {
		return fmt.Errorf("unable to verify record: %v", err)
	}

	// Print censorship record
	printf("Token  : %v\n", nr.Record.CensorshipRecord.Token)
	printf("Merkle : %v\n", nr.Record.CensorshipRecord.Merkle)
	printf("Receipt: %v\n", nr.Record.CensorshipRecord.Signature)

	return nil
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
1. indexfile   (string, required)  Index file
2. attachments (string)            Attachment files

Flags:
 --name   (string) Name of the proposal.
 --linkto (string) Token of an existing public proposal to link to.
 --linkby (string) UNIX timestamp of the RFP deadline. Setting this field will
                   make the proposal an RFP with a submission deadline set by
                   the linkby. Valid linkby units are:
                   s (seconds), m (minutes), h (hours)
 --random (bool)   Generate a random proposal. If this flag is used then the  
                   markdownfile argument is no longer required and any
                   provided files will be ignored.
 --rfp    (bool)   Make the proposal an RFP by setting the linkby to one month
                   from the current time. This is intended to be used in place
                   of --linkby.

Examples:

# Set linkby 24 hours from current time
$ pictl proposalnew --random --linkby=24h

# Use --rfp to set the linky 1 month from current time
$ pictl proposalnew --rfp index.md proposalmetadata.json
`
