// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"time"

	"github.com/decred/politeia/politeiad/api/v1/mime"
	pi "github.com/decred/politeia/politeiawww/api/pi/v1"
	v1 "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
	"github.com/decred/politeia/util"
)

// TODO replace www policies with pi policies

// proposalNewCmd submits a new proposal.
type proposalNewCmd struct {
	Args struct {
		IndexFile   string   `positional-arg-name:"indexfile"`
		Attachments []string `positional-arg-name:"attachments"`
	} `positional-args:"true" optional:"true"`

	// CLI flags
	Name   string `long:"name" optional:"true"`
	LinkTo string `long:"linkto" optional:"true"`
	LinkBy int64  `long:"linkby" optional:"true"`

	// Random generates random proposal data. An IndexFile and
	// Attachments are not required when using this flag.
	Random bool `long:"random" optional:"true"`

	// RFP is a flag that is intended to make submitting an RFP easier
	// by calculating and inserting a linkby timestamp automatically
	// instead of having to pass in a specific timestamp using the
	// --linkby flag.
	RFP bool `long:"rfp" optional:"true"`
}

// Execute executes the new proposal command.
func (cmd *proposalNewCmd) Execute(args []string) error {
	indexFile := cmd.Args.IndexFile
	attachments := cmd.Args.Attachments

	// Validate arguments
	switch {
	case !cmd.Random && indexFile == "":
		return fmt.Errorf("index file not found; you must either provide an " +
			"index.md file or use --random")

	case cmd.Random && indexFile != "":
		return fmt.Errorf("you cannot provide file arguments and use the " +
			"--random flag at the same time")

	case !cmd.Random && cmd.Name == "":
		return fmt.Errorf("you must either provide a proposal name using the " +
			"--name flag or use the --random flag to generate a random name")

	case cmd.RFP && cmd.LinkBy != 0:
		return fmt.Errorf("you cannot use both the --rfp and --linkby flags " +
			"at the same time")
	}

	// Check for user identity. A user identity is required to sign
	// the proposal files and metadata.
	if cfg.Identity == nil {
		return shared.ErrUserIdentityNotFound
	}

	// Prepare index file
	var payload []byte
	if cmd.Random {
		// Generate random text for the index file
		var b bytes.Buffer
		for i := 0; i < 10; i++ {
			r, err := util.Random(32)
			if err != nil {
				return err
			}
			b.WriteString(base64.StdEncoding.EncodeToString(r) + "\n")
		}
		payload = b.Bytes()
	} else {
		// Read the index file from disk
		fp := util.CleanAndExpandPath(indexFile)
		var err error
		payload, err = ioutil.ReadFile(fp)
		if err != nil {
			return fmt.Errorf("ReadFile %v: %v", fp, err)
		}
	}

	files := []pi.File{
		{
			Name:    v1.PolicyIndexFilename,
			MIME:    mime.DetectMimeType(payload),
			Digest:  hex.EncodeToString(util.Digest(payload)),
			Payload: base64.StdEncoding.EncodeToString(payload),
		},
	}

	// Prepare attachment files
	for _, fn := range attachments {
		fp := util.CleanAndExpandPath(fn)
		payload, err := ioutil.ReadFile(fp)
		if err != nil {
			return fmt.Errorf("ReadFile %v: %v", fp, err)
		}

		files = append(files, pi.File{
			Name:    filepath.Base(fn),
			MIME:    mime.DetectMimeType(payload),
			Digest:  hex.EncodeToString(util.Digest(payload)),
			Payload: base64.StdEncoding.EncodeToString(payload),
		})
	}

	// Setup metadata
	if cmd.Random {
		r, err := util.Random(v1.PolicyMinProposalNameLength)
		if err != nil {
			return err
		}
		cmd.Name = hex.EncodeToString(r)
	}
	if cmd.RFP {
		// Set linkby to a month from now
		cmd.LinkBy = time.Now().Add(time.Hour * 24 * 30).Unix()
	}
	pm := pi.ProposalMetadata{
		Name:   cmd.Name,
		LinkTo: cmd.LinkTo,
		LinkBy: cmd.LinkBy,
	}
	pmb, err := json.Marshal(pm)
	if err != nil {
		return err
	}
	metadata := []pi.Metadata{
		{
			Digest:  hex.EncodeToString(util.Digest(pmb)),
			Hint:    pi.HintProposalMetadata,
			Payload: base64.StdEncoding.EncodeToString(pmb),
		},
	}

	// Setup new proposal request
	sig, err := signedMerkleRoot(files, metadata, cfg.Identity)
	if err != nil {
		return err
	}
	pn := pi.ProposalNew{
		Files:     files,
		Metadata:  metadata,
		PublicKey: hex.EncodeToString(cfg.Identity.Public.Key[:]),
		Signature: sig,
	}

	// Send request. The request and response details are printed to
	// the console based on the logging flags that were used.
	err = shared.PrintJSON(pn)
	if err != nil {
		return err
	}
	pnr, err := client.ProposalNew(pn)
	if err != nil {
		return err
	}
	err = shared.PrintJSON(pnr)
	if err != nil {
		return err
	}

	// Verify the censorship record
	/*
		// TODO implement this using pi types
		vr, err := client.Version()
		if err != nil {
			return err
		}
		pr := v1.ProposalRecord{
			Files:            np.Files,
			Metadata:         np.Metadata,
			PublicKey:        np.PublicKey,
			Signature:        np.Signature,
			CensorshipRecord: npr.CensorshipRecord,
		}
		err = shared.VerifyProposal(pr, vr.PubKey)
		if err != nil {
			return fmt.Errorf("unable to verify proposal %v: %v",
				pr.CensorshipRecord.Token, err)
		}
	*/

	return nil
}

// proposalNewHelpMsg is the output of the help command.
const proposalNewHelpMsg = `proposalnew [flags] "indexfile" "attachments" 

Submit a new proposal to Politeia. A proposal is defined as a single markdown
file with the filename "index.md" and optional attachment png files. No other
file types are allowed.

A proposal can be submitted as an RFP (Request for Proposals) by using either
the --rfp flag or by manually specifying a link by deadline using the --linkby
flag. Only one of these flags can be used at a time.

A proposal can be submitted as an RFP submission by using the --linkto flag
to link to and existing RFP proposal.

Arguments:
1. indexfile     (string, required)   Index file
2. attachments   (string, optional)   Attachment files

Flags:
 --name   (string, optional)  The name of the proposal.
 --linkto (string, optional)  Token of an existing public proposal to link to.
 --linkby (int64, optional)   UNIX timestamp of the RFP deadline. Setting this
                              field will make the proposal an RFP with a
                              submission deadline specified by the linkby.
 --random (bool, optional)    Generate a random proposal. If this flag is used
                              then the markdownfile argument is no longer
                              required and any provided files will be ignored.
 --rfp    (bool, optional)    Make the proposal an RFP by setting the linkby to
                              one month from the current time. This is intended
                              to be used in place of --linkby.
`
