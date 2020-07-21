// Copyright (c) 2017-2019 The Decred developers
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
	v1 "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
	"github.com/decred/politeia/util"
)

// NewProposalCmd submits a new proposal.
type NewProposalCmd struct {
	Args struct {
		Markdown    string   `positional-arg-name:"markdownfile"`
		Attachments []string `positional-arg-name:"attachmentfiles"`
	} `positional-args:"true" optional:"true"`
	Name   string `long:"name" optional:"true"`
	LinkTo string `long:"linkto" optional:"true"`
	LinkBy int64  `long:"linkby" optional:"true"`

	// Random can be used in place of submitting proposal files. When
	// specified, random proposal data will be created and submitted.
	// The --random flag cannot be used if proposal files are provided
	// as arguments.
	Random bool `long:"random" optional:"true"`

	// RFP is a flag that is intended to make submitting an RFP easier
	// by calculating and inserting a linkby timestamp automatically
	// instead of having to pass in a specific timestamp using the
	// --linkby flag.
	RFP bool `long:"rfp" optional:"true"`
}

// Execute executes the new proposal command.
func (cmd *NewProposalCmd) Execute(args []string) error {
	mdFile := cmd.Args.Markdown
	attachmentFiles := cmd.Args.Attachments

	// Validate arguments
	switch {
	case cmd.Random && mdFile != "":
		return fmt.Errorf("you cannot provide file arguments and use the " +
			"--random flag at the same time")
	case !cmd.Random && mdFile == "":
		return errProposalMDNotFound
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

	// Get server public key. This will be used to verify the reply.
	vr, err := client.Version()
	if err != nil {
		return err
	}

	// Prepare proposal index file
	var md []byte
	files := make([]v1.File, 0, v1.PolicyMaxImages+1)
	if cmd.Random {
		// Generate random proposal markdown text
		var b bytes.Buffer
		for i := 0; i < 10; i++ {
			r, err := util.Random(32)
			if err != nil {
				return err
			}
			b.WriteString(base64.StdEncoding.EncodeToString(r) + "\n")
		}

		md = b.Bytes()
	} else {
		// Read  markdown file into memory and convert to type File
		fpath := util.CleanAndExpandPath(mdFile)

		var err error
		md, err = ioutil.ReadFile(fpath)
		if err != nil {
			return fmt.Errorf("ReadFile %v: %v", fpath, err)
		}
	}

	f := v1.File{
		Name:    v1.PolicyIndexFilename,
		MIME:    mime.DetectMimeType(md),
		Digest:  hex.EncodeToString(util.Digest(md)),
		Payload: base64.StdEncoding.EncodeToString(md),
	}

	files = append(files, f)

	// Prepare attachment files
	for _, file := range attachmentFiles {
		path := util.CleanAndExpandPath(file)
		attachment, err := ioutil.ReadFile(path)
		if err != nil {
			return fmt.Errorf("ReadFile %v: %v", path, err)
		}

		f := v1.File{
			Name:    filepath.Base(file),
			MIME:    mime.DetectMimeType(attachment),
			Digest:  hex.EncodeToString(util.Digest(attachment)),
			Payload: base64.StdEncoding.EncodeToString(attachment),
		}

		files = append(files, f)
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
	pm := v1.ProposalMetadata{
		Name:   cmd.Name,
		LinkTo: cmd.LinkTo,
		LinkBy: cmd.LinkBy,
	}
	pmb, err := json.Marshal(pm)
	if err != nil {
		return err
	}
	metadata := []v1.Metadata{
		{
			Digest:  hex.EncodeToString(util.Digest(pmb)),
			Hint:    v1.HintProposalMetadata,
			Payload: base64.StdEncoding.EncodeToString(pmb),
		},
	}

	// Setup new proposal request
	sig, err := shared.SignedMerkleRoot(files, metadata, cfg.Identity)
	if err != nil {
		return err
	}
	np := &v1.NewProposal{
		Files:     files,
		Metadata:  metadata,
		PublicKey: hex.EncodeToString(cfg.Identity.Public.Key[:]),
		Signature: sig,
	}

	// Send the new proposal request. The request and response details
	// are printed to the console based on the logging flags that are
	// used.
	err = shared.PrintJSON(np)
	if err != nil {
		return err
	}
	npr, err := client.NewProposal(np)
	if err != nil {
		return err
	}
	err = shared.PrintJSON(npr)
	if err != nil {
		return err
	}

	// Verify the censorship record
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

	return nil
}

const newProposalHelpMsg = `newproposal [flags] "markdownFile" "attachmentFiles" 

Submit a new proposal to Politeia. A proposal is defined as a single markdown
file with the filename "index.md" and optional attachment png files. No other
file types are allowed.

A proposal can be submitted as an RFP (Request for Proposals) by using either
the --rfp flag or by manually specifying a link by deadline using the --linkby
flag. Only one of these flags can be used at a time.

A proposal can be submitted as an RFP submission by using the --linkto flag
to link to and existing RFP proposal.

Arguments:
1. markdownFile      (string, required)   Proposal 
2. attachmentFiles   (string, optional)   Attachments 

Flags:
 --name   (string, optional)  The name of the proposal
 --linkto (string, optional)  Token of an existing public proposal to link to.
 --linkby (int64, optional)   UNIX timestamp of RFP deadline. Setting the linkby of a proposal will
                              make the proposal an RFP with a submission deadline specified by the
                              linkby.
 --random (bool, optional)    Generate a random proposal. If this flag is used then the markdown
                              file argument is no longer required and any provided files will be
                              ignored.
 --rfp    (bool, optional)    Make the proposal an RFP by setting the linkby to one month from the
                              current time. This is intended to be used in place of --linkby.
`
