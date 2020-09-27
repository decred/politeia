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

// proposalEditCmd edits an existing proposal.
type proposalEditCmd struct {
	Args struct {
		Token       string   `positional-arg-name:"token" required:"true"`
		IndexFile   string   `positional-arg-name:"indexfile"`
		Attachments []string `positional-arg-name:"attachmets"`
	} `positional-args:"true" optional:"true"`

	// CLI flags
	Vetted   bool   `long:"vetted" optional:"true"`
	Unvetted bool   `long:"unvetted" optional:"true"`
	Name     string `long:"name" optional:"true"`
	LinkTo   string `long:"linkto" optional:"true"`
	LinkBy   int64  `long:"linkby" optional:"true"`

	// Random generates random proposal data. An IndexFile and
	// Attachments are not required when using this flag.
	Random bool `long:"random" optional:"true"`

	// RFP is a flag that is intended to make editing an RFP easier
	// by calculating and inserting a linkby timestamp automatically
	// instead of having to pass in a specific timestamp using the
	// --linkby flag.
	RFP bool `long:"rfp" optional:"true"`

	// UseMD is a flag that is intended to make editing proposal
	// metadata easier by using exisiting proposal metadata values
	// instead of having to pass in specific values
	UseMD bool `long:"usemd" optional:"true"`
}

// Execute executes the proposal edit command.
func (cmd *proposalEditCmd) Execute(args []string) error {
	token := cmd.Args.Token
	indexFile := cmd.Args.IndexFile
	attachments := cmd.Args.Attachments

	// Verify arguments
	switch {
	case !cmd.Random && indexFile == "":
		return fmt.Errorf("index file not found; you must either provide an " +
			"index.md file or use --random")
	case cmd.RFP && cmd.LinkBy != 0:
		return fmt.Errorf("--rfp and --linkby can not be used together, as " +
			"--rfp sets the linkby one month from now")
	case cmd.Random && cmd.Name != "":
		return fmt.Errorf("--random and --name can not be used together, as " +
			"--random generates a random name and random proposal data")
	}

	// Verify state
	var state pi.PropStateT
	switch {
	case cmd.Vetted && cmd.Unvetted:
		return fmt.Errorf("cannot use --vetted and --unvetted simultaneously")
	case cmd.Unvetted:
		state = pi.PropStateUnvetted
	case cmd.Vetted:
		state = pi.PropStateVetted
	default:
		return fmt.Errorf("must specify either --vetted or unvetted")
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
	var pm pi.ProposalMetadata
	if cmd.UseMD {
		// Get the existing proposal metadata
		pr, err := proposalRecordLatest(state, cmd.Args.Token)
		if err != nil {
			return err
		}
		pmCurr, err := decodeProposalMetadata(pr.Metadata)
		if err != nil {
			return err
		}

		// Prefill proposal metadata with existing values
		pm.Name = pmCurr.Name
		pm.LinkTo = pmCurr.LinkTo
		pm.LinkBy = pmCurr.LinkBy
	}
	if cmd.Random {
		// Generate random name
		r, err := util.Random(v1.PolicyMinProposalNameLength)
		if err != nil {
			return err
		}
		pm.Name = hex.EncodeToString(r)
	}
	if cmd.RFP {
		// Set linkby to a month from now
		pm.LinkBy = time.Now().Add(time.Hour * 24 * 30).Unix()
	}
	if cmd.Name != "" {
		pm.Name = cmd.Name
	}
	if cmd.LinkBy != 0 {
		pm.LinkBy = cmd.LinkBy
	}
	if cmd.LinkTo != "" {
		pm.LinkTo = cmd.LinkTo
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

	// Setup edit proposal request
	sig, err := signedMerkleRoot(files, metadata, cfg.Identity)
	if err != nil {
		return err
	}
	pe := pi.ProposalEdit{
		Token:     token,
		State:     state,
		Files:     files,
		Metadata:  metadata,
		PublicKey: hex.EncodeToString(cfg.Identity.Public.Key[:]),
		Signature: sig,
	}

	// Send request. The request and response details are printed to
	// the console based on the logging flags that were used.
	err = shared.PrintJSON(pe)
	if err != nil {
		return err
	}
	per, err := client.ProposalEdit(pe)
	if err != nil {
		return err
	}
	err = shared.PrintJSON(per)
	if err != nil {
		return err
	}

	// Verify proposal censorship record
	/*
		// TODO
		vr, err := client.Version()
		if err != nil {
			return err
		}
		err = shared.VerifyProposal(per.Proposal, vr.PubKey)
		if err != nil {
			return fmt.Errorf("unable to verify proposal %v: %v",
				per.Proposal.CensorshipRecord.Token, err)
		}
	*/

	return nil
}

// proposalEditHelpMsg is the output of the help command.
const proposalEditHelpMsg = `editproposal [flags] "token" "indexfile" "attachments" 

Edit a proposal.

Arguments:
1. token         (string, required) Proposal censorship token
2. indexfile     (string, required) Index file
3. attachments   (string, optional) Attachment files

Flags:
  --vetted   (bool, optional)    Comment on vetted record.
  --unvetted (bool, optional)    Comment on unvetted reocrd.
  --random   (bool, optional)    Generate a random proposal name & files to
                                 submit. If this flag is used then the markdown
                                 file argument is no longer required and any 
                                 provided files will be ignored.
  --usemd    (bool, optional)    Use the existing proposal metadata.
  --name     (string, optional)  The name of the proposal.
  --linkto   (string, optional)  Censorship token of an existing public proposal
                                 to link to.
  --linkby   (int64, optional)   UNIX timestamp of RFP deadline.
  --rfp      (bool, optional)    Make the proposal an RFP by inserting a LinkBy
                                 timestamp into the proposal metadata. The LinkBy
                                 timestamp is set to be one month from the
                                 current time. This is intended to be used in
                                 place of --linkby.`
