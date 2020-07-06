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

// EditProposalCmd edits an existing proposal.
type EditProposalCmd struct {
	Args struct {
		Token       string   `positional-arg-name:"token" required:"true"`
		Markdown    string   `positional-arg-name:"markdownfile"`
		Attachments []string `positional-arg-name:"attachmentfiles"`
	} `positional-args:"true" optional:"true"`
	Name   string `long:"name" optional:"true"`
	LinkTo string `long:"linkto" optional:"true"`
	LinkBy int64  `long:"linkby" optional:"true"`

	// Random can be used in place of editing proposal name & data. When
	// specified, random proposal name & data will be created and submitted.
	Random bool `long:"random" optional:"true"`

	// RFP is a flag that is intended to make editing an RFP easier
	// by calculating and inserting a linkby timestamp automatically
	// instead of having to pass in a specific timestamp using the
	// --linkby flag.
	RFP bool `long:"rfp" optional:"true"`

	// Usemd is a flag that is intended to make editing propsoal metadata easier
	// by using exisiting proposal metadata values instead of having to pass in
	// specific values
	UseMd bool `long:"usemd" optional:"true"`
}

// Execute executes the edit proposal command.
func (cmd *EditProposalCmd) Execute(args []string) error {
	token := cmd.Args.Token
	mdFile := cmd.Args.Markdown
	attachmentFiles := cmd.Args.Attachments

	if !cmd.Random && mdFile == "" {
		return errProposalMDNotFound
	}

	// Check for user identity
	if cfg.Identity == nil {
		return shared.ErrUserIdentityNotFound
	}

	// RFP & linkby flags conflict
	if cmd.RFP && cmd.LinkBy != 0 {
		return errEditProposalRfpAndLinkbyFound
	}

	// Random & name flags conflict
	if cmd.Random && cmd.Name != "" {
		return errEditProposalRandomAndNameFound
	}

	// Get server public key
	vr, err := client.Version()
	if err != nil {
		return err
	}

	var md []byte
	files := make([]v1.File, 0, v1.PolicyMaxImages+1)
	if cmd.Random {
		// Generate random proposal markdown text
		var b bytes.Buffer
		b.WriteString("This is the proposal title\n")

		for i := 0; i < 10; i++ {
			r, err := util.Random(32)
			if err != nil {
				return err
			}
			b.WriteString(base64.StdEncoding.EncodeToString(r) + "\n")
		}

		md = b.Bytes()
	} else {
		// Read markdown file into memory and convert to type File
		fpath := util.CleanAndExpandPath(mdFile)

		var err error
		md, err = ioutil.ReadFile(fpath)
		if err != nil {
			return fmt.Errorf("ReadFile %v: %v", fpath, err)
		}
	}

	f := v1.File{
		Name:    "index.md",
		MIME:    mime.DetectMimeType(md),
		Digest:  hex.EncodeToString(util.Digest(md)),
		Payload: base64.StdEncoding.EncodeToString(md),
	}

	files = append(files, f)

	// Read attachment files into memory and convert to type File
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
	var pm v1.ProposalMetadata

	if cmd.UseMd {
		pdr, err := client.ProposalDetails(cmd.Args.Token,
			&v1.ProposalsDetails{})
		if err != nil {
			return err
		}
		// Prefill existing metadata
		pm.Name = pdr.Proposal.Name
		pm.LinkTo = pdr.Proposal.LinkTo
		pm.LinkBy = pdr.Proposal.LinkBy
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
	metadata := []v1.Metadata{
		{
			Digest:  hex.EncodeToString(util.Digest(pmb)),
			Hint:    v1.HintProposalMetadata,
			Payload: base64.StdEncoding.EncodeToString(pmb),
		},
	}

	// Compute merkle root and sign it
	sig, err := shared.SignedMerkleRoot(files, metadata, cfg.Identity)
	if err != nil {
		return fmt.Errorf("SignMerkleRoot: %v", err)
	}

	// Setup edit proposal request
	ep := &v1.EditProposal{
		Token:     token,
		Files:     files,
		Metadata:  metadata,
		PublicKey: hex.EncodeToString(cfg.Identity.Public.Key[:]),
		Signature: sig,
	}

	// Print request details
	err = shared.PrintJSON(ep)
	if err != nil {
		return err
	}

	// Send request
	epr, err := client.EditProposal(ep)
	if err != nil {
		return err
	}

	// Verify proposal censorship record
	err = shared.VerifyProposal(epr.Proposal, vr.PubKey)
	if err != nil {
		return fmt.Errorf("unable to verify proposal %v: %v",
			epr.Proposal.CensorshipRecord.Token, err)
	}

	// Print response details
	return shared.PrintJSON(epr)
}

// editProposalHelpMsg is the output of the help command when 'editproposal'
// is specified.
const editProposalHelpMsg = `editproposal [flags] "token" "markdownfile" "attachmentfiles" 

Edit a proposal.

Arguments:
1. token             (string, required)   Proposal censorship token
2. markdownfile      (string, required)   Edited proposal 
3. attachmentfiles   (string, optional)   Attachments 

Flags:
  --random   (bool, optional)   Generate a random proposal name & files to submit.
                                If this flag is used then the markdown file 
                                argument is no longer required and any provided files will be
                                ignored.
  --usemd    (bool, optional)   Use the existing metadata if value isn't provided explicitly.
  --name   (string, optional)   The name of the proposal
  --linkto (string, optional)   Token of an existing public proposal to link to. The token is
                                used to populate the LinkTo field in the proposal data JSON file.
  --linkby  (int64, optional)   UNIX timestamp of RFP deadline.
  --rfp      (bool, optional)   Make the proposal an RFP by inserting a LinkBy timestamp into the
                                proposal data JSON file. The LinkBy timestamp is set to be one
                                month from the current time.
                                This is intended to be used in place of --linkby.

Request:
{
  "token":  (string)  Censorship token
    "files": [
      {
        "name":      (string)  Filename 
        "mime":      (string)  Mime type 
        "digest":    (string)  File digest 
        "payload":   (string)  File payload 
      }
    ],
  "publickey": (string)  Public key used to sign proposal
  "signature": (string)  Signature of the merkle root 
}

Response:
{
  "proposal": {
    "name":          (string)       Suggested short proposal name 
    "state":         (PropStateT)   Current state of proposal
    "status":        (PropStatusT)  Current status of proposal
    "timestamp":     (int64)        Timestamp of last update of proposal
    "userid":        (string)       ID of user who submitted proposal
    "username":      (string)       Username of user who submitted proposal
    "publickey":     (string)       Public key used to sign proposal
    "signature":     (string)       Signature of merkle root
    "files": [
      {
        "name":      (string)       Filename 
        "mime":      (string)       Mime type 
        "digest":    (string)       File digest 
        "payload":   (string)       File payload 
      }
    ],
    "numcomments":   (uint)    Number of comments on the proposal
    "version":          (string)  Version of proposal
    "censorshiprecord": {    
      "token":       (string)  Censorship token
      "merkle":      (string)  Merkle root of proposal
      "signature":   (string)  Server side signature of []byte(Merkle+Token)
    }
  }
}`
