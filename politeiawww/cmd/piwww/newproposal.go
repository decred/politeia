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
		Markdown    string   `positional-arg-name:"markdownfile"`    // Proposal MD file
		Attachments []string `positional-arg-name:"attachmentfiles"` // Proposal attachment files
	} `positional-args:"true" optional:"true"`
	Random bool   `long:"random" optional:"true"` // Generate random proposal data
	Name   string `long:"name" optional:"true"`
	RFP    bool   `long:"rfp" optional:"true"`    // Insert a LinkBy timestamp to indicate an RFP
	LinkTo string `long:"linkto" optional:"true"` // Censorship token of prop to link to
}

// Execute executes the new proposal command.
func (cmd *NewProposalCmd) Execute(args []string) error {
	mdFile := cmd.Args.Markdown
	attachmentFiles := cmd.Args.Attachments

	switch {
	case !cmd.Random && mdFile == "":
		return errProposalMDNotFound
	case !cmd.Random && cmd.Name == "":
		return fmt.Errorf("you must either provide a proposal name using the " +
			"--name flag or use the --random flag to generate a random name")
	}

	// Check for user identity
	if cfg.Identity == nil {
		return shared.ErrUserIdentityNotFound
	}

	// Get server public key
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
	if cmd.Name == "" {
		cmd.Name = "Some proposal title"
	}
	pm := v1.ProposalMetadata{
		Name: cmd.Name,
	}
	if cmd.RFP {
		// Double the minimum LinkBy period to give a buffer
		t := time.Second * v1.PolicyLinkByMinPeriod * 2
		pm.LinkBy = time.Now().Add(t).Unix()
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

	// Setup new proposal request
	np := &v1.NewProposal{
		Files:     files,
		Metadata:  metadata,
		PublicKey: hex.EncodeToString(cfg.Identity.Public.Key[:]),
		Signature: sig,
	}

	// Print request details
	err = shared.PrintJSON(np)
	if err != nil {
		return err
	}

	// Send request
	npr, err := client.NewProposal(np)
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
	err = verifyProposal(pr, vr.PubKey)
	if err != nil {
		return fmt.Errorf("unable to verify proposal %v: %v",
			pr.CensorshipRecord.Token, err)
	}

	// Print response details
	return shared.PrintJSON(npr)
}

const newProposalHelpMsg = `newproposal [flags] "markdownFile" "attachmentFiles" 

Submit a new proposal to Politeia. Proposal must be a markdown file. Accepted 
attachment filetypes: png or plain text.

Arguments:
1. markdownFile      (string, required)   Proposal 
2. attachmentFiles   (string, optional)   Attachments 

Flags:
  --random   (bool, optional)    Generate a random proposal.
  --rfp      (bool, optional)    Make the proposal an RFP by inserting a LinkBy timestamp into the
                                 proposal data JSON file. The LinkBy timestamp is set to be one
																 week from the current time.
  --linkto   (string, optional)  Token of an existing public proposal to link to. The token is
                                 used to populate the LinkTo field in the proposal data JSON file.

Result:
{
  "files": [
    {
      "name":      (string)  Filename 
      "mime":      (string)  Mime type 
      "digest":    (string)  File digest 
      "payload":   (string)  File payload 
    }
  ],
  "publickey":   (string)  Public key of user
  "signature":   (string)  Signed merkel root of files in proposal 
}`
