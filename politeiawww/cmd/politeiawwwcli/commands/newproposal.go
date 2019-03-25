package commands

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"path/filepath"

	"github.com/decred/politeia/politeiad/api/v1/mime"
	"github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/util"
)

// NewProposalCmd submits a new proposal.
type NewProposalCmd struct {
	Args struct {
		Markdown    string   `positional-arg-name:"markdownfile"`    // Proposal MD file
		Attachments []string `positional-arg-name:"attachmentfiles"` // Proposal attachment files
	} `positional-args:"true" optional:"true"`
	Random bool `long:"random" optional:"true"` // Generate random proposal data
}

// Execute executes the new proposal command.
func (cmd *NewProposalCmd) Execute(args []string) error {
	mdFile := cmd.Args.Markdown
	attachmentFiles := cmd.Args.Attachments

	if !cmd.Random && mdFile == "" {
		return errProposalMDNotFound
	}

	// Check for user identity
	if cfg.Identity == nil {
		return errUserIdentityNotFound
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
		// Read  markdown file into memory and convert to type File
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

	// Compute merkle root and sign it
	sig, err := signedMerkleRoot(files, cfg.Identity)
	if err != nil {
		return fmt.Errorf("SignMerkleRoot: %v", err)
	}

	// Setup new proposal request
	np := &v1.NewProposal{
		Files:     files,
		PublicKey: hex.EncodeToString(cfg.Identity.Public.Key[:]),
		Signature: sig,
	}

	// Print request details
	err = printJSON(np)
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
	return printJSON(npr)
}

const newProposalHelpMsg = `newproposal [flags] "markdownFile" "attachmentFiles" 

Submit a new proposal to Politeia. Proposal must be a markdown file. Accepted 
attachment filetypes: png or plain text.

Arguments:
1. markdownFile      (string, required)   Proposal 
2. attachmentFiles   (string, optional)   Attachments 

Flags:
  --random           (bool, optional)     Generate a random proposal

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
