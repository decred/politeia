package commands

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"path/filepath"

	"github.com/decred/politeia/politeiad/api/v1/mime"
	"github.com/decred/politeia/politeiawww/api/cms/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/util"
)

// EditInvoiceCmd edits an existing invoice.
type EditInvoiceCmd struct {
	Args struct {
		Token       string   `positional-arg-name:"token" required:"true"` // Censorship token
		CSV         string   `positional-arg-name:"csvfile"`               // Invoice CSV file
		Attachments []string `positional-arg-name:"attachmentfiles"`       // Invoice attachments
	} `positional-args:"true" optional:"true"`
}

// Execute executes the edit invoice command.
func (cmd *EditInvoiceCmd) Execute(args []string) error {
	token := cmd.Args.Token
	csvFile := cmd.Args.CSV
	attachmentFiles := cmd.Args.Attachments

	if csvFile == "" {
		return errInvoiceCSVNotFound
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

	files := make([]www.File, 0, www.PolicyMaxImages+1)
	// Read markdown file into memory and convert to type File
	fpath := util.CleanAndExpandPath(csvFile)

	csv, err := ioutil.ReadFile(fpath)
	if err != nil {
		return fmt.Errorf("ReadFile %v: %v", fpath, err)
	}

	f := www.File{
		Name:    "invoice.csv",
		MIME:    mime.DetectMimeType(csv),
		Digest:  hex.EncodeToString(util.Digest(csv)),
		Payload: base64.StdEncoding.EncodeToString(csv),
	}

	files = append(files, f)

	// Read attachment files into memory and convert to type File
	for _, file := range attachmentFiles {
		path := util.CleanAndExpandPath(file)
		attachment, err := ioutil.ReadFile(path)
		if err != nil {
			return fmt.Errorf("ReadFile %v: %v", path, err)
		}

		f := www.File{
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

	// Setup edit invoice request
	ei := &v1.EditInvoice{
		Token:     token,
		Files:     files,
		PublicKey: hex.EncodeToString(cfg.Identity.Public.Key[:]),
		Signature: sig,
	}

	// Print request details
	err = printJSON(ei)
	if err != nil {
		return err
	}

	// Send request
	eir, err := client.EditInvoice(ei)
	if err != nil {
		return err
	}

	// Verify the censorship record
	pr := www.ProposalRecord{
		Files:            ei.Files,
		PublicKey:        ei.PublicKey,
		Signature:        ei.Signature,
		CensorshipRecord: eir.Invoice.CensorshipRecord,
	}
	err = verifyProposal(pr, vr.PubKey)
	if err != nil {
		return fmt.Errorf("unable to verify invoice %v: %v",
			eir.Invoice.CensorshipRecord.Token, err)
	}

	// Print response details
	return printJSON(eir)
}

// editInvoiceHelpMsg is the output of the help command when 'editinvoice'
// is specified.
const editInvoiceHelpMsg = `editinvoice [flags] "token" "csvfile" "attachmentfiles" 

Edit a invoice.

Arguments:
1. token             (string, required)   Invoice censorship token
2. csvfile           (string, required)   Edited invoice 
3. attachmentfiles   (string, optional)   Attachments 

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
  "publickey": (string)  Public key used to sign invoice
  "signature": (string)  Signature of the merkle root 
}

Response:
{
  "invoice": {
    "name":          (string)       Suggested short invoice name 
    "state":         (PropStateT)   Current state of invoice
    "status":        (PropStatusT)  Current status of invoice
    "timestamp":     (int64)        Timestamp of last update of invoice
    "userid":        (string)       ID of user who submitted invoice
    "username":      (string)       Username of user who submitted invoice
    "publickey":     (string)       Public key used to sign invoice
    "signature":     (string)       Signature of merkle root
    "files": [
      {
        "name":      (string)       Filename 
        "mime":      (string)       Mime type 
        "digest":    (string)       File digest 
        "payload":   (string)       File payload 
      }
    ],
    "numcomments":   (uint)    Number of comments on the invoice
    "version": 		 (string)  Version of invoice
    "censorshiprecord": {	
      "token":       (string)  Censorship token
      "merkle":      (string)  Merkle root of invoice
      "signature":   (string)  Server side signature of []byte(Merkle+Token)
    }
  }
}`
