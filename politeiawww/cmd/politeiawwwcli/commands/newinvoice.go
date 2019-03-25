// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package commands

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strconv"

	"github.com/decred/politeia/politeiad/api/v1/mime"
	"github.com/decred/politeia/politeiawww/api/cms/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/util"
)

// NewInvoiceCmd submits a new invoice.
type NewInvoiceCmd struct {
	Args struct {
		Month       string   `positional-arg-name:"month"`           // Invoice Month
		Year        string   `positional-arg-name:"year"`            // Invoice Year
		CSV         string   `positional-arg-name:"csvfile"`         // Invoice CSV file
		Attachments []string `positional-arg-name:"attachmentfiles"` // Invoice attachment files
	} `positional-args:"true" optional:"true"`
	Random bool `long:"random" optional:"true"` // Generate random invoice data
}

// Execute executes the new invoice command.
func (cmd *NewInvoiceCmd) Execute(args []string) error {
	csvFile := cmd.Args.CSV
	attachmentFiles := cmd.Args.Attachments

	month, err := strconv.Atoi(cmd.Args.Month)
	if err != nil {
		return err
	}

	year, err := strconv.Atoi(cmd.Args.Year)
	if err != nil {
		return err
	}

	if !cmd.Random && csvFile == "" {
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

	var csv []byte
	files := make([]www.File, 0, www.PolicyMaxImages+1)
	if cmd.Random {
		// Generate random invoice markdown text
		var b bytes.Buffer
		b.WriteString("This is the invoice title\n")

		for i := 0; i < 10; i++ {
			r, err := util.Random(32)
			if err != nil {
				return err
			}
			b.WriteString(base64.StdEncoding.EncodeToString(r) + "\n")
		}

		csv = b.Bytes()
	} else {
		// Read csv file into memory and convert to type File
		fpath := util.CleanAndExpandPath(csvFile)

		var err error
		csv, err = ioutil.ReadFile(fpath)
		if err != nil {
			return fmt.Errorf("ReadFile %v: %v", fpath, err)
		}
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

	// Setup new proposal request
	ni := &v1.NewInvoice{
		Files:     files,
		PublicKey: hex.EncodeToString(cfg.Identity.Public.Key[:]),
		Signature: sig,
		Month:     uint16(month),
		Year:      uint16(year),
	}

	// Print request details
	err = printJSON(ni)
	if err != nil {
		return err
	}

	// Send request
	nir, err := client.NewInvoice(ni)
	if err != nil {
		return err
	}

	// Verify the censorship record
	pr := www.ProposalRecord{
		Files:            ni.Files,
		PublicKey:        ni.PublicKey,
		Signature:        ni.Signature,
		CensorshipRecord: nir.CensorshipRecord,
	}
	err = verifyProposal(pr, vr.PubKey)
	if err != nil {
		return fmt.Errorf("unable to verify proposal %v: %v",
			pr.CensorshipRecord.Token, err)
	}

	// Print response details
	return printJSON(nir)
}

const newInvoiceHelpMsg = `newinvoice [flags] "csvFile" "attachmentFiles" 

Submit a new invoice to Politeia. Invoice must be a csv file. Accepted 
attachment filetypes: png or plain text.

Arguments:
1. month			 (string, required)   Month (MM, 01-12)
2. year				 (string, required)   Year (YYYY)
3. csvFile			 (string, required)   Invoice CSV file
4. attachmentFiles	 (string, optional)   Attachments 

Flags:
  --random           (bool, optional)     Generate a random invoice

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
  "signature":   (string)  Signed merkel root of files in invoice
}`
