// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/thi4go/politeia/politeiad/api/v1/mime"
	"github.com/thi4go/politeia/politeiawww/api/cms/v1"
	www "github.com/thi4go/politeia/politeiawww/api/www/v1"
	"github.com/thi4go/politeia/politeiawww/cmd/shared"
	"github.com/thi4go/politeia/util"
)

// EditInvoiceCmd edits an existing invoice.
type EditInvoiceCmd struct {
	Args struct {
		Month       uint     `positional-arg-name:"month" required:"true"`
		Year        uint     `positional-arg-name:"year"`
		Token       string   `positional-arg-name:"token"`           // Censorship token
		CSV         string   `positional-arg-name:"csvfile"`         // Invoice CSV file
		Attachments []string `positional-arg-name:"attachmentfiles"` // Invoice attachments
	} `positional-args:"true" optional:"true"`
	Name           string `long:"name" optional:"true" description:"Full name of the contractor"`
	Contact        string `long:"contact" optional:"true" description:"Email address or contact of the contractor"`
	Location       string `long:"location" optional:"true" description:"Location (e.g. Dallas, TX, USA) of the contractor"`
	PaymentAddress string `long:"paymentaddress" optional:"true" description:"Payment address for this invoice."`
	Rate           string `long:"rate" optional:"true" description:"Hourly rate for labor."`
}

// Execute executes the edit invoice command.
func (cmd *EditInvoiceCmd) Execute(args []string) error {
	month := cmd.Args.Month
	year := cmd.Args.Year
	token := cmd.Args.Token
	csvFile := cmd.Args.CSV
	attachmentFiles := cmd.Args.Attachments

	if csvFile == "" {
		return errInvoiceCSVNotFound
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

	if cmd.Name == "" || cmd.Location == "" || cmd.PaymentAddress == "" {
		reader := bufio.NewReader(os.Stdin)
		if cmd.Name == "" {
			fmt.Print("Enter name for the invoice: ")
			cmd.Name, _ = reader.ReadString('\n')
		}
		if cmd.Contact == "" {
			fmt.Print("Enter email to associate with this invoice: ")
			cmd.Contact, _ = reader.ReadString('\n')
		}
		if cmd.Location == "" {
			fmt.Print("Enter location to associate with this invoice: ")
			cmd.Location, _ = reader.ReadString('\n')
		}
		if cmd.PaymentAddress == "" {
			fmt.Print("Enter payment address for this invoice: ")
			cmd.PaymentAddress, _ = reader.ReadString('\n')
		}
		if cmd.Rate == "" {
			fmt.Print("Enter hourly rate for this invoice: ")
			cmd.Rate, _ = reader.ReadString('\n')
		}
		fmt.Print("\nPlease carefully review your information and ensure it's " +
			"correct. If not, press Ctrl + C to exit. Or, press Enter to continue " +
			"your registration.")
		reader.ReadString('\n')
	}

	var csv []byte
	files := make([]www.File, 0, www.PolicyMaxImages+1)
	// Read markdown file into memory and convert to type File
	fpath := util.CleanAndExpandPath(csvFile)
	csv, err = ioutil.ReadFile(fpath)
	if err != nil {
		return fmt.Errorf("ReadFile %v: %v", fpath, err)
	}

	invInput, err := validateParseCSV(csv)
	if err != nil {
		return fmt.Errorf("Parsing CSV failed: %v", err)
	}

	invInput.Month = month
	invInput.Year = year
	invInput.ContractorName = strings.TrimSpace(cmd.Name)
	invInput.ContractorLocation = strings.TrimSpace(cmd.Location)
	invInput.ContractorContact = strings.TrimSpace(cmd.Contact)
	invInput.PaymentAddress = strings.TrimSpace(cmd.PaymentAddress)
	invInput.Version = v1.InvoiceInputVersion

	rate, err := strconv.Atoi(strings.TrimSpace(cmd.Rate))
	if err != nil {
		return fmt.Errorf("invalid rate entered, please try again")
	}
	invInput.ContractorRate = uint(rate)

	b, err := json.Marshal(invInput)
	if err != nil {
		return fmt.Errorf("Marshal: %v", err)
	}

	f := www.File{
		Name:    "invoice.json",
		MIME:    mime.DetectMimeType(b),
		Digest:  hex.EncodeToString(util.Digest(b)),
		Payload: base64.StdEncoding.EncodeToString(b),
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
	sig, err := shared.SignedMerkleRoot(files, cfg.Identity)
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
	err = shared.PrintJSON(ei)
	if err != nil {
		return err
	}

	// Send request
	eir, err := client.EditInvoice(ei)
	if err != nil {
		return err
	}

	// Verify the censorship record
	pr := v1.InvoiceRecord{
		Files:            ei.Files,
		PublicKey:        ei.PublicKey,
		Signature:        ei.Signature,
		CensorshipRecord: eir.Invoice.CensorshipRecord,
	}
	err = verifyInvoice(pr, vr.PubKey)
	if err != nil {
		return fmt.Errorf("unable to verify invoice %v: %v",
			eir.Invoice.CensorshipRecord.Token, err)
	}

	// Print response details
	return shared.PrintJSON(eir)
}

// editInvoiceHelpMsg is the output of the help command when 'editinvoice'
// is specified.
const editInvoiceHelpMsg = `editinvoice [flags] "month" "year" token" "csvfile" "attachmentfiles" 

Edit a invoice.

Arguments:
1. month             (uint, required)     Invoice Month
2. year              (uint, required)     Invoice Year
1. token             (string, required)   Invoice censorship token
2. csvfile           (string, required)   Edited invoice 
3. attachmentfiles   (string, optional)   Attachments 

Flags:
  --name              (string, optional)   Fill in contractor name
  --contact           (string, optional)   Fill in email address or contact of the contractor
  --location          (string, optional)   Fill in contractor location (e.g. Dallas, TX, USA) of the contractor
  --paymentaddress    (string, optional)   Fill in payment address for this invoice.
  --rate              (string, optional)   Fill in contractor pay rate for labor.

Request:
{
  "month":  (uint)    Invoice Month
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
    "month":         (uint16)       Month of invoice
    "year":          (uint16)       Year of invoice
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
