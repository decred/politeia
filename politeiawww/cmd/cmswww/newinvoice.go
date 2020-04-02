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
	cms "github.com/thi4go/politeia/politeiawww/api/cms/v1"
	www "github.com/thi4go/politeia/politeiawww/api/www/v1"
	"github.com/thi4go/politeia/politeiawww/cmd/shared"
	"github.com/thi4go/politeia/util"
)

// NewInvoiceCmd submits a new invoice.
type NewInvoiceCmd struct {
	Args struct {
		Month       uint     `positional-arg-name:"month"`           // Invoice Month
		Year        uint     `positional-arg-name:"year"`            // Invoice Year
		CSV         string   `positional-arg-name:"csvfile"`         // Invoice CSV file
		Attachments []string `positional-arg-name:"attachmentfiles"` // Invoice attachment files
	} `positional-args:"true" optional:"true"`
	Name           string `long:"name" optional:"true" description:"Full name of the contractor"`
	Contact        string `long:"contact" optional:"true" description:"Email address or contact of the contractor"`
	Location       string `long:"location" optional:"true" description:"Location (e.g. Dallas, TX, USA) of the contractor"`
	PaymentAddress string `long:"paymentaddress" optional:"true" description:"Payment address for this invoice."`
	Rate           string `long:"rate" optional:"true" description:"Hourly rate for labor."`
}

// Execute executes the new invoice command.
func (cmd *NewInvoiceCmd) Execute(args []string) error {
	month := cmd.Args.Month
	year := cmd.Args.Year
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

	if cmd.Name == "" || cmd.Location == "" || cmd.PaymentAddress == "" ||
		cmd.Contact == "" || cmd.Rate == "" {
		reader := bufio.NewReader(os.Stdin)
		if cmd.Name == "" {
			fmt.Print("Enter your name to associate with this invoice: ")
			cmd.Name, _ = reader.ReadString('\n')
		}
		if cmd.Contact == "" {
			fmt.Print("Enter your contact information (email/matrix) to associate with this invoice: ")
			cmd.Contact, _ = reader.ReadString('\n')
		}
		if cmd.Location == "" {
			fmt.Print("Enter your location to associate with this invoice: ")
			cmd.Location, _ = reader.ReadString('\n')
		}
		if cmd.PaymentAddress == "" {
			fmt.Print("Enter payment address for this invoice: ")
			cmd.PaymentAddress, _ = reader.ReadString('\n')
		}
		if cmd.Rate == "" {
			fmt.Print("Enter hourly rate for this invoice (in USD): ")
			cmd.Rate, _ = reader.ReadString('\n')
		}
		fmt.Print("\nPlease carefully review your information and ensure it's " +
			"correct. If not, press Ctrl + C to exit. Or, press Enter to continue " +
			"your registration.")
		reader.ReadString('\n')
	}

	var csv []byte
	files := make([]www.File, 0, www.PolicyMaxImages+1)
	// Read csv file into memory and convert to type File
	fpath := util.CleanAndExpandPath(csvFile)

	csv, err = ioutil.ReadFile(fpath)
	if err != nil {
		return fmt.Errorf("ReadFile %v: %v", fpath, err)
	}

	invInput, err := validateParseCSV(csv)
	if err != nil {
		return fmt.Errorf("Parsing CSV failed: %v", err)
	}

	ier := &cms.InvoiceExchangeRate{
		Month: month,
		Year:  year,
	}

	// Send request
	ierr, err := client.InvoiceExchangeRate(ier)
	if err != nil {
		return err
	}

	invInput.Month = month
	invInput.Year = year
	invInput.ExchangeRate = ierr.ExchangeRate
	invInput.ContractorName = strings.TrimSpace(cmd.Name)
	invInput.ContractorLocation = strings.TrimSpace(cmd.Location)
	invInput.ContractorContact = strings.TrimSpace(cmd.Contact)
	invInput.PaymentAddress = strings.TrimSpace(cmd.PaymentAddress)
	invInput.Version = cms.InvoiceInputVersion

	rate, err := strconv.Atoi(strings.TrimSpace(cmd.Rate))
	if err != nil {
		return fmt.Errorf("invalid rate entered, please try again")
	}
	invInput.ContractorRate = uint(rate * 100)

	// Print request details
	err = shared.PrintJSON(invInput)
	if err != nil {
		return err
	}
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

	// Setup new proposal request
	ni := &cms.NewInvoice{
		Files:     files,
		PublicKey: hex.EncodeToString(cfg.Identity.Public.Key[:]),
		Signature: sig,
		Month:     month,
		Year:      year,
	}

	// Print request details
	err = shared.PrintJSON(ni)
	if err != nil {
		return err
	}

	// Send request
	nir, err := client.NewInvoice(ni)
	if err != nil {
		return err
	}

	// Verify the censorship record
	ir := cms.InvoiceRecord{
		Files:            ni.Files,
		PublicKey:        ni.PublicKey,
		Signature:        ni.Signature,
		CensorshipRecord: nir.CensorshipRecord,
	}
	err = verifyInvoice(ir, vr.PubKey)
	if err != nil {
		return fmt.Errorf("unable to verify invoice %v: %v",
			ir.CensorshipRecord.Token, err)
	}

	// Print response details
	return shared.PrintJSON(nir)
}

const newInvoiceHelpMsg = `newinvoice [flags] "csvFile" "attachmentFiles"

Submit a new invoice to Politeia. Invoice must be a csv file. Accepted
attachment filetypes: png or plain text.

An invoice csv line item should use the following format:

type,domain,subdomain,description,proposalToken,labor,expenses,subUserID

Valid types   : labor, expense, misc, sub
Labor units   : hours
Expenses units: USD

Arguments:
1. month             (string, required)   Month (MM, 01-12)
2. year              (string, required)   Year (YYYY)
3. csvFile           (string, required)   Invoice CSV file
4. attachmentFiles   (string, optional)   Attachments

Flags:
  --name              (string, optional)   Fill in contractor name
  --contact           (string, optional)   Fill in email address or contact of the contractor
  --location          (string, optional)   Fill in contractor location (e.g. Dallas, TX, USA) of the contractor
  --paymentaddress    (string, optional)   Fill in payment address for this invoice.
  --rate              (string, optional)   Fill in contractor pay rate for labor (USD).

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
