// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/decred/politeia/politeiad/api/v1/mime"
	cms "github.com/decred/politeia/politeiawww/api/cms/v2"
	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
	v1 "github.com/decred/politeia/politeiawww/api/www/v1"
	pclient "github.com/decred/politeia/politeiawww/client"
	"github.com/decred/politeia/politeiawww/cmd/shared"
	"github.com/decred/politeia/util"
)

// cmdInvoiceNew submits a new invoice.
type cmdInvoiceNew struct {
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

var (
	// errInvoiceCSVNotFound is emitted when a invoice csv file is
	// required but has not been passed into the command.
	errInvoiceCSVNotFound = errors.New("invoice csv file not found. " +
		"You must either provide a csv file or use the --random flag")
)

// This function satisfies the go-flags Commander interface.
func (c *cmdInvoiceNew) Execute(args []string) error {
	_, err := invoiceNew(c)
	if err != nil {
		return err
	}
	return nil
}

// invoiceNew creates a new invoice. This function has been pulled out of the
// Execute method so that it can be used in the test commands.
func invoiceNew(c *cmdInvoiceNew) (*rcv1.Record, error) {
	// Setup client
	opts := pclient.Opts{
		HTTPSCert:  cfg.HTTPSCert,
		Cookies:    cfg.Cookies,
		HeaderCSRF: cfg.CSRF,
		Verbose:    cfg.Verbose,
		RawJSON:    cfg.RawJSON,
	}
	pc, err := pclient.New(cfg.Host, opts)
	if err != nil {
		return nil, err
	}

	month := c.Args.Month
	year := c.Args.Year
	csvFile := c.Args.CSV
	attachmentFiles := c.Args.Attachments

	if csvFile == "" {
		return nil, errInvoiceCSVNotFound
	}

	// Check for user identity
	if cfg.Identity == nil {
		return nil, shared.ErrUserIdentityNotFound
	}

	if c.Name == "" || c.Location == "" || c.PaymentAddress == "" ||
		c.Contact == "" || c.Rate == "" {
		reader := bufio.NewReader(os.Stdin)
		if c.Name == "" {
			fmt.Print("Enter your name to associate with this invoice: ")
			c.Name, _ = reader.ReadString('\n')
		}
		if c.Contact == "" {
			fmt.Print("Enter your contact information (email/matrix) to associate with this invoice: ")
			c.Contact, _ = reader.ReadString('\n')
		}
		if c.Location == "" {
			fmt.Print("Enter your location to associate with this invoice: ")
			c.Location, _ = reader.ReadString('\n')
		}
		if c.PaymentAddress == "" {
			fmt.Print("Enter payment address for this invoice: ")
			c.PaymentAddress, _ = reader.ReadString('\n')
		}
		if c.Rate == "" {
			fmt.Print("Enter hourly rate for this invoice (in USD): ")
			c.Rate, _ = reader.ReadString('\n')
		}
		fmt.Print("\nPlease carefully review your information and ensure it's " +
			"correct. If not, press Ctrl + C to exit. Or, press Enter to continue " +
			"your registration.")
		reader.ReadString('\n')
	}

	rate, err := strconv.Atoi(strings.TrimSpace(c.Rate))
	if err != nil {
		return nil, fmt.Errorf("invalid rate entered, please try again")
	}

	var csv []byte
	files := make([]rcv1.File, 0, v1.PolicyMaxImages+1)
	// Read csv file into memory and convert to type File
	fpath := util.CleanAndExpandPath(csvFile)

	csv, err = ioutil.ReadFile(fpath)
	if err != nil {
		return nil, fmt.Errorf("ReadFile %v: %v", fpath, err)
	}

	invInput, err := validateParseCSV(csv)
	if err != nil {
		return nil, fmt.Errorf("parsing CSV failed: %v", err)
	}

	// Print request details
	err = shared.PrintJSON(invInput)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(invInput)
	if err != nil {
		return nil, fmt.Errorf("marshal: %v", err)
	}

	f := rcv1.File{
		Name:    cms.FileNameIndexFile,
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
			return nil, fmt.Errorf("readFile %v: %v", path, err)
		}

		f := rcv1.File{
			Name:    filepath.Base(file),
			MIME:    mime.DetectMimeType(attachment),
			Digest:  hex.EncodeToString(util.Digest(attachment)),
			Payload: base64.StdEncoding.EncodeToString(attachment),
		}

		files = append(files, f)
	}
	ier := &cms.InvoiceExchangeRate{
		Month: month,
		Year:  year,
	}

	// Send request
	ierr, err := client.InvoiceExchangeRateV2(ier)
	if err != nil {
		return nil, err
	}

	pm := cms.InvoiceMetadata{
		ContractorName:     strings.TrimSpace(c.Name),
		ContractorContact:  strings.TrimSpace(c.Contact),
		ContractorLocation: strings.TrimSpace(c.Location),
		Month:              month,
		Year:               year,
		PaymentAddress:     c.PaymentAddress,
		ExchangeRate:       ierr.ExchangeRate,
		ContractorRate:     uint(rate * 100),
	}

	pmb, err := json.Marshal(pm)
	if err != nil {
		return nil, err
	}
	files = append(files, rcv1.File{
		Name:    cms.FileNameInvoiceMetadata,
		MIME:    mime.DetectMimeType(pmb),
		Digest:  hex.EncodeToString(util.Digest(pmb)),
		Payload: base64.StdEncoding.EncodeToString(pmb),
	})

	// Print invoice to stdout
	printf("Files\n")
	err = printInvoiceFiles(files)
	if err != nil {
		return nil, err
	}

	// Submit invoice
	sig, err := signedMerkleRoot(files, cfg.Identity)
	if err != nil {
		return nil, err
	}
	n := rcv1.New{
		Files:     files,
		PublicKey: cfg.Identity.Public.String(),
		Signature: sig,
	}
	nr, err := pc.RecordNew(n)
	if err != nil {
		return nil, err
	}

	// Verify record
	vr, err := client.Version()
	if err != nil {
		return nil, err
	}
	err = pclient.RecordVerify(nr.Record, vr.PubKey)
	if err != nil {
		return nil, fmt.Errorf("unable to verify record: %v", err)
	}

	// Print censorship record
	printf("Token  : %v\n", nr.Record.CensorshipRecord.Token)
	printf("Merkle : %v\n", nr.Record.CensorshipRecord.Merkle)
	printf("Receipt: %v\n", nr.Record.CensorshipRecord.Signature)

	return &nr.Record, nil
}

const invoiceNewHelpMsg = `newinvoice [flags] "csvFile" "attachmentFiles"

Submit a new invoice to Politeia. Invoice must be a csv file. Accepted
attachment filetypes: png or plain text.

An invoice csv line item should use the following format:

type,domain,subdomain,description,proposalToken,labor,expenses,subUserID,subRate

Valid types   : labor, expense, misc, sub
Labor units   : hours
Expenses units: USD

Example csv lines:
labor,random,subdomain,description,,180,0,,0
expense,marketing,subdomain,description,,0,1500,,0

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
