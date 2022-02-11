// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/decred/politeia/politeiad/api/v1/mime"
	cmsv2 "github.com/decred/politeia/politeiawww/api/cms/v2"
	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
	v1 "github.com/decred/politeia/politeiawww/api/www/v1"
	pclient "github.com/decred/politeia/politeiawww/client"
	"github.com/decred/politeia/politeiawww/cmd/shared"
	"github.com/decred/politeia/util"
)

// cmdInvoiceEdit edits an existing invoice.
type cmdInvoiceEdit struct {
	Args struct {
		Token       string   `positional-arg-name:"token" required:"true"`
		CSVFile     string   `positional-arg-name:"csvfile"`
		Attachments []string `positional-arg-name:"attachments"`
	} `positional-args:"true" optional:"true"`

	// UseMD is a flag that is intended to make editing invoice
	// metadata easier by using exisiting invoice metadata values
	// instead of having to pass in specific values.
	UseMD bool `long:"usemd" optional:"true"`

	// Metadata fields that can be set by the user
	Month          uint   `long:"month" optional:"true" description:"Month of the invoice"`
	Year           uint   `long:"year" optional:"true" description:"Year of the invoice"`
	Name           string `long:"name" optional:"true" description:"Full name of the contractor"`
	Contact        string `long:"contact" optional:"true" description:"Email address or contact of the contractor"`
	Location       string `long:"location" optional:"true" description:"Location (e.g. Dallas, TX, USA) of the contractor"`
	PaymentAddress string `long:"paymentaddress" optional:"true" description:"Payment address for this invoice."`
	Rate           string `long:"rate" optional:"true" description:"Hourly rate for labor."`
}

// Execute executes the cmdInvoiceEdit command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdInvoiceEdit) Execute(args []string) error {
	_, err := invoiceEdit(c)
	if err != nil {
		return err
	}
	return nil
}

// invoiceEdit edits a invoice. This function has been pulled out of the
// Execute method so that is can be used in the test commands.
func invoiceEdit(c *cmdInvoiceEdit) (*rcv1.Record, error) {
	// Unpack args
	token := c.Args.Token
	csvFile := c.Args.CSVFile
	attachmentFiles := c.Args.Attachments

	// Verify args and flags
	if csvFile == "" {
		return nil, errInvoiceCSVNotFound
	}

	// Check for user identity. A user identity is required to sign
	// the invoice files.
	if cfg.Identity == nil {
		return nil, shared.ErrUserIdentityNotFound
	}

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
		Name:    cmsv2.FileNameIndexFile,
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

	// Get current invoice if we are using the existing metadata
	var curr *rcv1.Record
	if c.UseMD {
		d := rcv1.Details{
			Token: token,
		}
		curr, err = pc.RecordDetails(d)
		if err != nil {
			return nil, err
		}
	}

	// Setup invoice metadata
	switch {
	// Use existing invoice metadata.
	case c.UseMD:
		pm, err := pclient.InvoiceMetadataDecode(curr.Files)
		if err != nil {
			return nil, err
		}
		c.Month = pm.Month
		c.Year = pm.Year
		c.Name = pm.ContractorName
		c.Contact = pm.ContractorContact
		c.Location = pm.ContractorLocation
		c.PaymentAddress = pm.PaymentAddress
		c.Rate = strconv.Itoa(int(pm.ContractorRate))
	}

	rate, err := strconv.Atoi(strings.TrimSpace(c.Rate))
	if err != nil {
		return nil, fmt.Errorf("invalid rate entered, please try again")
	}

	pm := cmsv2.InvoiceMetadata{
		ContractorName:     c.Name,
		ContractorContact:  c.Contact,
		ContractorLocation: c.Location,
		ContractorRate:     uint(rate),
		PaymentAddress:     c.PaymentAddress,
		Month:              c.Month,
		Year:               c.Year,
	}

	pmb, err := json.Marshal(pm)
	if err != nil {
		return nil, err
	}
	files = append(files, rcv1.File{
		Name:    cmsv2.FileNameInvoiceMetadata,
		MIME:    mime.DetectMimeType(pmb),
		Digest:  hex.EncodeToString(util.Digest(pmb)),
		Payload: base64.StdEncoding.EncodeToString(pmb),
	})

	// Edit record
	sig, err := signedMerkleRoot(files, cfg.Identity)
	if err != nil {
		return nil, err
	}
	e := rcv1.Edit{
		Token:     token,
		Files:     files,
		PublicKey: cfg.Identity.Public.String(),
		Signature: sig,
	}
	er, err := pc.RecordEdit(e)
	if err != nil {
		return nil, err
	}

	// Verify record
	vr, err := client.Version()
	if err != nil {
		return nil, err
	}
	err = pclient.RecordVerify(er.Record, vr.PubKey)
	if err != nil {
		return nil, fmt.Errorf("unable to verify record: %v", err)
	}

	// Print invoice to stdout
	printf("Invoice editted\n")
	err = printInvoice(er.Record)
	if err != nil {
		return nil, err
	}

	return &er.Record, nil
}

// invoiceEditHelpMsg is the printed to stdout by the help command.
const invoiceEditHelpMsg = `editinvoice [flags] "token" "indexfile" "attachments" 

Edit an existing invoice.

Arguments:
1. token       (string, required) Invoice censorship token.
2. csvfile     (string, optional) CSV invoice file.
3. attachments (string, optional) Attachment files.

Flags:
 --usemd        (bool)   Use the existing invoice metadata.

 --name         (string) Contractor Name for the invoice.

 --random       (bool)   Generate random invoice data, not including
                         attachments. The indexFile argument is not allowed
                         when using this flag.

 --randomimages (bool)   Generate random attachments. The attachments argument
                         is not allowed when using this flag.
`
