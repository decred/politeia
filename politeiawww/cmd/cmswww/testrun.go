// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/dcrd/hdkeychain"
	"github.com/decred/politeia/cmsplugin"
	"github.com/decred/politeia/politeiad/api/v1/mime"
	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/cmd/shared"
	"github.com/decred/politeia/util"
)

// TestRunCmd performs a test run of cmswww routes.
type TestRunCmd struct {
	Args struct {
		AdminEmail    string `positional-arg-name:"adminemail"`
		AdminPassword string `positional-arg-name:"adminpassword"`
	} `positional-args:"true" required:"true"`
}

const (
	// DCC support/oppose options. These are not the all contractor
	// vote options. Those are defined in cmsplugin.
	dccIssuanceSupport = "aye"
	dccIssuanceOppose  = "nay"
)

// user represents a cms user that is used during the test run.
type user struct {
	ID           string
	Email        string
	Username     string
	Password     string
	AddressIndex uint32 // Used to generate unique payment addresses
}

func (u *user) paymentAddress() (string, error) {
	xpub := "tpubVobLtToNtTq6TZNw4raWQok35PRPZou53vegZqNubtBTJMMFmuMpWybF" +
		"CfweJ52N8uZJPZZdHE5SRnBBuuRPfC5jdNstfKjiAs8JtbYG9jx"

	if u.AddressIndex == 0 {
		// The address index is set to be the uint32 representation of
		// the hex username, which was randomly generated, so that we
		// don't have payment address collisions between the different
		// test users. CMS doesn't allow the same payment address to
		// be used more than a single time.
		b, err := hex.DecodeString(u.Username)
		if err != nil {
			return "", err
		}
		u.AddressIndex = binary.LittleEndian.Uint32(b)
	}

	// Increment the address index for the user so that a unique
	// payment address is generated each time.
	u.AddressIndex += 1

	// The index isn't allowed to be larger than the HardenKeyStart.
	// See hdkeychain ExtendedKey.Child() for more info.
	if u.AddressIndex >= hdkeychain.HardenedKeyStart {
		u.AddressIndex = u.AddressIndex % hdkeychain.HardenedKeyStart
	}

	return util.DerivePaywallAddress(&chaincfg.TestNet3Params,
		xpub, u.AddressIndex)
}

func randomString() string {
	b, err := util.Random(16)
	if err != nil {
		return "uh oh, randomString() failed"
	}
	return hex.EncodeToString(b)
}

// login logs the given user into politeiawww. The full LoginCmd must be used
// instead of just calling client.Login() so that the persistent CLI data is
// updated properly.
func login(u user) error {
	lc := shared.LoginCmd{}
	lc.Args.Email = u.Email
	lc.Args.Password = u.Password
	return lc.Execute(nil)
}

// logout logs out whatever user is currently logged in with the CLI. The full
// LogoutCmd must be used instead of just calling client.Logout() so that the
// persistent CLI data is updated properly.
func logout() error {
	l := shared.LogoutCmd{}
	return l.Execute(nil)
}

// userNew returns a new cms user that has been invited and registered. The
// user credentials are randomly generated.
//
// This function returns with the admin logged out.
func userNew(admin user) (*user, error) {
	// Login the admin
	err := login(admin)
	if err != nil {
		return nil, fmt.Errorf("login: %v", err)
	}

	// Generate random user credentials
	b, err := util.Random(www.PolicyMinPasswordLength)
	if err != nil {
		return nil, err
	}
	u := user{
		Email:    hex.EncodeToString(b) + "@example.com",
		Username: hex.EncodeToString(b),
		Password: hex.EncodeToString(b),
	}

	// Invite user
	inu := cms.InviteNewUser{
		Email: u.Email,
	}
	inur, err := client.InviteNewUser(&inu)
	if err != nil {
		return nil, fmt.Errorf("InviteNewUser: %v", err)
	}
	if inur.VerificationToken == "" {
		return nil, fmt.Errorf("InviteNewUserReply: verification token not " +
			"found; the politeiawww email server likely needs to be disabled")
	}

	// Register user. Use the full command so that the identity is
	// saved to disk. This will also log the user in.
	r := RegisterUserCmd{}
	r.Args.Email = u.Email
	r.Args.Username = u.Username
	r.Args.Password = u.Password
	r.Args.Token = inur.VerificationToken
	err = r.Execute(nil)
	if err != nil {
		return nil, fmt.Errorf("RegisterUserCmd: %v", err)
	}

	// Get the user ID
	lr, err := client.Me()
	if err != nil {
		return nil, fmt.Errorf("Me: %v", err)
	}
	u.ID = lr.UserID

	// Log the user out
	err = logout()
	if err != nil {
		return nil, fmt.Errorf("logout: %v", err)
	}

	return &u, nil
}

// contractorNew creates a new user then updates the user with the given
// contractor details.
//
// This function returns with the admin logged out.
func contractorNew(admin user, dt cms.DomainTypeT, ct cms.ContractorTypeT) (*user, error) {
	// Invite and register a new user
	u, err := userNew(admin)
	if err != nil {
		return nil, fmt.Errorf("userNew: %v", err)
	}

	err = login(admin)
	if err != nil {
		return nil, fmt.Errorf("login: %v", err)
	}

	// Update the user's contractor status
	muc := CMSManageUserCmd{
		Domain:         strconv.Itoa(int(dt)),
		ContractorType: strconv.Itoa(int(ct)),
	}
	muc.Args.UserID = u.ID
	err = muc.Execute(nil)
	if err != nil {
		return nil, fmt.Errorf("CMSManageUserCmd: %v", err)
	}

	err = logout()
	if err != nil {
		return nil, fmt.Errorf("logout: %v", err)
	}

	return u, err
}

// invoiceNew submits a new invoice for the provided user. The invoice is
// submitted for the most recent month that the user has not submitted an
// invoice for.
//
// contractorRate is in USD.
// labor is in hours.
//
// This function returns with the user logged out.
func invoiceNew(u user, contractorRate uint, labor float64) (*www.CensorshipRecord, error) {
	err := login(u)
	if err != nil {
		return nil, fmt.Errorf("login: %v", err)
	}

	// Get user's previous invoices
	uir, err := client.UserInvoices(&cms.UserInvoices{})
	if err != nil {
		return nil, fmt.Errorf("UserInvoices: %v", err)
	}

	// Find the first available date that we can submit an invoice
	// for.
	invoiceDates := make(map[uint]map[uint]struct{}) // [year][month]struct{}
	for _, v := range uir.Invoices {
		_, ok := invoiceDates[v.Input.Year]
		if !ok {
			invoiceDates[v.Input.Year] = make(map[uint]struct{}, 12)
		}
		invoiceDates[v.Input.Year][v.Input.Month] = struct{}{}
	}

	y, m, _ := time.Now().AddDate(0, -1, 0).Date()
	var (
		month = uint(m) // Last month
		year  = uint(y) // Current year
		found bool
	)
	for !found {
		_, ok := invoiceDates[year]
		if !ok {
			found = true
			continue
		}
		_, ok = invoiceDates[year][month]
		if !ok {
			found = true
			continue
		}

		// Decrement month
		switch {
		case month > 1:
			month -= 1
		case month == 1:
			month = 12
			year -= 1
		default:
			return nil, fmt.Errorf("invalid date")
		}
	}

	// Submit an invoice for the first available month
	ier := cms.InvoiceExchangeRate{
		Month: month,
		Year:  year,
	}
	ierr, err := client.InvoiceExchangeRate(&ier)
	if err != nil {
		return nil, fmt.Errorf("InvoiceExchangeRate %v: %v",
			ier, err)
	}
	address, err := u.paymentAddress()
	if err != nil {
		return nil, err
	}
	ii := cms.InvoiceInput{
		Month:              month,
		Year:               year,
		ExchangeRate:       ierr.ExchangeRate,
		ContractorName:     u.Username,
		ContractorLocation: "Mars",
		ContractorContact:  u.Email,
		ContractorRate:     contractorRate * 100, // In cents
		PaymentAddress:     address,
		LineItems: []cms.LineItemsInput{
			{
				Type:          cms.LineItemTypeLabor,
				Domain:        "Development",
				Subdomain:     "politeia",
				Description:   "PR 999: politeiawww: Add stuff.",
				ProposalToken: "",
				SubUserID:     "",
				SubRate:       0,
				Labor:         uint(labor * 60), // In minutes
				Expenses:      0,
			},
		},
	}
	b, err := json.Marshal(ii)
	if err != nil {
		return nil, err
	}
	files := []www.File{
		{
			Name:    "invoice.json",
			MIME:    mime.DetectMimeType(b),
			Digest:  hex.EncodeToString(util.Digest(b)),
			Payload: base64.StdEncoding.EncodeToString(b),
		},
	}
	sig, err := shared.SignedMerkleRoot(files, nil, cfg.Identity)
	if err != nil {
		return nil, err
	}
	ni := &cms.NewInvoice{
		Files:     files,
		PublicKey: hex.EncodeToString(cfg.Identity.Public.Key[:]),
		Signature: sig,
		Month:     month,
		Year:      year,
	}
	nir, err := client.NewInvoice(ni)
	if err != nil {
		return nil, fmt.Errorf("NewInvoice: %v", err)
	}

	// Verify the censorship record
	vr, err := client.Version()
	if err != nil {
		return nil, fmt.Errorf("Version: %v", err)
	}
	ir := cms.InvoiceRecord{
		Files:            ni.Files,
		PublicKey:        ni.PublicKey,
		Signature:        ni.Signature,
		CensorshipRecord: nir.CensorshipRecord,
	}
	err = verifyInvoice(ir, vr.PubKey)
	if err != nil {
		return nil, fmt.Errorf("unable to verify invoice %v: %v",
			ir.CensorshipRecord.Token, err)
	}

	// Log the user out
	err = logout()
	if err != nil {
		return nil, fmt.Errorf("logout: %v", err)
	}

	return &nir.CensorshipRecord, nil
}

// invoiceSetStatus sets the status of the provided invoice.
//
// Changing an invoic's status to InvoiceStatusPaid is not a valid status
// transition. The invoicesPay() function must be used instead if you want
// to manually mark invoices as paid.
//
// This function returns with the admin logged out.
func invoiceSetStatus(admin user, token string, s cms.InvoiceStatusT) error {
	err := login(admin)
	if err != nil {
		return fmt.Errorf("login: %v", err)
	}

	// Get the most recent version of the DCC to pull the version
	// from it.
	idr, err := client.InvoiceDetails(token, nil)
	if err != nil {
		return fmt.Errorf("InvoiceDetails: %v", err)
	}

	// Set the invoice status
	c := SetInvoiceStatusCmd{}
	c.Args.Version = idr.Invoice.Version
	c.Args.Token = token
	c.Args.Status = strconv.Itoa(int(s))
	c.Args.Reason = "some reason...."
	err = c.Execute(nil)
	if err != nil {
		return fmt.Errorf("SetInvoiceStatusCmd: %v", err)
	}

	err = logout()
	if err != nil {
		return fmt.Errorf("logout: %v", err)
	}

	return nil
}

// invoicesPays marks all of the currently approved invoices as paid.
//
// This function returns with the admin logged out.
func invoicesPay(admin user) error {
	err := login(admin)
	if err != nil {
		return fmt.Errorf("login: %v", err)
	}

	_, err = client.PayInvoices(&cms.PayInvoices{})
	if err != nil {
		return fmt.Errorf("PayInvoices: %v", err)
	}

	err = logout()
	if err != nil {
		return fmt.Errorf("logout: %v", err)
	}

	return nil
}

// dccNew submits a new DCC to cmswww then returns the submitted DCC.
//
// This function returns with the user logged out.
func dccNew(sponsor user, nomineeID string, dcct cms.DCCTypeT, dt cms.DomainTypeT, ct cms.ContractorTypeT) (*cms.DCCRecord, error) {
	err := login(sponsor)
	if err != nil {
		return nil, fmt.Errorf("login: %v", err)
	}

	// We can't use the NewDCCCmd here because we need the
	// censorship token that is returned in the reply. Run
	// the command manually.
	di := cms.DCCInput{
		Type:             dcct,
		NomineeUserID:    nomineeID,
		Domain:           dt,
		ContractorType:   ct,
		SponsorStatement: "this person is good",
	}
	b, err := json.Marshal(di)
	if err != nil {
		return nil, err
	}
	f := www.File{
		Name:    "dcc.json",
		MIME:    mime.DetectMimeType(b),
		Digest:  hex.EncodeToString(util.Digest(b)),
		Payload: base64.StdEncoding.EncodeToString(b),
	}
	files := []www.File{f}
	sig, err := shared.SignedMerkleRoot(files, nil, cfg.Identity)
	if err != nil {
		return nil, err
	}
	nd := cms.NewDCC{
		File:      f,
		PublicKey: hex.EncodeToString(cfg.Identity.Public.Key[:]),
		Signature: sig,
	}
	ndr, err := client.NewDCC(nd)
	if err != nil {
		return nil, fmt.Errorf("NewDCC: %v", err)
	}

	// Get the full DCC record to return
	dcc, err := dcc(ndr.CensorshipRecord.Token)
	if err != nil {
		return nil, fmt.Errorf("dcc: %v", err)
	}

	// Log the user out
	err = logout()
	if err != nil {
		return nil, fmt.Errorf("logout: %v", err)
	}

	return dcc, nil
}

// dcc returns the DCCRecord for the given token.
func dcc(token string) (*cms.DCCRecord, error) {
	ddr, err := client.DCCDetails(token)
	if err != nil {
		return nil, err
	}
	return &ddr.DCC, nil
}

// dccSetStatus updates the status of the given DCC.
//
// This function returns with the admin logged out.
func dccSetStatus(admin user, token string, st cms.DCCStatusT, reason string) error {
	err := login(admin)
	if err != nil {
		return fmt.Errorf("login: %v", err)
	}

	sds := SetDCCStatusCmd{}
	sds.Args.Token = token
	sds.Args.Status = strconv.Itoa(int(st))
	sds.Args.Reason = reason
	err = sds.Execute(nil)
	if err != nil {
		return fmt.Errorf("SetDCCStatusCmd: %v", err)
	}

	err = logout()
	if err != nil {
		return fmt.Errorf("logout: %v", err)
	}
	return nil
}

// dccSupport casts a support or oppose vote with the provided user for the
// provided dcc.
//
// This function returns with the user logged out.
func dccSupport(u user, token, vote string) error {
	err := login(u)
	if err != nil {
		return fmt.Errorf("login: %v", err)
	}

	c := SupportOpposeDCCCmd{}
	c.Args.Token = token
	c.Args.Vote = vote
	err = c.Execute(nil)
	if err != nil {
		return fmt.Errorf("SupportOpposeDCCCmd: %v", err)
	}

	err = logout()
	if err != nil {
		return fmt.Errorf("logout: %v", err)
	}

	return nil
}

// dccStartVote starts an all contractor vote for the provided DCC.
//
// This function returns with the admin logged out.
func dccStartVote(admin user, token string) error {
	err := login(admin)
	if err != nil {
		return fmt.Errorf("login: %v", err)
	}

	svc := StartVoteCmd{}
	svc.Args.Token = token
	err = svc.Execute(nil)
	if err != nil {
		return fmt.Errorf("StartVoteCmd: %v", err)
	}

	err = logout()
	if err != nil {
		return fmt.Errorf("logout: %v", err)
	}

	return nil
}

// dccVote casts a support or oppose vote with the provided user for the
// provided dcc all contractor vote.
//
// This function returns with the user logged out.
func dccVote(u user, token, vote string) error {
	err := login(u)
	if err != nil {
		return fmt.Errorf("login: %v", err)
	}

	c := VoteDCCCmd{}
	c.Args.Token = token
	c.Args.Vote = vote
	err = c.Execute(nil)
	if err != nil {
		return fmt.Errorf("VoteDCCCmd: %v", err)
	}

	err = logout()
	if err != nil {
		return fmt.Errorf("logout: %v", err)
	}

	return nil
}

// dccVoteSummary returns the DCC vote summary for the provided DCC token.
//
// This function returns with the user logged out.
func dccVoteSummary(u user, token string) (*cms.VoteSummary, error) {
	err := login(u)
	if err != nil {
		return nil, fmt.Errorf("login: %v", err)
	}

	ddr, err := client.DCCDetails(token)
	if err != nil {
		return nil, fmt.Errorf("DCCDetails: %v", err)
	}

	err = logout()
	if err != nil {
		return nil, fmt.Errorf("logout: %v", err)
	}

	return &ddr.VoteSummary, nil
}

// dccCommentNew posts a new comment to the provided DCC.
//
// This function returns with the user logged out.
func dccCommentNew(u user, token, parentID, comment string) error {
	if parentID == "" {
		parentID = "0"
	}

	err := login(u)
	if err != nil {
		return fmt.Errorf("login: %v", err)
	}

	c := NewDCCCommentCmd{}
	c.Args.Token = token
	c.Args.ParentID = parentID
	c.Args.Comment = comment
	err = c.Execute(nil)
	if err != nil {
		return fmt.Errorf("NewDCCCommentCmd: %v", err)
	}

	err = logout()
	if err != nil {
		return fmt.Errorf("logout: %v", err)
	}

	return nil
}

// dccComments returns the comments for the provided DCC token.
//
// This function returns with the user logged out.
func dccComments(u user, token string) ([]www.Comment, error) {
	err := login(u)
	if err != nil {
		return nil, fmt.Errorf("login: %v", err)
	}

	gcr, err := client.DCCComments(token)
	if err != nil {
		return nil, fmt.Errorf("DCCComments: %v", err)
	}

	err = logout()
	if err != nil {
		return nil, fmt.Errorf("logout: %v", err)
	}

	return gcr.Comments, nil
}

// testDCC tests the DCC (Decred Contractor Clearance) routes. See the proposal
// below for more information about the DCC process.
//
// https://proposals.decred.org/proposals/fa38a35
//
// A new cms user must have their contractor type updated before they are able
// to submit invoices. There are currently two ways for this to happen.
// 1. An admin can update it manually using the CMSManageUser route.
// 2. The contractor can undergo the DCC process. The DCC process is where
//    the new contractor is nominated by an existing contractor then other
//    existing contractors can support or oppose the DCC nomination. Admins
//    currently have final say in the approval of a DCC. If a DCC is
//    contentious, it can be put up for an all contractor vote where existing
//    contractor votes are weighted by the amount of hours they've billed.
//    Once a DCC has been approved, the user's ContractorType is automatically
//    updated and they are able to submit invoices.
//
// testDCC runs through the full DCC process with the exception of the all
// contractor vote for contentious DCCs. See testDCCVote() for details on the
// all contractor vote.
func testDCC(admin user) error {
	fmt.Printf("Running testDCC\n")

	// Create three users and make them existing contractors
	fmt.Printf("  create existing contractors\n")

	c1, err := contractorNew(admin, cms.DomainTypeDeveloper,
		cms.ContractorTypeDirect)
	if err != nil {
		return err
	}
	c2, err := contractorNew(admin, cms.DomainTypeDeveloper,
		cms.ContractorTypeDirect)
	if err != nil {
		return err
	}
	c3, err := contractorNew(admin, cms.DomainTypeDeveloper,
		cms.ContractorTypeDirect)
	if err != nil {
		return err
	}

	// Create a nominee
	fmt.Printf("  create a user to be the nominee\n")

	n1, err := userNew(admin)
	if err != nil {
		return err
	}

	// Create a new DCC for the nominee
	fmt.Printf("  create a DCC for the nominee: ")

	dcc, err := dccNew(*c1, n1.ID, cms.DCCTypeIssuance,
		cms.DomainTypeDeveloper, cms.ContractorTypeDirect)
	if err != nil {
		return err
	}
	dccToken := dcc.CensorshipRecord.Token

	fmt.Printf("%v\n", dccToken)

	// Comment on the DCC
	fmt.Printf("  comment on the DCC\n")

	err = dccCommentNew(*c1, dccToken, "", randomString())
	if err != nil {
		return err
	}
	err = dccCommentNew(*c2, dccToken, "", randomString())
	if err != nil {
		return err
	}
	err = dccCommentNew(*c3, dccToken, "", randomString())
	if err != nil {
		return err
	}

	// Support the DCC
	fmt.Printf("  support the DCC\n")

	err = dccSupport(*c2, dccToken, dccIssuanceSupport)
	if err != nil {
		return err
	}
	err = dccSupport(*c3, dccToken, dccIssuanceSupport)
	if err != nil {
		return err
	}

	// Have admin approve the DCC
	fmt.Printf("  approve the DCC\n")

	err = dccSetStatus(admin, dccToken, cms.DCCStatusApproved,
		"there was non-contentious support")
	if err != nil {
		return err
	}

	// Create a nominee. This time we'll reject their DCC.
	fmt.Printf("  create a user to be the nominee\n")

	n2, err := userNew(admin)
	if err != nil {
		return err
	}

	// Create a new DCC for the nominee
	fmt.Printf("  create a DCC for the nominee: ")

	dcc, err = dccNew(*c1, n2.ID, cms.DCCTypeIssuance,
		cms.DomainTypeDeveloper, cms.ContractorTypeDirect)
	if err != nil {
		return err
	}
	dccToken = dcc.CensorshipRecord.Token

	fmt.Printf("%v\n", dccToken)

	// Oppose the DCC
	fmt.Printf("  oppose the DCC\n")

	err = dccSupport(*c2, dccToken, dccIssuanceOppose)
	if err != nil {
		return err
	}
	err = dccSupport(*c3, dccToken, dccIssuanceOppose)
	if err != nil {
		return err
	}

	// Have admin reject the DCC
	fmt.Printf("  reject the DCC\n")

	err = dccSetStatus(admin, dccToken, cms.DCCStatusRejected,
		"there was non-contentious opposition")
	if err != nil {
		return err
	}

	fmt.Printf("testDCC success!\n")

	return nil
}

// testDCCVote tests the DCC all contractor vote routes.
//
// When a DCC proposal is deemed contentious by the admin, the admin can start
// an all contractor vote for the DCC. Contractors are able to cast votes
// proportional to the amount of time they've billed, and that has been paid,
// over the previous 6 months. Admins still currently have final say over
// whether to approve or reject the DCC.
//
// The admin starts an all contractor vote on a DCC by setting the DCC status
// to DCCStatusAllVote.
func testDCCVote(admin user) error {
	fmt.Printf("Running testDCCVote\n")

	// Create three users and make them existing contractors
	fmt.Printf("  create existing contractors\n")

	c1, err := contractorNew(admin, cms.DomainTypeDeveloper,
		cms.ContractorTypeDirect)
	if err != nil {
		return err
	}
	c2, err := contractorNew(admin, cms.DomainTypeDeveloper,
		cms.ContractorTypeDirect)
	if err != nil {
		return err
	}
	c3, err := contractorNew(admin, cms.DomainTypeDeveloper,
		cms.ContractorTypeDirect)
	if err != nil {
		return err
	}

	// Submit and pay invoices for the users so that we can make sure
	// the vote weights are being calculated correctly.
	fmt.Printf("  submitting invoices for contractors\n")

	cr1, err := invoiceNew(*c1, 40, 50)
	if err != nil {
		return err
	}
	cr2, err := invoiceNew(*c2, 40, 100)
	if err != nil {
		return err
	}
	cr3, err := invoiceNew(*c3, 40, 150)
	if err != nil {
		return err
	}

	fmt.Printf("  marking invoices as approved and paid\n")

	err = invoiceSetStatus(admin, cr1.Token, cms.InvoiceStatusApproved)
	if err != nil {
		return err
	}
	err = invoiceSetStatus(admin, cr2.Token, cms.InvoiceStatusApproved)
	if err != nil {
		return err
	}
	err = invoiceSetStatus(admin, cr3.Token, cms.InvoiceStatusApproved)
	if err != nil {
		return err
	}
	err = invoicesPay(admin)
	if err != nil {
		return err
	}

	// Create a nominee
	fmt.Printf("  create a user to be the nominee\n")

	n1, err := userNew(admin)
	if err != nil {
		return err
	}

	// Create a new DCC for the nominee
	fmt.Printf("  create a DCC for the nominee: ")

	dcc, err := dccNew(*c1, n1.ID, cms.DCCTypeIssuance,
		cms.DomainTypeDeveloper, cms.ContractorTypeDirect)
	if err != nil {
		return err
	}
	dccToken := dcc.CensorshipRecord.Token

	fmt.Printf("%v\n", dccToken)

	// Support/oppose the DCC
	fmt.Printf("  support/oppose DCC\n")

	err = dccSupport(*c2, dccToken, dccIssuanceSupport)
	if err != nil {
		return err
	}
	err = dccSupport(*c3, dccToken, dccIssuanceOppose)
	if err != nil {
		return err
	}

	// Start an all contractor vote for the DCC
	fmt.Printf("  start DCC vote\n")
	err = dccStartVote(admin, dccToken)
	if err != nil {
		return err
	}

	// Vote on the DCC
	fmt.Printf("  cast DCC votes\n")
	err = dccVote(*c2, dccToken, cmsplugin.DCCApprovalString)
	if err != nil {
		return err
	}
	expectedApprovalVotes := uint64(1)
	err = dccVote(*c3, dccToken, cmsplugin.DCCDisapprovalString)
	if err != nil {
		return err
	}
	expectedDisapprovalVotes := uint64(1)
	// Check to see that the votes are properly cast in gitbe
	fmt.Printf("  check DCC votes")
	vs, err := dccVoteSummary(*c2, dccToken)
	if err != nil {
		return err
	}
	expectedVoteOptionResults := 2
	if len(vs.Results) != expectedVoteOptionResults {
		return fmt.Errorf("unexpected number of vote option results: got %v,"+
			" wanted %v", len(vs.Results), expectedVoteOptionResults)
	}
	for _, result := range vs.Results {
		if result.Option.Id == cmsplugin.DCCApprovalString &&
			result.VotesReceived != expectedApprovalVotes {
			return fmt.Errorf("unexpected amount of %v votes, got %v wanted %v",
				cmsplugin.DCCApprovalString, result.VotesReceived,
				expectedApprovalVotes)
		}
		if result.Option.Id == cmsplugin.DCCDisapprovalString &&
			result.VotesReceived != expectedDisapprovalVotes {
			return fmt.Errorf("unexpected amount of %v votes, got %v wanted %v",
				cmsplugin.DCCDisapprovalString, result.VotesReceived,
				expectedDisapprovalVotes)
		}
	}
	/*
		// Have the admin approve the DCC
		// This can't be done in the test run because the vote needs to
		// have ended before the admin can change the status. This is how
		// a DCC is ultimately decided as approved or rejected though.
		err = dccSetStatus(admin, dccToken, cms.DCCStatusApproved,
			"I decree it to be")
		if err != nil {
			return err
		}
	*/

	fmt.Printf("testDCCVote success!\n")

	return nil
}

// Execute executes the TestRun command.
func (cmd *TestRunCmd) Execute(args []string) error {
	const (
		modeCMSWWW = "cmswww"
	)

	// Suppress output from cli commands
	cfg.Silent = true

	fmt.Printf("Running pre-testrun validation\n")

	// Validate politeiawww setup
	vr, err := client.Version()
	switch {
	case err != nil:
		return fmt.Errorf("version: %v", err)
	case vr.Mode != modeCMSWWW:
		return fmt.Errorf("politeiawww is not in cmswww mode")
	case !vr.TestNet:
		return fmt.Errorf("politeiawww is not on testnet")
	}

	// Validate admin credentials
	admin := user{
		Email:    cmd.Args.AdminEmail,
		Password: cmd.Args.AdminPassword,
	}
	err = login(admin)
	if err != nil {
		return err
	}
	lr, err := client.Me()
	if err != nil {
		return err
	}
	if !lr.IsAdmin {
		return fmt.Errorf("%v is not an admin", admin.Email)
	}
	admin.Username = lr.Username

	// Test runs
	err = testDCC(admin)
	if err != nil {
		return fmt.Errorf("testDCC: %v", err)
	}
	err = testDCCVote(admin)
	if err != nil {
		return fmt.Errorf("testDCCVote: %v", err)
	}

	fmt.Printf("testrun complete!\n")

	return nil
}
