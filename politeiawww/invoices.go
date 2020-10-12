// Copyright (c) 2019-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/decred/dcrd/dcrutil/v3"
	"github.com/decred/politeia/decredplugin"
	"github.com/decred/politeia/mdstream"
	pd "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/cmsdatabase"
	database "github.com/decred/politeia/politeiawww/cmsdatabase"
	"github.com/decred/politeia/politeiawww/user"
	wwwutil "github.com/decred/politeia/politeiawww/util"
	"github.com/decred/politeia/util"
)

const (
	// invoiceFile contains the file name of the invoice file
	invoiceFile = "invoice.json"

	// Sanity check for Contractor Rates
	minRate = 500   // 5 USD (in cents)
	maxRate = 50000 // 500 USD (in cents)

	domainInvoiceLimit = time.Minute * 60 * 24 * 180 // 180 days in minutes
)

var (
	// This covers the possible valid status transitions for any invoices.  If
	// a current invoice's status does not fall into these 3 categories, then
	// an admin will not be able to update their status.  For example,
	// paid or approved invoices cannot have their status changed.
	validStatusTransitions = map[cms.InvoiceStatusT][]cms.InvoiceStatusT{
		// New invoices may only be updated to approved, rejected or disputed.
		cms.InvoiceStatusNew: {
			cms.InvoiceStatusApproved,
			cms.InvoiceStatusRejected,
			cms.InvoiceStatusDisputed,
		},
		// Updated invoices may only be updated to approved, rejected or disputed.
		cms.InvoiceStatusUpdated: {
			cms.InvoiceStatusApproved,
			cms.InvoiceStatusRejected,
			cms.InvoiceStatusDisputed,
		},
	}
	// The invalid contractor types for new invoice submission
	invalidNewInvoiceContractorType = map[cms.ContractorTypeT]bool{
		cms.ContractorTypeNominee:         true,
		cms.ContractorTypeInvalid:         true,
		cms.ContractorTypeSubContractor:   true,
		cms.ContractorTypeTempDeactivated: true,
	}

	// The valid contractor types for domain invoice viewing
	validDomainInvoiceViewingContractorType = map[cms.ContractorTypeT]bool{
		cms.ContractorTypeDirect:        true,
		cms.ContractorTypeSupervisor:    true,
		cms.ContractorTypeSubContractor: true,
	}

	validInvoiceField = regexp.MustCompile(createInvoiceFieldRegex())
	validName         = regexp.MustCompile(createNameRegex())
	validLocation     = regexp.MustCompile(createLocationRegex())
	validContact      = regexp.MustCompile(createContactRegex())
)

func convertPDFileFromWWW(f www.File) pd.File {
	return pd.File{
		Name:    f.Name,
		MIME:    f.MIME,
		Digest:  f.Digest,
		Payload: f.Payload,
	}
}

func convertPDFilesFromWWW(f []www.File) []pd.File {
	files := make([]pd.File, 0, len(f))
	for _, v := range f {
		files = append(files, convertPDFileFromWWW(v))
	}
	return files
}

func convertPDCensorFromWWW(f www.CensorshipRecord) pd.CensorshipRecord {
	return pd.CensorshipRecord{
		Token:     f.Token,
		Merkle:    f.Merkle,
		Signature: f.Signature,
	}
}

func convertWWWFileFromPD(f pd.File) www.File {
	return www.File{
		Name:    f.Name,
		MIME:    f.MIME,
		Digest:  f.Digest,
		Payload: f.Payload,
	}
}

func convertWWWFilesFromPD(f []pd.File) []www.File {
	files := make([]www.File, 0, len(f))
	for _, v := range f {
		files = append(files, convertWWWFileFromPD(v))
	}
	return files
}

func convertWWWCensorFromPD(f pd.CensorshipRecord) www.CensorshipRecord {
	return www.CensorshipRecord{
		Token:     f.Token,
		Merkle:    f.Merkle,
		Signature: f.Signature,
	}
}

func convertNewCommentToDecredPlugin(nc www.NewComment) decredplugin.NewComment {
	return decredplugin.NewComment{
		Token:     nc.Token,
		ParentID:  nc.ParentID,
		Comment:   nc.Comment,
		Signature: nc.Signature,
		PublicKey: nc.PublicKey,
	}
}

func convertCommentFromDecred(c decredplugin.Comment) www.Comment {
	// Upvotes, Downvotes, UserID, and Username are filled in as zero
	// values since a decred plugin comment does not contain this data.
	return www.Comment{
		Token:       c.Token,
		ParentID:    c.ParentID,
		Comment:     c.Comment,
		Signature:   c.Signature,
		PublicKey:   c.PublicKey,
		CommentID:   c.CommentID,
		Receipt:     c.Receipt,
		Timestamp:   c.Timestamp,
		ResultVotes: 0,
		Upvotes:     0,
		Downvotes:   0,
		UserID:      "",
		Username:    "",
		Censored:    c.Censored,
	}
}

func convertDatabaseInvoiceToInvoiceRecord(dbInvoice cmsdatabase.Invoice) (cms.InvoiceRecord, error) {
	invRec := cms.InvoiceRecord{}
	invRec.Status = dbInvoice.Status
	invRec.Timestamp = dbInvoice.Timestamp
	invRec.UserID = dbInvoice.UserID
	invRec.Username = dbInvoice.Username
	invRec.PublicKey = dbInvoice.PublicKey
	invRec.Version = dbInvoice.Version
	invRec.Signature = dbInvoice.UserSignature
	invRec.CensorshipRecord = www.CensorshipRecord{
		Token: dbInvoice.Token,
	}
	invInput := cms.InvoiceInput{
		ContractorContact:  dbInvoice.ContractorContact,
		ContractorRate:     dbInvoice.ContractorRate,
		ContractorName:     dbInvoice.ContractorName,
		ContractorLocation: dbInvoice.ContractorLocation,
		PaymentAddress:     dbInvoice.PaymentAddress,
		Month:              dbInvoice.Month,
		Year:               dbInvoice.Year,
		ExchangeRate:       dbInvoice.ExchangeRate,
	}
	invInputLineItems := make([]cms.LineItemsInput, 0, len(dbInvoice.LineItems))
	for _, dbLineItem := range dbInvoice.LineItems {
		lineItem := cms.LineItemsInput{
			Type:          dbLineItem.Type,
			Domain:        dbLineItem.Domain,
			Subdomain:     dbLineItem.Subdomain,
			Description:   dbLineItem.Description,
			ProposalToken: dbLineItem.ProposalURL,
			Labor:         dbLineItem.Labor,
			Expenses:      dbLineItem.Expenses,
			SubRate:       dbLineItem.ContractorRate,
			SubUserID:     dbLineItem.SubUserID,
		}
		invInputLineItems = append(invInputLineItems, lineItem)
	}

	payout, err := calculatePayout(dbInvoice)
	if err != nil {
		return invRec, err
	}
	invRec.Total = int64(payout.Total)

	invInput.LineItems = invInputLineItems
	invRec.Input = invInput
	invRec.Input.LineItems = invInputLineItems
	txIDs := strings.Split(dbInvoice.Payments.TxIDs, ",")
	payment := cms.PaymentInformation{
		Token:           dbInvoice.Payments.InvoiceToken,
		Address:         dbInvoice.Payments.Address,
		TxIDs:           txIDs,
		AmountReceived:  dcrutil.Amount(dbInvoice.Payments.AmountReceived),
		TimeLastUpdated: dbInvoice.Payments.TimeLastUpdated,
	}
	invRec.Payment = payment
	return invRec, nil
}

func convertInvoiceRecordToDatabaseInvoice(invRec *cms.InvoiceRecord) *cmsdatabase.Invoice {
	dbInvoice := &cmsdatabase.Invoice{}
	dbInvoice.Status = invRec.Status
	dbInvoice.Timestamp = invRec.Timestamp
	dbInvoice.UserID = invRec.UserID
	dbInvoice.PublicKey = invRec.PublicKey
	dbInvoice.Version = invRec.Version
	dbInvoice.ContractorContact = invRec.Input.ContractorContact
	dbInvoice.ContractorRate = invRec.Input.ContractorRate
	dbInvoice.ContractorName = invRec.Input.ContractorName
	dbInvoice.ContractorLocation = invRec.Input.ContractorLocation
	dbInvoice.PaymentAddress = invRec.Input.PaymentAddress
	dbInvoice.Month = invRec.Input.Month
	dbInvoice.Year = invRec.Input.Year
	dbInvoice.ExchangeRate = invRec.Input.ExchangeRate
	dbInvoice.Token = invRec.CensorshipRecord.Token
	dbInvoice.ServerSignature = invRec.Signature

	dbInvoice.LineItems = make([]cmsdatabase.LineItem, 0, len(invRec.Input.LineItems))
	for _, lineItem := range invRec.Input.LineItems {
		dbLineItem := cmsdatabase.LineItem{
			Type:           lineItem.Type,
			Domain:         lineItem.Domain,
			Subdomain:      lineItem.Subdomain,
			Description:    lineItem.Description,
			ProposalURL:    lineItem.ProposalToken,
			Labor:          lineItem.Labor,
			Expenses:       lineItem.Expenses,
			ContractorRate: lineItem.SubRate,
			SubUserID:      lineItem.SubUserID,
		}
		dbInvoice.LineItems = append(dbInvoice.LineItems, dbLineItem)
	}
	return dbInvoice
}

func convertLineItemsToDatabase(token string, l []cms.LineItemsInput) []cmsdatabase.LineItem {
	dl := make([]cmsdatabase.LineItem, 0, len(l))
	for _, v := range l {
		dl = append(dl, cmsdatabase.LineItem{
			InvoiceToken: token,
			Type:         v.Type,
			Domain:       v.Domain,
			Subdomain:    v.Subdomain,
			Description:  v.Description,
			ProposalURL:  v.ProposalToken,
			Labor:        v.Labor,
			Expenses:     v.Expenses,
			// If subrate is populated, use the existing contractor rate field.
			ContractorRate: v.SubRate,
			SubUserID:      v.SubUserID,
		})
	}
	return dl
}

func convertRecordToDatabaseInvoice(p pd.Record) (*cmsdatabase.Invoice, error) {
	dbInvoice := cmsdatabase.Invoice{
		Files:           convertWWWFilesFromPD(p.Files),
		Token:           p.CensorshipRecord.Token,
		ServerSignature: p.CensorshipRecord.Signature,
		Version:         p.Version,
	}

	// Decode invoice file
	for _, v := range p.Files {
		if v.Name == invoiceFile {
			b, err := base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				return nil, err
			}

			var ii cms.InvoiceInput
			err = json.Unmarshal(b, &ii)
			if err != nil {
				return nil, www.UserError{
					ErrorCode: www.ErrorStatusInvalidInput,
				}
			}

			dbInvoice.Month = ii.Month
			dbInvoice.Year = ii.Year
			dbInvoice.ExchangeRate = ii.ExchangeRate
			dbInvoice.LineItems = convertLineItemsToDatabase(dbInvoice.Token,
				ii.LineItems)
			dbInvoice.ContractorContact = ii.ContractorContact
			dbInvoice.ContractorLocation = ii.ContractorLocation
			dbInvoice.ContractorRate = ii.ContractorRate
			dbInvoice.ContractorName = ii.ContractorName
			dbInvoice.PaymentAddress = ii.PaymentAddress
		}
	}
	payout, err := calculatePayout(dbInvoice)
	if err != nil {
		return nil, err
	}
	payment := cmsdatabase.Payments{
		Address:      dbInvoice.PaymentAddress,
		AmountNeeded: int64(payout.DCRTotal),
	}
	for _, m := range p.Metadata {
		switch m.ID {
		case mdstream.IDRecordStatusChange:
			// Ignore initial stream change since it's just the automatic change from
			// unvetted to vetted
			continue
		case mdstream.IDInvoiceGeneral:
			var mdGeneral mdstream.InvoiceGeneral
			err := json.Unmarshal([]byte(m.Payload), &mdGeneral)
			if err != nil {
				return nil, fmt.Errorf("could not decode metadata '%v' token '%v': %v",
					p.Metadata, p.CensorshipRecord.Token, err)
			}

			dbInvoice.Timestamp = mdGeneral.Timestamp
			dbInvoice.PublicKey = mdGeneral.PublicKey
			dbInvoice.UserSignature = mdGeneral.Signature
		case mdstream.IDInvoiceStatusChange:
			sc, err := mdstream.DecodeInvoiceStatusChange([]byte(m.Payload))
			if err != nil {
				return nil, fmt.Errorf("could not decode metadata '%v' token '%v': %v",
					m, p.CensorshipRecord.Token, err)
			}

			invChanges := make([]cmsdatabase.InvoiceChange, 0, len(sc))
			for _, s := range sc {
				invChange := cmsdatabase.InvoiceChange{
					AdminPublicKey: s.AdminPublicKey,
					NewStatus:      s.NewStatus,
					Reason:         s.Reason,
					Timestamp:      s.Timestamp,
				}
				invChanges = append(invChanges, invChange)
				// Capture information about payments
				dbInvoice.Status = s.NewStatus
				if s.NewStatus == cms.InvoiceStatusApproved {
					payment.Status = cms.PaymentStatusWatching
					payment.TimeStarted = s.Timestamp
				} else if s.NewStatus == cms.InvoiceStatusPaid {
					payment.Status = cms.PaymentStatusPaid
				}
			}
			dbInvoice.Changes = invChanges

		case mdstream.IDInvoicePayment:
			ip, err := mdstream.DecodeInvoicePayment([]byte(m.Payload))
			if err != nil {
				return nil, fmt.Errorf("could not decode metadata '%v' token '%v': %v",
					m, p.CensorshipRecord.Token, err)
			}

			// We don't need all of the payments.
			// Just the most recent one.
			for _, s := range ip {
				payment.TxIDs = s.TxIDs
				payment.TimeLastUpdated = s.Timestamp
				payment.AmountReceived = s.AmountReceived
			}
			dbInvoice.Payments = payment
		default:
			// Log error but proceed
			log.Errorf("initializeInventory: invalid "+
				"metadata stream ID %v token %v",
				m.ID, p.CensorshipRecord.Token)
		}
	}

	return &dbInvoice, nil
}

func convertDatabaseInvoiceToProposalLineItems(inv cmsdatabase.Invoice) cms.ProposalLineItems {
	return cms.ProposalLineItems{
		Month:    int(inv.Month),
		Year:     int(inv.Year),
		UserID:   inv.UserID,
		Username: inv.Username,
		LineItem: cms.LineItemsInput{
			Type:          inv.LineItems[0].Type,
			Domain:        inv.LineItems[0].Domain,
			Subdomain:     inv.LineItems[0].Subdomain,
			Description:   inv.LineItems[0].Description,
			ProposalToken: inv.LineItems[0].ProposalURL,
			Labor:         inv.LineItems[0].Labor,
			Expenses:      inv.LineItems[0].Expenses,
			SubRate:       inv.LineItems[0].ContractorRate,
		},
	}
}

// formatInvoiceField normalizes an invoice field without leading and
// trailing spaces.
func formatInvoiceField(field string) string {
	return strings.TrimSpace(field)
}

// validateInvoiceField verifies that a field filled out in invoice.json is
// valid
func validateInvoiceField(field string) bool {
	if field != formatInvoiceField(field) {
		log.Tracef("validateInvoiceField: not normalized: %s %s",
			field, formatInvoiceField(field))
		return false
	}
	if len(field) > cms.PolicyMaxLineItemColLength ||
		len(field) < cms.PolicyMinLineItemColLength {
		log.Tracef("validateInvoiceField: not within bounds: %s",
			field)
		return false
	}
	if !validInvoiceField.MatchString(field) {
		log.Tracef("validateInvoiceField: not valid: %s %s",
			field, validInvoiceField.String())
		return false
	}
	return true
}

// createInvoiceFieldRegex generates a regex based on the policy supplied for
// valid characters invoice field.
func createInvoiceFieldRegex() string {
	var buf bytes.Buffer
	buf.WriteString("^[")

	for _, supportedChar := range cms.PolicyInvoiceFieldSupportedChars {
		if len(supportedChar) > 1 {
			buf.WriteString(supportedChar)
		} else {
			buf.WriteString(`\` + supportedChar)
		}
	}
	buf.WriteString("]{")
	buf.WriteString(strconv.Itoa(cms.PolicyMinLineItemColLength) + ",")
	buf.WriteString(strconv.Itoa(cms.PolicyMaxLineItemColLength) + "}$")

	return buf.String()
}

// createNameRegex generates a regex based on the policy supplied for valid
// characters in a user's name.
func createNameRegex() string {
	var buf bytes.Buffer
	buf.WriteString("^[")

	for _, supportedChar := range cms.PolicyCMSNameLocationSupportedChars {
		if len(supportedChar) > 1 {
			buf.WriteString(supportedChar)
		} else {
			buf.WriteString(`\` + supportedChar)
		}
	}
	buf.WriteString("]{")
	buf.WriteString(strconv.Itoa(cms.PolicyMinNameLength) + ",")
	buf.WriteString(strconv.Itoa(cms.PolicyMaxNameLength) + "}$")

	return buf.String()
}

// createLocationRegex generates a regex based on the policy supplied for valid
// characters in a user's location.
func createLocationRegex() string {
	var buf bytes.Buffer
	buf.WriteString("^[")

	for _, supportedChar := range cms.PolicyCMSNameLocationSupportedChars {
		if len(supportedChar) > 1 {
			buf.WriteString(supportedChar)
		} else {
			buf.WriteString(`\` + supportedChar)
		}
	}
	buf.WriteString("]{")
	buf.WriteString(strconv.Itoa(cms.PolicyMinLocationLength) + ",")
	buf.WriteString(strconv.Itoa(cms.PolicyMaxLocationLength) + "}$")

	return buf.String()
}

// createContactRegex generates a regex based on the policy supplied for valid
// characters in a user's contact information.
func createContactRegex() string {
	var buf bytes.Buffer
	buf.WriteString("^[")

	for _, supportedChar := range cms.PolicyCMSContactSupportedChars {
		if len(supportedChar) > 1 {
			buf.WriteString(supportedChar)
		} else {
			buf.WriteString(`\` + supportedChar)
		}
	}
	buf.WriteString("]{")
	buf.WriteString(strconv.Itoa(cms.PolicyMinContactLength) + ",")
	buf.WriteString(strconv.Itoa(cms.PolicyMaxContactLength) + "}$")

	return buf.String()
}

// formatName normalizes a contractor name to lowercase without leading and
// trailing spaces.
func formatName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func validateName(name string) error {
	if len(name) < cms.PolicyMinNameLength ||
		len(name) > cms.PolicyMaxNameLength {
		log.Debugf("Name not within bounds: %s", name)
		return www.UserError{
			ErrorCode: cms.ErrorStatusMalformedName,
		}
	}

	if !validName.MatchString(name) {
		log.Debugf("Name not valid: %s %s", name, validName.String())
		return www.UserError{
			ErrorCode: cms.ErrorStatusMalformedName,
		}
	}

	return nil
}

// formatLocation normalizes a contractor location to lowercase without leading and
// trailing spaces.
func formatLocation(location string) string {
	return strings.ToLower(strings.TrimSpace(location))
}

func validateLocation(location string) error {
	if len(location) < cms.PolicyMinLocationLength ||
		len(location) > cms.PolicyMaxLocationLength {
		log.Debugf("Location not within bounds: %s", location)
		return www.UserError{
			ErrorCode: cms.ErrorStatusMalformedLocation,
		}
	}

	if !validLocation.MatchString(location) {
		log.Debugf("Location not valid: %s %s", location, validLocation.String())
		return www.UserError{
			ErrorCode: cms.ErrorStatusMalformedLocation,
		}
	}

	return nil
}

// formatContact normalizes a contractor contact to lowercase without leading and
// trailing spaces.
func formatContact(contact string) string {
	return strings.ToLower(strings.TrimSpace(contact))
}

func validateContact(contact string) error {
	if len(contact) < cms.PolicyMinContactLength ||
		len(contact) > cms.PolicyMaxContactLength {
		log.Debugf("Contact not within bounds: %s", contact)
		return www.UserError{
			ErrorCode: cms.ErrorStatusInvoiceMalformedContact,
		}
	}

	if !validContact.MatchString(contact) {
		log.Debugf("Contact not valid: %s %s", contact, validContact.String())
		return www.UserError{
			ErrorCode: cms.ErrorStatusInvoiceMalformedContact,
		}
	}

	return nil
}

// processNewInvoice tries to submit a new invoice to politeiad.
func (p *politeiawww) processNewInvoice(ctx context.Context, ni cms.NewInvoice, u *user.User) (*cms.NewInvoiceReply, error) {
	log.Tracef("processNewInvoice")

	cmsUser, err := p.getCMSUserByIDRaw(u.ID.String())
	if err != nil {
		return nil, err
	}

	// Ensure that the user is not unauthorized to create invoices
	if _, ok := invalidNewInvoiceContractorType[cms.ContractorTypeT(
		cmsUser.ContractorType)]; ok {
		return nil, www.UserError{
			ErrorCode: cms.ErrorStatusInvalidUserNewInvoice,
		}
	}
	err = p.validateInvoice(ni, cmsUser)
	if err != nil {
		return nil, err
	}

	// Dupe address check.
	invInput, err := parseInvoiceInput(ni.Files)
	if err != nil {
		return nil, err
	}

	invoiceAddress, err := p.cmsDB.InvoicesByAddress(invInput.PaymentAddress)
	if err != nil {
		return nil, www.UserError{
			ErrorCode: cms.ErrorStatusInvalidPaymentAddress,
		}
	}
	if len(invoiceAddress) > 0 {
		return nil, www.UserError{
			ErrorCode: cms.ErrorStatusDuplicatePaymentAddress,
		}
	}

	m := mdstream.InvoiceGeneral{
		Version:   mdstream.VersionInvoiceGeneral,
		Timestamp: time.Now().Unix(),
		PublicKey: ni.PublicKey,
		Signature: ni.Signature,
	}
	md, err := mdstream.EncodeInvoiceGeneral(m)
	if err != nil {
		return nil, err
	}

	sc := mdstream.InvoiceStatusChange{
		Version:   mdstream.IDInvoiceStatusChange,
		Timestamp: time.Now().Unix(),
		NewStatus: cms.InvoiceStatusNew,
	}
	scb, err := mdstream.EncodeInvoiceStatusChange(sc)
	if err != nil {
		return nil, err
	}

	// Setup politeiad request
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}
	n := pd.NewRecord{
		Challenge: hex.EncodeToString(challenge),
		Metadata: []pd.MetadataStream{
			{
				ID:      mdstream.IDInvoiceGeneral,
				Payload: string(md),
			},
			{
				ID:      mdstream.IDInvoiceStatusChange,
				Payload: string(scb),
			},
		},
		Files: convertPDFilesFromWWW(ni.Files),
	}

	// Handle test case
	if p.test {
		tokenBytes, err := util.Random(pd.TokenSizeMax)
		if err != nil {
			return nil, err
		}

		testReply := pd.NewRecordReply{
			CensorshipRecord: pd.CensorshipRecord{
				Token: hex.EncodeToString(tokenBytes),
			},
		}

		return &cms.NewInvoiceReply{
			CensorshipRecord: convertWWWCensorFromPD(testReply.CensorshipRecord),
		}, nil
	}

	// Send the newrecord politeiad request
	responseBody, err := p.makeRequest(ctx, http.MethodPost,
		pd.NewRecordRoute, n)
	if err != nil {
		return nil, err
	}

	log.Infof("Submitted invoice: %v %v-%v",
		u.Username, ni.Month, ni.Year)
	for k, f := range n.Files {
		log.Infof("%02v: %v %v", k, f.Name, f.Digest)
	}

	// Handle newRecord response
	var pdReply pd.NewRecordReply
	err = json.Unmarshal(responseBody, &pdReply)
	if err != nil {
		return nil, fmt.Errorf("Unmarshal NewInvoiceReply: %v", err)
	}

	// Verify NewRecord challenge
	err = util.VerifyChallenge(p.cfg.Identity, challenge, pdReply.Response)
	if err != nil {
		return nil, err
	}

	// Change politeiad record status to public. Invoices
	// do not need to be reviewed before becoming public.
	// An admin pubkey and signature are not included for
	// this reason.
	c := mdstream.RecordStatusChangeV2{
		Version:   mdstream.VersionRecordStatusChange,
		Timestamp: time.Now().Unix(),
		NewStatus: pd.RecordStatusPublic,
	}
	blob, err := mdstream.EncodeRecordStatusChangeV2(c)
	if err != nil {
		return nil, err
	}

	challenge, err = util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	sus := pd.SetUnvettedStatus{
		Token:     pdReply.CensorshipRecord.Token,
		Status:    pd.RecordStatusPublic,
		Challenge: hex.EncodeToString(challenge),
		MDAppend: []pd.MetadataStream{
			{
				ID:      mdstream.IDRecordStatusChange,
				Payload: string(blob),
			},
		},
	}

	// Send SetUnvettedStatus request to politeiad
	responseBody, err = p.makeRequest(ctx, http.MethodPost,
		pd.SetUnvettedStatusRoute, sus)
	if err != nil {
		return nil, err
	}

	var pdSetUnvettedStatusReply pd.SetUnvettedStatusReply
	err = json.Unmarshal(responseBody, &pdSetUnvettedStatusReply)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal SetUnvettedStatusReply: %v",
			err)
	}

	// Verify the SetUnvettedStatus challenge.
	err = util.VerifyChallenge(p.cfg.Identity, challenge,
		pdSetUnvettedStatusReply.Response)
	if err != nil {
		return nil, err
	}

	r := pd.Record{
		Metadata:         n.Metadata,
		Files:            n.Files,
		CensorshipRecord: pdReply.CensorshipRecord,
		Version:          "1",
	}
	ir, err := convertRecordToDatabaseInvoice(r)
	if err != nil {
		return nil, err
	}
	// Set UserID for current user
	ir.UserID = u.ID.String()
	ir.Status = cms.InvoiceStatusNew

	err = p.cmsDB.NewInvoice(ir)
	if err != nil {
		return nil, err
	}
	cr := convertWWWCensorFromPD(pdReply.CensorshipRecord)

	return &cms.NewInvoiceReply{
		CensorshipRecord: cr,
	}, nil
}

func (p *politeiawww) validateInvoice(ni cms.NewInvoice, u *user.CMSUser) error {
	log.Tracef("validateInvoice")

	// Obtain signature
	sig, err := util.ConvertSignature(ni.Signature)
	if err != nil {
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidSignature,
		}
	}

	// Verify public key
	if u.PublicKey() != ni.PublicKey {
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidSigningKey,
		}
	}

	pk, err := identity.PublicIdentityFromBytes(u.ActiveIdentity().Key[:])
	if err != nil {
		return err
	}

	// Check for at least 1 markdown file with a non-empty payload.
	if len(ni.Files) == 0 || ni.Files[0].Payload == "" {
		return www.UserError{
			ErrorCode: www.ErrorStatusProposalMissingFiles,
		}
	}

	// verify if there are duplicate names
	filenames := make(map[string]int, len(ni.Files))
	// Check that the file number policy is followed.
	var (
		numCSVs, numImages, numInvoiceFiles    int
		csvExceedsMaxSize, imageExceedsMaxSize bool
	)
	for _, v := range ni.Files {
		filenames[v.Name]++
		var (
			data []byte
			err  error
		)
		if strings.HasPrefix(v.MIME, "image/") {
			numImages++
			data, err = base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				return err
			}
			if len(data) > cms.PolicyMaxImageSize {
				imageExceedsMaxSize = true
			}
		} else {
			numCSVs++

			if v.Name == invoiceFile {
				numInvoiceFiles++
			}

			data, err = base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				return err
			}
			if len(data) > cms.PolicyMaxMDSize {
				csvExceedsMaxSize = true
			}

			// Check to see if the data can be parsed properly into InvoiceInput
			// struct.
			var invInput cms.InvoiceInput
			if err := json.Unmarshal(data, &invInput); err != nil {
				return www.UserError{
					ErrorCode: cms.ErrorStatusMalformedInvoiceFile,
				}
			}

			// Validate that the input month is a valid month
			if invInput.Month < 1 || invInput.Month > 12 {
				return www.UserError{
					ErrorCode: cms.ErrorStatusInvalidInvoiceMonthYear,
				}
			}

			// Validate month/year to make sure the first day of the following
			// month is after the current date.  For example, if a user submits
			// an invoice for 03/2019, the first time that they could submit an
			// invoice would be approx. 12:01 AM 04/01/2019
			startOfFollowingMonth := time.Date(int(invInput.Year),
				time.Month(invInput.Month+1), 0, 0, 0, 0, 0, time.UTC)
			if startOfFollowingMonth.After(time.Now()) {
				return www.UserError{
					ErrorCode: cms.ErrorStatusInvalidInvoiceMonthYear,
				}
			}

			// Validate Payment Address
			_, err := dcrutil.DecodeAddress(strings.TrimSpace(invInput.PaymentAddress), p.params)
			if err != nil {
				return www.UserError{
					ErrorCode: cms.ErrorStatusInvalidPaymentAddress,
				}
			}

			// Verify that the submitted monthly average matches the value
			// was calculated server side.
			monthAvg, err := p.cmsDB.ExchangeRate(int(invInput.Month),
				int(invInput.Year))
			if err != nil {
				return www.UserError{
					ErrorCode: cms.ErrorStatusInvalidExchangeRate,
				}
			}
			if monthAvg.ExchangeRate != invInput.ExchangeRate {
				return www.UserError{
					ErrorCode: cms.ErrorStatusInvalidExchangeRate,
				}
			}

			// Validate provided contractor name
			if invInput.ContractorName == "" {
				return www.UserError{
					ErrorCode: cms.ErrorStatusInvoiceMissingName,
				}
			}
			name := formatName(invInput.ContractorName)
			err = validateName(name)
			if err != nil {
				return www.UserError{
					ErrorCode: cms.ErrorStatusMalformedName,
				}
			}

			location := formatLocation(invInput.ContractorLocation)
			err = validateLocation(location)
			if err != nil {
				return www.UserError{
					ErrorCode: cms.ErrorStatusMalformedLocation,
				}
			}

			// Validate provided contractor email/contact
			if invInput.ContractorContact == "" {
				return www.UserError{
					ErrorCode: cms.ErrorStatusInvoiceMissingContact,
				}
			}
			contact := formatContact(invInput.ContractorContact)
			err = validateContact(contact)
			if err != nil {
				return www.UserError{
					ErrorCode: cms.ErrorStatusInvoiceMalformedContact,
				}
			}

			// Validate hourly rate
			if invInput.ContractorRate == 0 {
				return www.UserError{
					ErrorCode: cms.ErrorStatusInvoiceMissingRate,
				}
			}
			if invInput.ContractorRate < uint(minRate) || invInput.ContractorRate > uint(maxRate) {
				return www.UserError{
					ErrorCode: cms.ErrorStatusInvoiceInvalidRate,
				}
			}

			// Validate line items
			if len(invInput.LineItems) < 1 {
				return www.UserError{
					ErrorCode: cms.ErrorStatusInvoiceRequireLineItems,
				}
			}
			for _, lineInput := range invInput.LineItems {
				domain := formatInvoiceField(lineInput.Domain)
				if !validateInvoiceField(domain) {
					return www.UserError{
						ErrorCode: cms.ErrorStatusMalformedDomain,
					}
				}
				subdomain := formatInvoiceField(lineInput.Subdomain)
				if !validateInvoiceField(subdomain) {
					return www.UserError{
						ErrorCode: cms.ErrorStatusMalformedSubdomain,
					}
				}

				description := formatInvoiceField(lineInput.Description)
				if !validateInvoiceField(description) {
					return www.UserError{
						ErrorCode: cms.ErrorStatusMalformedDescription,
					}
				}

				piToken := formatInvoiceField(lineInput.ProposalToken)
				if piToken != "" && !validateInvoiceField(piToken) {
					return www.UserError{
						ErrorCode: cms.ErrorStatusMalformedProposalToken,
					}
				}

				switch lineInput.Type {
				case cms.LineItemTypeLabor:
					if lineInput.Expenses != 0 {
						return www.UserError{
							ErrorCode: cms.ErrorStatusInvalidLaborExpense,
						}
					}
					if lineInput.SubRate != 0 {
						return www.UserError{
							ErrorCode: cms.ErrorStatusInvoiceInvalidRate,
						}
					}
					if lineInput.SubUserID != "" {
						return www.UserError{
							ErrorCode: cms.ErrorStatusInvalidSubUserIDLineItem,
						}
					}
				case cms.LineItemTypeExpense:
					fallthrough
				case cms.LineItemTypeMisc:
					if lineInput.Labor != 0 {
						return www.UserError{
							ErrorCode: cms.ErrorStatusInvalidLaborExpense,
						}
					}
				case cms.LineItemTypeSubHours:
					if u.ContractorType != int(cms.ContractorTypeSupervisor) {
						return www.UserError{
							ErrorCode: cms.ErrorStatusInvalidTypeSubHoursLineItem,
						}
					}
					if lineInput.SubUserID == "" {
						return www.UserError{
							ErrorCode: cms.ErrorStatusMissingSubUserIDLineItem,
						}
					}
					subUser, err := p.getCMSUserByIDRaw(lineInput.SubUserID)
					if err != nil {
						return err
					}
					found := false
					for _, superUserIds := range subUser.SupervisorUserIDs {
						if superUserIds.String() == u.ID.String() {
							found = true
							break
						}
					}
					if !found {
						return www.UserError{
							ErrorCode: cms.ErrorStatusInvalidSubUserIDLineItem,
						}
					}
					if lineInput.Labor == 0 {
						return www.UserError{
							ErrorCode: cms.ErrorStatusInvalidLaborExpense,
						}
					}
					if lineInput.SubRate < uint(minRate) || lineInput.SubRate > uint(maxRate) {
						return www.UserError{
							ErrorCode: cms.ErrorStatusInvoiceInvalidRate,
						}
					}
				default:
					return www.UserError{
						ErrorCode: cms.ErrorStatusInvalidLineItemType,
					}
				}
			}
		}
	}

	// verify duplicate file names
	if len(ni.Files) > 1 {
		var repeated []string
		for name, count := range filenames {
			if count > 1 {
				repeated = append(repeated, name)
			}
		}
		if len(repeated) > 0 {
			return www.UserError{
				ErrorCode:    www.ErrorStatusProposalDuplicateFilenames,
				ErrorContext: repeated,
			}
		}
	}

	// we expect one index file
	if numInvoiceFiles == 0 {
		return www.UserError{
			ErrorCode:    www.ErrorStatusProposalMissingFiles,
			ErrorContext: []string{www.PolicyIndexFilename},
		}
	}

	if numCSVs > www.PolicyMaxMDs {
		return www.UserError{
			ErrorCode: www.ErrorStatusMaxMDsExceededPolicy,
		}
	}

	if numImages > cms.PolicyMaxImages {
		return www.UserError{
			ErrorCode: www.ErrorStatusMaxImagesExceededPolicy,
		}
	}

	if csvExceedsMaxSize {
		return www.UserError{
			ErrorCode: www.ErrorStatusMaxMDSizeExceededPolicy,
		}
	}

	if imageExceedsMaxSize {
		return www.UserError{
			ErrorCode: www.ErrorStatusMaxImageSizeExceededPolicy,
		}
	}

	// Note that we need validate the string representation of the merkle
	files := convertPiFilesFromWWW(ni.Files)
	mr, err := wwwutil.MerkleRoot(files, nil)
	if err != nil {
		return err
	}
	if !pk.VerifyMessage([]byte(mr), sig) {
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidSignature,
		}
	}

	return nil
}

func filterDomainInvoice(inv *cms.InvoiceRecord) cms.InvoiceRecord {
	inv.Files = nil
	inv.Input.ContractorContact = ""
	inv.Input.ContractorLocation = ""
	inv.Input.ContractorName = ""
	inv.Input.ContractorRate = 0

	for i, li := range inv.Input.LineItems {
		li.Expenses = 0
		li.SubRate = 0
		inv.Input.LineItems[i] = li
	}

	return *inv
}

// processInvoiceDetails fetches a specific proposal version from the invoice
// db and returns it.
func (p *politeiawww) processInvoiceDetails(invDetails cms.InvoiceDetails, u *user.User) (*cms.InvoiceDetailsReply, error) {
	log.Tracef("processInvoiceDetails")

	requestingUser, err := p.getCMSUserByIDRaw(u.ID.String())
	if err != nil {
		return nil, err
	}

	// Version is an optional query param. Fetch latest version
	// when query param is not specified.
	var invRec *cms.InvoiceRecord
	if invDetails.Version == "" {
		invRec, err = p.getInvoice(invDetails.Token)
	} else {
		invRec, err = p.getInvoiceVersion(invDetails.Token, invDetails.Version)
	}
	if err != nil {
		return nil, err
	}

	invoiceUser, err := p.getCMSUserByIDRaw(invRec.UserID)
	if err != nil {
		return nil, err
	}

	// Check to make sure the user is either an admin or shares the domain
	// as the invoice creator (which will then be filtered).
	if !u.Admin && (invoiceUser.Domain != requestingUser.Domain) {
		err := www.UserError{
			ErrorCode: www.ErrorStatusUserActionNotAllowed,
		}
		return nil, err
	}

	// Calculate the payout from the invoice record
	dbInv := convertInvoiceRecordToDatabaseInvoice(invRec)
	var reply cms.InvoiceDetailsReply
	if u.Admin || dbInv.UserID == u.ID.String() {
		payout, err := calculatePayout(*dbInv)
		if err != nil {
			return nil, err
		}

		payout.Username = u.Username

		// Setup reply
		reply.Invoice = *invRec
		reply.Payout = payout

	} else {
		reply.Invoice = filterDomainInvoice(invRec)
	}
	return &reply, nil
}

// processSetInvoiceStatus updates the status of the specified invoice.
func (p *politeiawww) processSetInvoiceStatus(ctx context.Context, sis cms.SetInvoiceStatus, u *user.User) (*cms.SetInvoiceStatusReply, error) {
	log.Tracef("processSetInvoiceStatus")

	invRec, err := p.getInvoice(sis.Token)
	if err != nil {
		return nil, err
	}

	// Ensure the provided public key is the user's active key.
	if sis.PublicKey != u.PublicKey() {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidSigningKey,
		}
	}

	// Validate signature
	msg := fmt.Sprintf("%v%v%v%v", sis.Token, invRec.Version,
		sis.Status, sis.Reason)
	err = validateSignature(sis.PublicKey, sis.Signature, msg)
	if err != nil {
		return nil, err
	}

	dbInvoice, err := p.cmsDB.InvoiceByToken(sis.Token)
	if err != nil {
		if errors.Is(err, database.ErrInvoiceNotFound) {
			err = www.UserError{
				ErrorCode: cms.ErrorStatusInvoiceNotFound,
			}
		}
		return nil, err
	}
	err = validateStatusTransition(dbInvoice.Status, sis.Status, sis.Reason)
	if err != nil {
		return nil, err
	}

	// Create the change record.
	c := mdstream.InvoiceStatusChange{
		Version:        mdstream.VersionInvoiceStatusChange,
		AdminPublicKey: u.PublicKey(),
		Timestamp:      time.Now().Unix(),
		NewStatus:      sis.Status,
		Reason:         sis.Reason,
	}
	blob, err := mdstream.EncodeInvoiceStatusChange(c)
	if err != nil {
		return nil, err
	}

	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	pdCommand := pd.UpdateVettedMetadata{
		Challenge: hex.EncodeToString(challenge),
		Token:     sis.Token,
		MDAppend: []pd.MetadataStream{
			{
				ID:      mdstream.IDInvoiceStatusChange,
				Payload: string(blob),
			},
		},
	}

	responseBody, err := p.makeRequest(ctx, http.MethodPost, pd.UpdateVettedMetadataRoute, pdCommand)
	if err != nil {
		return nil, err
	}

	var pdReply pd.UpdateVettedMetadataReply
	err = json.Unmarshal(responseBody, &pdReply)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal UpdateVettedMetadataReply: %v",
			err)
	}

	// Verify the UpdateVettedMetadata challenge.
	err = util.VerifyChallenge(p.cfg.Identity, challenge, pdReply.Response)
	if err != nil {
		return nil, err
	}

	// Update the database with the metadata changes.
	dbInvoice.Changes = append(dbInvoice.Changes, database.InvoiceChange{
		Timestamp:      c.Timestamp,
		AdminPublicKey: c.AdminPublicKey,
		NewStatus:      c.NewStatus,
		Reason:         c.Reason,
	})
	dbInvoice.StatusChangeReason = c.Reason
	dbInvoice.Status = c.NewStatus

	// Calculate amount of DCR needed
	payout, err := calculatePayout(*dbInvoice)
	if err != nil {
		return nil, err
	}
	payout.Username = u.Username
	// If approved then update Invoice's Payment table in DB
	if c.NewStatus == cms.InvoiceStatusApproved {
		dbInvoice.Payments = database.Payments{
			Address:      strings.TrimSpace(dbInvoice.PaymentAddress),
			TimeStarted:  time.Now().Unix(),
			Status:       cms.PaymentStatusWatching,
			AmountNeeded: int64(payout.DCRTotal),
		}
	}

	err = p.cmsDB.UpdateInvoice(dbInvoice)
	if err != nil {
		return nil, err
	}

	if dbInvoice.Status == cms.InvoiceStatusApproved ||
		dbInvoice.Status == cms.InvoiceStatusRejected ||
		dbInvoice.Status == cms.InvoiceStatusDisputed {
		invoiceUser, err := p.db.UserGetByUsername(invRec.Username)
		if err != nil {
			return nil, fmt.Errorf("failed to get user by username %v %v",
				invRec.Username, err)
		}
		// If approved and successfully entered into DB, start watcher for address
		if c.NewStatus == cms.InvoiceStatusApproved {
			p.addWatchAddress(dbInvoice.PaymentAddress)
		}

		// Emit event notification for invoice status update
		p.eventManager.emit(eventInvoiceStatusUpdate,
			dataInvoiceStatusUpdate{
				token: dbInvoice.Token,
				email: invoiceUser.Email,
			})
	}

	dbInvoice.Username = invRec.Username
	// Return the reply.

	dbRec, err := convertDatabaseInvoiceToInvoiceRecord(*dbInvoice)
	if err != nil {
		return nil, err
	}

	sisr := cms.SetInvoiceStatusReply{
		Invoice: dbRec,
	}
	return &sisr, nil
}

func validateStatusTransition(
	oldStatus cms.InvoiceStatusT,
	newStatus cms.InvoiceStatusT,
	reason string,
) error {
	validStatuses, ok := validStatusTransitions[oldStatus]
	if !ok {
		log.Debugf("status not supported: %v", oldStatus)
		return www.UserError{
			ErrorCode: cms.ErrorStatusInvalidInvoiceStatusTransition,
		}
	}

	if !statusInSlice(validStatuses, newStatus) {
		return www.UserError{
			ErrorCode: cms.ErrorStatusInvalidInvoiceStatusTransition,
		}
	}

	if newStatus == cms.InvoiceStatusRejected && reason == "" {
		return www.UserError{
			ErrorCode: cms.ErrorStatusReasonNotProvided,
		}
	}

	return nil
}

func statusInSlice(arr []cms.InvoiceStatusT, status cms.InvoiceStatusT) bool {
	for _, s := range arr {
		if status == s {
			return true
		}
	}

	return false
}

// processEditInvoice attempts to edit a proposal on politeiad.
func (p *politeiawww) processEditInvoice(ctx context.Context, ei cms.EditInvoice, u *user.User) (*cms.EditInvoiceReply, error) {
	log.Tracef("processEditInvoice %v", ei.Token)

	invRec, err := p.getInvoice(ei.Token)
	if err != nil {
		return nil, err
	}

	if invRec.Status == cms.InvoiceStatusPaid || invRec.Status == cms.InvoiceStatusApproved ||
		invRec.Status == cms.InvoiceStatusRejected {
		return nil, www.UserError{
			ErrorCode: cms.ErrorStatusWrongInvoiceStatus,
		}
	}
	// Ensure user is the invoice author
	if invRec.UserID != u.ID.String() {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusUserNotAuthor,
		}
	}

	// Make sure that the edit being submitted is different than the current invoice.
	// So check the Files to see if the digests are different at all.
	if len(ei.Files) == len(invRec.Files) {
		sameFiles := true
		for i, recFile := range invRec.Files {
			if recFile.Digest != ei.Files[i].Digest {
				sameFiles = false
			}
		}
		if sameFiles {
			return nil, www.UserError{
				ErrorCode: cms.ErrorStatusInvoiceDuplicate,
			}
		}
	}

	cmsUser, err := p.getCMSUserByIDRaw(u.ID.String())
	if err != nil {
		return nil, err
	}
	// Validate invoice. Convert it to cms.NewInvoice so that
	// we can reuse the function validateProposal.
	ni := cms.NewInvoice{
		Files:     ei.Files,
		PublicKey: ei.PublicKey,
		Signature: ei.Signature,
	}
	err = p.validateInvoice(ni, cmsUser)
	if err != nil {
		return nil, err
	}

	// Check to see that the month/year of the editted invoice is the same as
	// the previous record.
	month, year := getInvoiceMonthYear(ei.Files)
	if month != invRec.Input.Month || year != invRec.Input.Year {
		return nil, www.UserError{
			ErrorCode: cms.ErrorStatusInvalidInvoiceEditMonthYear,
		}
	}

	// Dupe address check.
	invInput, err := parseInvoiceInput(ei.Files)
	if err != nil {
		return nil, err
	}

	invoiceAddress, err := p.cmsDB.InvoicesByAddress(invInput.PaymentAddress)
	if err != nil {
		return nil, www.UserError{
			ErrorCode: cms.ErrorStatusInvalidPaymentAddress,
		}
	}

	// Only disregard any duplicate hits to InvoicesByAddress if it's not the
	// current invoice being edited.
	for _, v := range invoiceAddress {
		if v.Token != ei.Token {
			return nil, www.UserError{
				ErrorCode: cms.ErrorStatusDuplicatePaymentAddress,
			}
		}
	}

	m := mdstream.InvoiceGeneral{
		Version:   mdstream.VersionInvoiceGeneral,
		Timestamp: time.Now().Unix(),
		PublicKey: ei.PublicKey,
		Signature: ei.Signature,
	}
	md, err := mdstream.EncodeInvoiceGeneral(m)
	if err != nil {
		return nil, err
	}

	mds := []pd.MetadataStream{{
		ID:      mdstream.IDInvoiceGeneral,
		Payload: string(md),
	}}

	// Check if any files need to be deleted
	var delFiles []string
	for _, v := range invRec.Files {
		found := false
		for _, c := range ei.Files {
			if v.Name == c.Name {
				found = true
			}
		}
		if !found {
			delFiles = append(delFiles, v.Name)
		}
	}

	// Setup politeiad request
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	e := pd.UpdateRecord{
		Token:       ei.Token,
		Challenge:   hex.EncodeToString(challenge),
		MDOverwrite: mds,
		FilesAdd:    convertPDFilesFromWWW(ei.Files),
		FilesDel:    delFiles,
	}

	// Send politeiad request
	responseBody, err := p.makeRequest(ctx, http.MethodPost, pd.UpdateVettedRoute, e)
	if err != nil {
		return nil, err
	}

	// Handle response
	var pdReply pd.UpdateRecordReply
	err = json.Unmarshal(responseBody, &pdReply)
	if err != nil {
		return nil, fmt.Errorf("Unmarshal UpdateUnvettedReply: %v", err)
	}

	err = util.VerifyChallenge(p.cfg.Identity, challenge, pdReply.Response)
	if err != nil {
		return nil, err
	}

	// Create the change record.
	c := mdstream.InvoiceStatusChange{
		Version:        mdstream.VersionInvoiceStatusChange,
		AdminPublicKey: u.PublicKey(),
		Timestamp:      time.Now().Unix(),
		NewStatus:      cms.InvoiceStatusUpdated,
	}
	blob, err := mdstream.EncodeInvoiceStatusChange(c)
	if err != nil {
		return nil, err
	}

	challenge, err = util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	pdCommand := pd.UpdateVettedMetadata{
		Challenge: hex.EncodeToString(challenge),
		Token:     ei.Token,
		MDAppend: []pd.MetadataStream{
			{
				ID:      mdstream.IDInvoiceStatusChange,
				Payload: string(blob),
			},
		},
	}

	var updateMetaReply pd.UpdateVettedMetadataReply
	responseBody, err = p.makeRequest(ctx, http.MethodPost,
		pd.UpdateVettedMetadataRoute, pdCommand)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(responseBody, &updateMetaReply)
	if err != nil {
		return nil, fmt.Errorf("Could not unmarshal UpdateVettedMetadataReply: %v",
			err)
	}

	// Verify the UpdateVettedMetadata challenge.
	err = util.VerifyChallenge(p.cfg.Identity, challenge, updateMetaReply.Response)
	if err != nil {
		return nil, err
	}

	// Remove all existing line items for that invoice.  They will all get added
	// back on the update below.
	err = p.cmsDB.RemoveInvoiceLineItems(invRec.CensorshipRecord.Token)
	if err != nil {
		return nil, err
	}

	// Update the cmsdb
	dbInvoice, err := convertRecordToDatabaseInvoice(pd.Record{
		Files:            convertPDFilesFromWWW(ei.Files),
		Metadata:         mds,
		CensorshipRecord: convertPDCensorFromWWW(invRec.CensorshipRecord),
		Version:          invRec.Version,
	})
	if err != nil {
		return nil, err
	}

	dbInvoice.UserID = u.ID.String()
	dbInvoice.Status = cms.InvoiceStatusUpdated

	err = p.cmsDB.UpdateInvoice(dbInvoice)
	if err != nil {
		return nil, err
	}

	// Get updated invoice from the database
	inv, err := p.getInvoice(dbInvoice.Token)
	if err != nil {
		log.Errorf("processEditInvoice: getInvoice %v: %v",
			dbInvoice.Token, err)
	}

	return &cms.EditInvoiceReply{
		Invoice: *inv,
	}, nil
}

// processGeneratePayouts looks for all approved invoices and uses the provided
// exchange rate to generate a list of addresses and amounts for an admin to
// process payments.
func (p *politeiawww) processGeneratePayouts(gp cms.GeneratePayouts, u *user.User) (*cms.GeneratePayoutsReply, error) {
	log.Tracef("processGeneratePayouts")

	dbInvs, err := p.cmsDB.InvoicesByStatus(int(cms.InvoiceStatusApproved))
	if err != nil {
		return nil, err
	}

	reply := &cms.GeneratePayoutsReply{}
	payouts := make([]cms.Payout, 0, len(dbInvs))
	for _, inv := range dbInvs {
		payout, err := calculatePayout(inv)
		if err != nil {
			return nil, err
		}
		payout.Username = u.Username
		payouts = append(payouts, payout)
	}
	sort.Slice(payouts, func(i, j int) bool {
		return payouts[i].ApprovedTime > payouts[j].ApprovedTime
	})
	reply.Payouts = payouts
	return reply, err
}

// getInvoice gets the most recent verions of the given invoice from the db
// then fills in any missing user fields before returning the invoice record.
func (p *politeiawww) getInvoice(token string) (*cms.InvoiceRecord, error) {
	// Get invoice from db
	r, err := p.cmsDB.InvoiceByToken(token)
	if err != nil {
		return nil, err
	}
	i, err := convertDatabaseInvoiceToInvoiceRecord(*r)
	if err != nil {
		return nil, err
	}
	// Fill in userID and username fields
	u, err := p.db.UserGetByPubKey(i.PublicKey)
	if err != nil {
		log.Errorf("getInvoice: getUserByPubKey: token:%v "+
			"pubKey:%v err:%v", token, i.PublicKey, err)
	} else {
		i.UserID = u.ID.String()
		i.Username = u.Username
	}

	return &i, nil
}

// getInvoiceVersion gets a specific version of an invoice from the db.
func (p *politeiawww) getInvoiceVersion(token, version string) (*cms.InvoiceRecord, error) {
	log.Tracef("getInvoiceVersion: %v %v", token, version)

	r, err := p.cmsDB.InvoiceByTokenVersion(token, version)
	if err != nil {
		return nil, err
	}

	i, err := convertDatabaseInvoiceToInvoiceRecord(*r)
	if err != nil {
		return nil, err
	}

	// Fill in userID and username fields
	u, err := p.db.UserGetByPubKey(i.PublicKey)
	if err != nil {
		log.Errorf("getInvoice: getUserByPubKey: token:%v "+
			"pubKey:%v err:%v", token, i.PublicKey, err)
	} else {
		i.UserID = u.ID.String()
		i.Username = u.Username
	}

	return &i, nil
}

// processUserInvoices fetches all invoices that are currently stored in the
// cmsdb for the logged in user.
func (p *politeiawww) processUserInvoices(user *user.User) (*cms.UserInvoicesReply, error) {
	log.Tracef("processUserInvoices")

	dbInvs, err := p.cmsDB.InvoicesByUserID(user.ID.String())
	if err != nil {
		return nil, err
	}

	invRecs := make([]cms.InvoiceRecord, 0, len(dbInvs))
	for _, v := range dbInvs {
		inv, err := p.getInvoice(v.Token)
		if err != nil {
			return nil, err
		}
		invRecs = append(invRecs, *inv)
	}

	// Setup reply
	reply := cms.UserInvoicesReply{
		Invoices: invRecs,
	}
	return &reply, nil
}

// processAdminUserInvoices fetches all invoices that are currently stored in the
// cmsdb for the logged in user.
func (p *politeiawww) processAdminUserInvoices(aui cms.AdminUserInvoices) (*cms.AdminUserInvoicesReply, error) {
	log.Tracef("processAdminUserInvoices")

	dbInvs, err := p.cmsDB.InvoicesByUserID(aui.UserID)
	if err != nil {
		return nil, err
	}

	invRecs := make([]cms.InvoiceRecord, 0, len(dbInvs))
	for _, v := range dbInvs {
		inv, err := p.getInvoice(v.Token)
		if err != nil {
			return nil, err
		}
		invRecs = append(invRecs, *inv)
	}

	// Setup reply
	reply := cms.AdminUserInvoicesReply{
		Invoices: invRecs,
	}
	return &reply, nil
}

// processInvoices fetches all invoices that are currently stored in the
// cmsdb for an administrator, based on request fields (month/year,
// starttime/endtime, userid and/or status).
func (p *politeiawww) processInvoices(ai cms.Invoices, u *user.User) (*cms.UserInvoicesReply, error) {
	log.Tracef("processInvoices")

	requestingUser, err := p.getCMSUserByIDRaw(u.ID.String())
	if err != nil {
		return nil, err
	}

	// Ensure that the user is authorized to view domain invoices.
	if _, ok := validDomainInvoiceViewingContractorType[cms.ContractorTypeT(
		requestingUser.ContractorType)]; !ok && !u.Admin {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusUserActionNotAllowed,
		}
	}

	// Make sure month AND year are set, if any.
	if (ai.Month == 0 && ai.Year != 0) || (ai.Month != 0 && ai.Year == 0) {
		return nil, www.UserError{
			ErrorCode: cms.ErrorStatusInvalidMonthYearRequest,
		}
	}

	// Make sure month and year are sensible inputs
	if ai.Month < 0 || ai.Month > 12 {
		return nil, www.UserError{
			ErrorCode: cms.ErrorStatusInvalidMonthYearRequest,
		}
	}

	// Only accept year inputs for years +/- some constant from the current year.
	const acceptableYearRange = 2
	if ai.Year != 0 && (ai.Year < uint16(time.Now().Year()-acceptableYearRange) ||
		ai.Year > uint16(time.Now().Year()+acceptableYearRange)) {
		return nil, www.UserError{
			ErrorCode: cms.ErrorStatusInvalidMonthYearRequest,
		}
	}

	// Make sure if month and year populated that start and end ARE NOT
	if (ai.Month != 0 && ai.Year != 0) && (ai.StartTime != 0 && ai.EndTime != 0) {
		return nil, www.UserError{
			ErrorCode: cms.ErrorStatusInvalidMonthYearRequest,
		}
	}

	var dbInvs []database.Invoice
	switch {
	case (ai.Month != 0 && ai.Year != 0) && ai.Status != 0:
		dbInvs, err = p.cmsDB.InvoicesByMonthYearStatus(ai.Month, ai.Year, int(ai.Status))
		if err != nil {
			return nil, err
		}
	case (ai.Month != 0 && ai.Year != 0) && ai.Status == 0:
		dbInvs, err = p.cmsDB.InvoicesByMonthYear(ai.Month, ai.Year)
		if err != nil {
			return nil, err
		}
	case (ai.StartTime != 0 && ai.EndTime != 0) && ai.Status == 0:
		dbInvs, err = p.cmsDB.InvoicesByDateRange(ai.StartTime, ai.EndTime)
		if err != nil {
			return nil, err
		}
	case (ai.Month == 0 && ai.Year == 0) && ai.Status != 0:
		dbInvs, err = p.cmsDB.InvoicesByStatus(int(ai.Status))
		if err != nil {
			return nil, err
		}
	case (ai.StartTime != 0 && ai.EndTime != 0) && ai.Status != 0:
		dbInvs, err = p.cmsDB.InvoicesByDateRangeStatus(ai.StartTime,
			ai.EndTime, int(ai.Status))
		if err != nil {
			return nil, err
		}
	default:
		dbInvs, err = p.cmsDB.InvoicesAll()
		if err != nil {
			return nil, err
		}
	}

	// Sort returned invoices by time submitted
	sort.Slice(dbInvs, func(a, b int) bool {
		return dbInvs[a].Timestamp < dbInvs[b].Timestamp
	})

	invRecs := make([]cms.InvoiceRecord, 0, len(dbInvs))
	for _, v := range dbInvs {
		// Only return up to max page size if start time and end time are
		// provided.
		if (ai.StartTime != 0 && ai.EndTime != 0) &&
			len(invRecs) > cms.InvoiceListPageSize {
			break
		}

		invoiceUser, err := p.getCMSUserByIDRaw(v.UserID)
		if err != nil {
			return nil, err
		}

		// Skip invoice if requesting user is not an admin && they don't
		// share the same domain as the invoice user.
		// Also skip invoice if the provided user id does not match the
		// invoices' userid.
		if (!u.Admin && invoiceUser.Domain != requestingUser.Domain) ||
			(ai.UserID != "" && ai.UserID != v.UserID) {
			continue
		}

		inv, err := convertDatabaseInvoiceToInvoiceRecord(v)
		if err != nil {
			return nil, err
		}
		invUser, err := p.db.UserGetByPubKey(inv.PublicKey)
		if err != nil {
			log.Errorf("getInvoice: getUserByPubKey: token:%v "+
				"pubKey:%v err:%v", v.Token, inv.PublicKey, err)
		} else {
			inv.Username = invUser.Username
		}

		// If the user is not an admin AND not the invoice owner
		// filter out the information for domain viewing an only allow to see
		// invoices that are less than 6 months old.

		if !u.Admin && inv.UserID != u.ID.String() {
			date := time.Date(int(inv.Input.Year), time.Month(inv.Input.Month), 0, 0, 0, 0, 0, time.UTC)

			// Skip if month/year of invoice is BEFORE the current time minus
			// the domain invoice limit duration.
			if date.Before(time.Now().Add(-1 * domainInvoiceLimit)) {
				continue
			}

			inv = filterDomainInvoice(&inv)
		}
		invRecs = append(invRecs, inv)
	}

	// Setup reply
	reply := cms.UserInvoicesReply{
		Invoices: invRecs,
	}
	return &reply, nil
}

// processNewCommentInvoice sends a new comment decred plugin command to politeaid
// then fetches the new comment from the cache and returns it.
func (p *politeiawww) processNewCommentInvoice(ctx context.Context, nc www.NewComment, u *user.User) (*www.NewCommentReply, error) {
	log.Tracef("processNewComment: %v %v", nc.Token, u.ID)

	ir, err := p.getInvoice(nc.Token)
	if err != nil {
		if errors.Is(err, cmsdatabase.ErrInvoiceNotFound) {
			err = www.UserError{
				ErrorCode: cms.ErrorStatusInvoiceNotFound,
			}
		}
		return nil, err
	}

	// Check to make sure the user is either an admin or the
	// author of the invoice.
	if !u.Admin && (ir.Username != u.Username) {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusUserActionNotAllowed,
		}
	}

	// Ensure the public key is the user's active key
	if nc.PublicKey != u.PublicKey() {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidSigningKey,
		}
	}

	// Validate signature
	msg := nc.Token + nc.ParentID + nc.Comment
	err = validateSignature(nc.PublicKey, nc.Signature, msg)
	if err != nil {
		return nil, err
	}

	// Validate comment
	err = validateNewComment(nc)
	if err != nil {
		return nil, err
	}

	// Check to make sure that invoice isn't already approved or paid.
	if ir.Status == cms.InvoiceStatusApproved || ir.Status == cms.InvoiceStatusPaid {
		return nil, www.UserError{
			ErrorCode: cms.ErrorStatusWrongInvoiceStatus,
		}
	}

	// Setup plugin command
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	dnc := convertNewCommentToDecredPlugin(nc)
	payload, err := decredplugin.EncodeNewComment(dnc)
	if err != nil {
		return nil, err
	}

	pc := pd.PluginCommand{
		Challenge: hex.EncodeToString(challenge),
		ID:        decredplugin.ID,
		Command:   decredplugin.CmdNewComment,
		CommandID: decredplugin.CmdNewComment,
		Payload:   string(payload),
	}

	// Send polieiad request
	responseBody, err := p.makeRequest(ctx, http.MethodPost,
		pd.PluginCommandRoute, pc)
	if err != nil {
		return nil, err
	}

	// Handle response
	var reply pd.PluginCommandReply
	err = json.Unmarshal(responseBody, &reply)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal "+
			"PluginCommandReply: %v", err)
	}

	err = util.VerifyChallenge(p.cfg.Identity, challenge, reply.Response)
	if err != nil {
		return nil, err
	}

	ncr, err := decredplugin.DecodeNewCommentReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}

	// Get comment
	comments, err := p.getInvoiceComments(ctx, nc.Token)
	if err != nil {
		return nil, fmt.Errorf("getComment: %v", err)
	}
	var c www.Comment
	for _, v := range comments {
		if v.CommentID == ncr.CommentID {
			c = v
			break
		}
	}

	if u.Admin {
		invoiceUser, err := p.db.UserGetByUsername(ir.Username)
		if err != nil {
			return nil, fmt.Errorf("failed to get user by username %v %v",
				ir.Username, err)
		}
		// Emit event notification for a invoice comment
		p.eventManager.emit(eventInvoiceComment,
			dataInvoiceComment{
				token: nc.Token,
				email: invoiceUser.Email,
			})
	}
	return &www.NewCommentReply{
		Comment: c,
	}, nil
}

// processCommentsGet returns all comments for a given proposal. If the user is
// logged in the user's last access time for the given comments will also be
// returned.
func (p *politeiawww) processInvoiceComments(ctx context.Context, token string, u *user.User) (*www.GetCommentsReply, error) {
	log.Tracef("ProcessCommentGet: %v", token)

	ir, err := p.getInvoice(token)
	if err != nil {
		if errors.Is(err, database.ErrInvoiceNotFound) {
			err = www.UserError{
				ErrorCode: cms.ErrorStatusInvoiceNotFound,
			}
		}
		return nil, err
	}

	// Check to make sure the user is either an admin or the
	// invoice author.
	if !u.Admin && (ir.Username != u.Username) {
		err := www.UserError{
			ErrorCode: www.ErrorStatusUserActionNotAllowed,
		}
		return nil, err
	}

	// Fetch proposal comments from cache
	c, err := p.getInvoiceComments(ctx, token)
	if err != nil {
		return nil, err
	}

	// Get the last time the user accessed these comments. This is
	// a public route so a user may not exist.
	var accessTime int64
	if u != nil {
		if u.ProposalCommentsAccessTimes == nil {
			u.ProposalCommentsAccessTimes = make(map[string]int64)
		}
		accessTime = u.ProposalCommentsAccessTimes[token]
		u.ProposalCommentsAccessTimes[token] = time.Now().Unix()
		err = p.db.UserUpdate(*u)
		if err != nil {
			return nil, err
		}
	}

	return &www.GetCommentsReply{
		Comments:   c,
		AccessTime: accessTime,
	}, nil
}

func (p *politeiawww) getInvoiceComments(ctx context.Context, token string) ([]www.Comment, error) {
	log.Tracef("getInvoiceComments: %v", token)

	dc, err := p.decredGetComments(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("decredGetComments: %v", err)
	}

	// Convert comments and fill in author info.
	comments := make([]www.Comment, 0, len(dc))
	for _, v := range dc {
		c := convertCommentFromDecred(v)
		u, err := p.db.UserGetByPubKey(c.PublicKey)
		if err != nil {
			log.Errorf("getInvoiceComments: UserGetByPubKey: "+
				"token:%v commentID:%v pubKey:%v err:%v",
				token, c.CommentID, c.PublicKey, err)
		} else {
			c.UserID = u.ID.String()
			c.Username = u.Username
		}
		comments = append(comments, c)
	}

	return comments, nil
}

// processPayInvoices looks for all approved invoices and then goes about
// changing their statuses' to paid.
func (p *politeiawww) processPayInvoices(ctx context.Context, u *user.User) (*cms.PayInvoicesReply, error) {
	log.Tracef("processPayInvoices")

	dbInvs, err := p.cmsDB.InvoicesByStatus(int(cms.InvoiceStatusApproved))
	if err != nil {
		return nil, err
	}

	reply := &cms.PayInvoicesReply{}
	for _, inv := range dbInvs {
		// Create the change record.
		c := mdstream.InvoiceStatusChange{
			Version:        mdstream.VersionInvoiceStatusChange,
			AdminPublicKey: u.PublicKey(),
			Timestamp:      time.Now().Unix(),
			NewStatus:      cms.InvoiceStatusPaid,
		}
		blob, err := mdstream.EncodeInvoiceStatusChange(c)
		if err != nil {
			return nil, err
		}

		challenge, err := util.Random(pd.ChallengeSize)
		if err != nil {
			return nil, err
		}

		pdCommand := pd.UpdateVettedMetadata{
			Challenge: hex.EncodeToString(challenge),
			Token:     inv.Token,
			MDAppend: []pd.MetadataStream{
				{
					ID:      mdstream.IDInvoiceStatusChange,
					Payload: string(blob),
				},
			},
		}

		responseBody, err := p.makeRequest(ctx, http.MethodPost,
			pd.UpdateVettedMetadataRoute, pdCommand)
		if err != nil {
			return nil, err
		}

		var pdReply pd.UpdateVettedMetadataReply
		err = json.Unmarshal(responseBody, &pdReply)
		if err != nil {
			return nil,
				fmt.Errorf("Could not unmarshal UpdateVettedMetadataReply: %v",
					err)
		}

		// Verify the UpdateVettedMetadata challenge.
		err = util.VerifyChallenge(p.cfg.Identity, challenge, pdReply.Response)
		if err != nil {
			return nil, err
		}

		// Update the database with the metadata changes.
		inv.Changes = append(inv.Changes, database.InvoiceChange{
			Timestamp:      c.Timestamp,
			AdminPublicKey: c.AdminPublicKey,
			NewStatus:      c.NewStatus,
			Reason:         c.Reason,
		})
		inv.StatusChangeReason = c.Reason
		inv.Status = c.NewStatus

		err = p.cmsDB.UpdateInvoice(&inv)
		if err != nil {
			return nil, err
		}
	}
	return reply, err
}

// processInvoicePayouts looks for all paid invoices within the given start and end dates.
func (p *politeiawww) processInvoicePayouts(lip cms.InvoicePayouts) (*cms.InvoicePayoutsReply, error) {
	reply := &cms.InvoicePayoutsReply{}

	// check for valid dates
	if lip.StartTime > lip.EndTime {
		return nil, www.UserError{
			ErrorCode: cms.ErrorStatusInvalidDatesRequested,
		}
	}
	dbInvs, err := p.cmsDB.InvoicesByDateRangeStatus(lip.StartTime, lip.EndTime,
		int(cms.InvoiceStatusPaid))
	if err != nil {
		return nil, err
	}
	invoices := make([]cms.InvoiceRecord, 0, len(dbInvs))
	for _, inv := range dbInvs {
		invRec, err := convertDatabaseInvoiceToInvoiceRecord(inv)
		if err != nil {
			return nil, err
		}

		invoices = append(invoices, invRec)
	}
	reply.Invoices = invoices
	return reply, nil
}

// processProposalBilling ensures that the request user is either an admin or
// listed as an owner of the requested proposal.
func (p *politeiawww) processProposalBilling(pb cms.ProposalBilling, u *user.User) (*cms.ProposalBillingReply, error) {
	reply := &cms.ProposalBillingReply{}

	cmsUser, err := p.getCMSUserByID(u.ID.String())
	if err != nil {
		return nil, err
	}

	// Check to see if the user currently listed as owning the proposal
	propOwned := false
	for _, prop := range cmsUser.ProposalsOwned {
		if prop == pb.Token {
			propOwned = true
		}
	}
	// If it's not owned and it's not an admin requesting return an error.
	if !cmsUser.Admin && !propOwned {
		err := www.UserError{
			ErrorCode: www.ErrorStatusUserActionNotAllowed,
		}
		return nil, err
	}

	invoices, err := p.cmsDB.InvoicesByLineItemsProposalToken(pb.Token)
	if err != nil {
		return nil, www.UserError{
			ErrorCode: cms.ErrorStatusInvoiceNotFound,
		}
	}
	propBilling := make([]cms.ProposalLineItems, 0, len(invoices))
	for _, inv := range invoices {
		// All invoices should have only 1 line item returned from that function
		if len(inv.LineItems) > 1 {
			continue
		}
		lineItem := convertDatabaseInvoiceToProposalLineItems(inv)
		u, err := p.db.UserGetByPubKey(inv.PublicKey)
		if err != nil {
			log.Errorf("processProposalBilling: getUserByPubKey: token:%v "+
				"pubKey:%v err:%v", pb.Token, inv.PublicKey, err)
		} else {
			lineItem.Username = u.Username
		}
		propBilling = append(propBilling, lineItem)
	}
	reply.BilledLineItems = propBilling
	return reply, nil
}

// getInvoiceMonthYear will return the first invoice.json month/year that is
// found, otherwise 0, 0 in the event of any error.
func getInvoiceMonthYear(files []www.File) (uint, uint) {
	for _, v := range files {
		if v.Name != invoiceFile {
			continue
		}
		data, err := base64.StdEncoding.DecodeString(v.Payload)
		if err != nil {
			return 0, 0
		}

		var invInput cms.InvoiceInput
		if err := json.Unmarshal(data, &invInput); err != nil {
			return 0, 0
		}
		return invInput.Month, invInput.Year
	}
	return 0, 0
}

func calculatePayout(inv database.Invoice) (cms.Payout, error) {
	payout := cms.Payout{}
	var err error
	var totalLaborMinutes uint
	var totalExpenses uint
	var totalSubContractorLabor uint
	for _, lineItem := range inv.LineItems {
		switch lineItem.Type {
		case cms.LineItemTypeLabor:
			totalLaborMinutes += lineItem.Labor
		case cms.LineItemTypeSubHours:
			// If SubContractor line item calculate them per line item and total
			// them up.
			totalSubContractorLabor += lineItem.Labor *
				lineItem.ContractorRate / 60
		case cms.LineItemTypeExpense, cms.LineItemTypeMisc:
			totalExpenses += lineItem.Expenses
		}
	}

	payout.LaborTotal = totalLaborMinutes * inv.ContractorRate / 60
	// Add in subcontractor line items to total for payout.
	payout.LaborTotal += totalSubContractorLabor

	payout.ContractorRate = inv.ContractorRate
	payout.ExpenseTotal = totalExpenses

	payout.Address = inv.PaymentAddress
	payout.Token = inv.Token
	payout.ContractorName = inv.ContractorName

	payout.Month = inv.Month
	payout.Year = inv.Year
	payout.Total = payout.LaborTotal + payout.ExpenseTotal
	if inv.ExchangeRate > 0 {
		payout.DCRTotal, err = dcrutil.NewAmount(float64(payout.Total) /
			float64(inv.ExchangeRate))
		if err != nil {
			log.Errorf("calculatePayout %v: NewAmount: %v",
				inv.Token, err)
		}
	}

	payout.ExchangeRate = inv.ExchangeRate

	// Range through invoice's documented status changes to find the
	// time in which the invoice was approved.
	for _, change := range inv.Changes {
		if change.NewStatus == cms.InvoiceStatusApproved {
			payout.ApprovedTime = change.Timestamp
			break
		}
	}

	return payout, nil
}

func parseInvoiceInput(files []www.File) (*cms.InvoiceInput, error) {
	data, err := base64.StdEncoding.DecodeString(files[0].Payload)
	if err != nil {
		return nil, err
	}

	// Check to see if the data can be parsed properly into InvoiceInput
	// struct.
	var invInput cms.InvoiceInput
	if err := json.Unmarshal(data, &invInput); err != nil {
		return nil, www.UserError{
			ErrorCode: cms.ErrorStatusMalformedInvoiceFile,
		}
	}
	return &invInput, nil
}

func (p *politeiawww) processProposalBillingSummary(pbs cms.ProposalBillingSummary) (*cms.ProposalBillingSummaryReply, error) {
	reply := &cms.ProposalBillingSummaryReply{}

	data, err := p.makeProposalsRequest(http.MethodGet, www.RouteTokenInventory, nil)
	if err != nil {
		return nil, err
	}

	var tvr www.TokenInventoryReply
	err = json.Unmarshal(data, &tvr)
	if err != nil {
		return nil, err
	}

	approvedProposals := tvr.Approved

	approvedProposalDetails := make([]www.ProposalRecord, 0, len(approvedProposals))
	if len(approvedProposals) > 0 {
		startOffset := 0
		endOffset := www.ProposalListPageSize
		if endOffset > len(approvedProposals) {
			endOffset = len(approvedProposals)
		}
		for i := endOffset; i <= len(approvedProposals); {
			// Go fetch proposal information to get name/title.
			bp := &www.BatchProposals{
				Tokens: approvedProposals[startOffset:i],
			}

			data, err := p.makeProposalsRequest(http.MethodPost, www.RouteBatchProposals, bp)
			if err != nil {
				return nil, err
			}

			var bpr www.BatchProposalsReply
			err = json.Unmarshal(data, &bpr)
			if err != nil {
				return nil, err
			}
			approvedProposalDetails = append(approvedProposalDetails, bpr.Proposals...)

			startOffset = i
			i += www.ProposalListPageSize
			if i > len(approvedProposals) {
				i = len(approvedProposals)
			}
			if i == startOffset {
				break
			}
		}
	}

	count := pbs.Count
	if count > cms.ProposalBillingListPageSize {
		count = cms.ProposalBillingListPageSize
	}

	proposalInvoices := make(map[string][]database.Invoice, len(approvedProposals))
	for i, prop := range approvedProposals {
		if i < pbs.Offset {
			continue
		}
		propInvoices, err := p.cmsDB.InvoicesByLineItemsProposalToken(prop)
		if err != nil {
			return nil, err
		}
		if len(propInvoices) > 0 {
			proposalInvoices[prop] = propInvoices
		} else {
			proposalInvoices[prop] = make([]database.Invoice, 0)
		}

		if count != 0 && len(proposalInvoices) >= count {
			break
		}
	}

	spendingSummaries := make([]cms.ProposalSpending, 0, len(proposalInvoices))
	for prop, invoices := range proposalInvoices {
		spendingSummary := cms.ProposalSpending{}
		spendingSummary.Token = prop

		totalSpent := int64(0)
		for _, dbInv := range invoices {
			payout, err := calculatePayout(dbInv)
			if err != nil {
				return nil, err
			}
			totalSpent += int64(payout.Total)
		}
		// Look across approved proposals batch reply for proposal name.
		for _, propDetails := range approvedProposalDetails {
			if propDetails.CensorshipRecord.Token == prop {
				spendingSummary.Title = propDetails.Name
				break
			}
		}
		spendingSummary.TotalBilled = totalSpent
		spendingSummaries = append(spendingSummaries, spendingSummary)
	}

	reply.Proposals = spendingSummaries

	return reply, nil
}

func (p *politeiawww) processProposalBillingDetails(pbd cms.ProposalBillingDetails) (*cms.ProposalBillingDetailsReply, error) {
	reply := &cms.ProposalBillingDetailsReply{}

	propInvoices, err := p.cmsDB.InvoicesByLineItemsProposalToken(pbd.Token)
	if err != nil {
		return nil, err
	}

	spendingSummary := cms.ProposalSpending{}
	spendingSummary.Token = pbd.Token

	invRecs := make([]cms.InvoiceRecord, 0, len(propInvoices))
	totalSpent := int64(0)
	for _, dbInv := range propInvoices {
		u, err := p.db.UserGetByPubKey(dbInv.PublicKey)
		if err != nil {
			log.Errorf("getUserByPubKey: token:%v "+
				"pubKey:%v err:%v", dbInv.PublicKey, err)
		} else {
			dbInv.Username = u.Username
		}
		payout, err := calculatePayout(dbInv)
		if err != nil {
			return nil, err
		}
		totalSpent += int64(payout.Total)
		invRec, err := convertDatabaseInvoiceToInvoiceRecord(dbInv)
		if err != nil {
			return nil, err
		}
		invRecs = append(invRecs, invRec)
	}

	data, err := p.makeProposalsRequest(http.MethodGet, "/proposals/"+pbd.Token, nil)
	if err != nil {
		return nil, err
	}

	var pdr www.ProposalDetailsReply
	err = json.Unmarshal(data, &pdr)
	if err != nil {
		return nil, err
	}

	spendingSummary.Title = pdr.Proposal.Name
	spendingSummary.Invoices = invRecs
	spendingSummary.TotalBilled = totalSpent

	reply.Details = spendingSummary
	return reply, nil
}
