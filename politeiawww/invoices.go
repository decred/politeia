// Copyright (c) 2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/decred/dcrd/dcrutil"
	"github.com/decred/dcrtime/merkle"
	pd "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/cache"
	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	database "github.com/decred/politeia/politeiawww/cmsdatabase"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/decred/politeia/util"
)

const (
	// invoiceFile contains the file name of the invoice file
	invoiceFile = "invoice.json"

	// politeiad invoice record metadata streams
	mdStreamInvoiceGeneral       = 3 // General invoice metadata
	mdStreamInvoiceStatusChanges = 4 // Invoice status changes

	// Metadata stream struct versions
	backendInvoiceMetadataVersion     = 1
	backendInvoiceStatusChangeVersion = 1
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
		// Rejected invoices may only be updated to approved or updated.
		cms.InvoiceStatusRejected: {
			cms.InvoiceStatusApproved,
			cms.InvoiceStatusUpdated,
		},
		// Updated invoices may only be updated to approved, rejected or disputed.
		cms.InvoiceStatusUpdated: {
			cms.InvoiceStatusApproved,
			cms.InvoiceStatusRejected,
			cms.InvoiceStatusDisputed,
		},
	}
	validInvoiceField = regexp.MustCompile(createInvoiceFieldRegex())
	validName         = regexp.MustCompile(createNameLocationRegex())
	validLocation     = regexp.MustCompile(createNameLocationRegex())
)

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
	if len(field) > cms.PolicyMaxInvoiceFieldLength {
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

// createNameLocationRegex generates a regex based on the policy supplied valid
// characters in a user name.
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
	buf.WriteString("]{0,")
	buf.WriteString(strconv.Itoa(cms.PolicyMaxInvoiceFieldLength) + "}$")

	return buf.String()
}

// createUsernameRegex generates a regex based on the policy supplied valid
// characters in a user's name or location.
func createNameLocationRegex() string {
	var buf bytes.Buffer
	buf.WriteString("^[")

	for _, supportedChar := range cms.PolicyNameLocationSupportedChars {
		if len(supportedChar) > 1 {
			buf.WriteString(supportedChar)
		} else {
			buf.WriteString(`\` + supportedChar)
		}
	}
	buf.WriteString("]{")
	buf.WriteString(strconv.Itoa(www.PolicyMinUsernameLength) + ",")
	buf.WriteString(strconv.Itoa(www.PolicyMaxUsernameLength) + "}$")

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
			ErrorCode: www.ErrorStatusMalformedName,
		}
	}

	if !validName.MatchString(name) {
		log.Debugf("Name not valid: %s %s", name, validName.String())
		return www.UserError{
			ErrorCode: www.ErrorStatusMalformedName,
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
			ErrorCode: www.ErrorStatusMalformedLocation,
		}
	}

	if !validLocation.MatchString(location) {
		log.Debugf("Location not valid: %s %s", location, validLocation.String())
		return www.UserError{
			ErrorCode: www.ErrorStatusMalformedLocation,
		}
	}

	return nil
}

// processNewInvoice tries to submit a new invoice to politeiad.
func (p *politeiawww) processNewInvoice(ni cms.NewInvoice, u *user.User) (*cms.NewInvoiceReply, error) {
	log.Tracef("processNewInvoice")

	err := p.validateInvoice(ni, u)
	if err != nil {
		return nil, err
	}
	// Check to make sure user has not yet submitted an invoice for the month/year
	dbInvs, err := p.cmsDB.InvoicesByUserID(u.ID.String())
	if err != nil {
		return nil, err
	}

	for _, dbInv := range dbInvs {
		if dbInv.Month == ni.Month && dbInv.Year == ni.Year {
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusMultipleInvoiceMonthYear,
			}
		}
	}

	m := backendInvoiceMetadata{
		Version:   backendInvoiceMetadataVersion,
		Timestamp: time.Now().Unix(),
		PublicKey: ni.PublicKey,
		Signature: ni.Signature,
	}
	md, err := encodeBackendInvoiceMetadata(m)
	if err != nil {
		return nil, err
	}

	sc := backendInvoiceStatusChange{
		Version:   backendInvoiceStatusChangeVersion,
		Timestamp: time.Now().Unix(),
		NewStatus: cms.InvoiceStatusNew,
	}
	scb, err := encodeBackendInvoiceStatusChange(sc)
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
				ID:      mdStreamInvoiceGeneral,
				Payload: string(md),
			},
			{
				ID:      mdStreamInvoiceStatusChanges,
				Payload: string(scb),
			},
		},
		Files: convertPropFilesFromWWW(ni.Files),
	}

	// Handle test case
	if p.test {
		tokenBytes, err := util.Random(pd.TokenSize)
		if err != nil {
			return nil, err
		}

		testReply := pd.NewRecordReply{
			CensorshipRecord: pd.CensorshipRecord{
				Token: hex.EncodeToString(tokenBytes),
			},
		}

		return &cms.NewInvoiceReply{
			CensorshipRecord: convertPropCensorFromPD(testReply.CensorshipRecord),
		}, nil
	}

	// Send the newrecord politeiad request
	responseBody, err := p.makeRequest(http.MethodPost,
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
	// An admin signature is not included for this reason.
	c := MDStreamChanges{
		Version:   VersionMDStreamChanges,
		Timestamp: time.Now().Unix(),
		NewStatus: pd.RecordStatusPublic,
	}
	blob, err := encodeMDStreamChanges(c)
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
				ID:      mdStreamChanges,
				Payload: string(blob),
			},
		},
	}

	// Send SetUnvettedStatus request to politeiad
	responseBody, err = p.makeRequest(http.MethodPost,
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
	cr := convertPropCensorFromPD(pdReply.CensorshipRecord)

	// Fire off new proposal event
	p.fireEvent(EventTypeProposalSubmitted,
		EventDataProposalSubmitted{
			CensorshipRecord: &cr,
			User:             u,
		},
	)

	return &cms.NewInvoiceReply{
		CensorshipRecord: cr,
	}, nil
}

func (p *politeiawww) validateInvoice(ni cms.NewInvoice, u *user.User) error {
	log.Tracef("validateInvoice")

	// Obtain signature
	sig, err := util.ConvertSignature(ni.Signature)
	if err != nil {
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidSignature,
		}
	}

	// Verify public key
	id, err := checkPublicKey(u, ni.PublicKey)
	if err != nil {
		return err
	}

	pk, err := identity.PublicIdentityFromBytes(id[:])
	if err != nil {
		return err
	}

	// Check for at least 1 markdown file with a non-empty payload.
	if len(ni.Files) == 0 || ni.Files[0].Payload == "" {
		fmt.Println(ni.Files[0].Payload)
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
		hashes                                 []*[sha256.Size]byte
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
					ErrorCode: www.ErrorStatusMalformedInvoiceFile,
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
					ErrorCode: www.ErrorStatusInvalidInvoiceMonthYear,
				}
			}

			// Validate Payment Address
			addr, err := dcrutil.DecodeAddress(strings.TrimSpace(invInput.PaymentAddress))
			if err != nil {
				return www.UserError{
					ErrorCode: www.ErrorStatusInvalidPaymentAddress,
				}
			}
			if !addr.IsForNet(activeNetParams.Params) {
				return www.UserError{
					ErrorCode: www.ErrorStatusInvalidPaymentAddress,
				}
			}

			// Verify that the submitted monthly average matches the value
			// was calculated server side.
			monthAvg, err := p.cmsDB.ExchangeRate(int(invInput.Month),
				int(invInput.Year))
			if err != nil {
				return www.UserError{
					ErrorCode: www.ErrorStatusInvalidExchangeRate,
				}
			}
			if monthAvg.ExchangeRate != invInput.ExchangeRate {
				return www.UserError{
					ErrorCode: www.ErrorStatusInvalidExchangeRate,
				}
			}

			// Validate provided contractor name
			if invInput.ContractorName == "" {
				return www.UserError{
					ErrorCode: www.ErrorStatusInvoiceMissingName,
				}
			}
			name := formatInvoiceField(invInput.ContractorName)
			if !validateInvoiceField(name) {
				return www.UserError{
					ErrorCode: www.ErrorStatusMalformedName,
				}
			}

			// Validate provided contractor location
			if invInput.ContractorLocation == "" {
				return www.UserError{
					ErrorCode: www.ErrorStatusInvoiceMissingLocation,
				}
			}
			location := formatInvoiceField(invInput.ContractorLocation)
			if !validateInvoiceField(location) {
				return www.UserError{
					ErrorCode: www.ErrorStatusMalformedLocation,
				}
			}

			// Validate provided contractor email/contact
			if invInput.ContractorContact == "" {
				return www.UserError{
					ErrorCode: www.ErrorStatusInvoiceMissingContact,
				}
			}
			contact := formatInvoiceField(invInput.ContractorContact)
			if !validateInvoiceField(contact) {
				return www.UserError{
					ErrorCode: www.ErrorStatusInvoiceMalformedContact,
				}
			}

			// Validate hourly rate
			if invInput.ContractorRate == 0 {
				return www.UserError{
					ErrorCode: www.ErrorStatusInvoiceMissingRate,
				}
			}
			// Do basic sanity check for contractor rate, since it's in cents
			// some users may enter in the
			minRate := 500   // 5 USD (in cents)
			maxRate := 50000 // 500 USD (in cents)
			if invInput.ContractorRate < uint(minRate) || invInput.ContractorRate > uint(maxRate) {
				fmt.Println(invInput.ContractorRate)
				return www.UserError{
					ErrorCode: www.ErrorStatusInvoiceInvalidRate,
				}
			}

			// Validate line items
			if len(invInput.LineItems) < 1 {
				return www.UserError{
					ErrorCode: www.ErrorStatusInvoiceRequireLineItems,
				}
			}
			for _, lineInput := range invInput.LineItems {
				domain := formatInvoiceField(lineInput.Domain)
				if !validateInvoiceField(domain) {
					return www.UserError{
						ErrorCode: www.ErrorStatusMalformedDomain,
					}
				}
				subdomain := formatInvoiceField(lineInput.Subdomain)
				if !validateInvoiceField(subdomain) {
					return www.UserError{
						ErrorCode: www.ErrorStatusMalformedSubdomain,
					}
				}

				description := formatInvoiceField(lineInput.Description)
				if !validateInvoiceField(description) {
					return www.UserError{
						ErrorCode: www.ErrorStatusMalformedDescription,
					}
				}

				piToken := formatInvoiceField(lineInput.ProposalToken)
				if !validateInvoiceField(piToken) {
					return www.UserError{
						ErrorCode: www.ErrorStatusMalformedProposalToken,
					}
				}

				switch lineInput.Type {
				case cms.LineItemTypeLabor:
					if lineInput.Expenses != 0 {
						return www.UserError{
							ErrorCode: www.ErrorStatusMalformedLineItem,
						}
					}
				case cms.LineItemTypeExpense:
				case cms.LineItemTypeMisc:
					if lineInput.Labor != 0 {
						return www.UserError{
							ErrorCode: www.ErrorStatusMalformedLineItem,
						}
					}
				}
			}
		}

		// Append digest to array for merkle root calculation
		digest := util.Digest(data)
		var d [sha256.Size]byte
		copy(d[:], digest)
		hashes = append(hashes, &d)
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
			ErrorContext: []string{indexFile},
		}
	}

	if numCSVs > www.PolicyMaxMDs {
		return www.UserError{
			ErrorCode: www.ErrorStatusMaxMDsExceededPolicy,
		}
	}

	if numImages > www.PolicyMaxImages {
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
	mr := merkle.Root(hashes)
	if !pk.VerifyMessage([]byte(hex.EncodeToString(mr[:])), sig) {
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidSignature,
		}
	}

	return nil
}

// processInvoiceDetails fetches a specific proposal version from the records
// cache and returns it.
func (p *politeiawww) processInvoiceDetails(invDetails cms.InvoiceDetails, user *user.User) (*cms.InvoiceDetailsReply, error) {
	log.Tracef("processInvoiceDetails")

	invRec, err := p.getInvoice(invDetails.Token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: www.ErrorStatusInvoiceNotFound,
			}
		}
		return nil, err
	}

	// Setup reply
	reply := cms.InvoiceDetailsReply{
		Invoice: *invRec,
	}

	return &reply, nil
}

// processSetInvoiceStatus updates the status of the specified invoice.
func (p *politeiawww) processSetInvoiceStatus(sis cms.SetInvoiceStatus,
	u *user.User) (*cms.SetInvoiceStatusReply, error) {
	log.Tracef("processSetInvoiceStatus")

	invRec, err := p.getInvoice(sis.Token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: www.ErrorStatusInvoiceNotFound,
			}
		}
		return nil, err
	}

	err = checkPublicKeyAndSignature(u, sis.PublicKey, sis.Signature,
		sis.Token, invRec.Version, strconv.FormatUint(uint64(sis.Status), 10),
		sis.Reason)
	if err != nil {
		return nil, err
	}

	dbInvoice, err := p.cmsDB.InvoiceByToken(sis.Token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: www.ErrorStatusInvoiceNotFound,
			}
		}
		return nil, err
	}
	err = validateStatusTransition(dbInvoice.Status, sis.Status, sis.Reason)
	if err != nil {
		return nil, err
	}

	// Create the change record.
	c := backendInvoiceStatusChange{
		Version:        backendInvoiceStatusChangeVersion,
		AdminPublicKey: u.PublicKey(),
		Timestamp:      time.Now().Unix(),
		NewStatus:      sis.Status,
		Reason:         sis.Reason,
	}
	blob, err := encodeBackendInvoiceStatusChange(c)
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
				ID:      mdStreamInvoiceStatusChanges,
				Payload: string(blob),
			},
		},
	}

	responseBody, err := p.makeRequest(http.MethodPost, pd.UpdateVettedMetadataRoute, pdCommand)
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

	err = p.cmsDB.UpdateInvoice(dbInvoice)
	if err != nil {
		return nil, err
	}
	/*
		p.fireEvent(EventTypeInvoiceStatusChange,
			EventDataInvoiceStatusChange{
				Invoice:   dbInvoice,
				AdminUser: user,
			},
		)
	*/
	// Return the reply.
	sisr := cms.SetInvoiceStatusReply{
		Invoice: *convertDatabaseInvoiceToInvoiceRecord(*dbInvoice),
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
		log.Errorf("status not supported: %v", oldStatus)
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidInvoiceStatusTransition,
		}
	}

	if !statusInSlice(validStatuses, newStatus) {
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidInvoiceStatusTransition,
		}
	}

	if newStatus == cms.InvoiceStatusRejected && reason == "" {
		return www.UserError{
			ErrorCode: www.ErrorStatusReasonNotProvided,
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
func (p *politeiawww) processEditInvoice(ei cms.EditInvoice, u *user.User) (*cms.EditInvoiceReply, error) {
	log.Tracef("processEditInvoice %v", ei.Token)

	invRec, err := p.getInvoice(ei.Token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: www.ErrorStatusInvoiceNotFound,
			}
		}
		return nil, err
	}

	if invRec.Status == cms.InvoiceStatusPaid || invRec.Status == cms.InvoiceStatusApproved ||
		invRec.Status == cms.InvoiceStatusRejected {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusWrongInvoiceStatus,
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
				ErrorCode: www.ErrorStatusInvoiceDuplicate,
			}
		}
	}

	// Validate invoice. Convert it to cms.NewInvoice so that
	// we can reuse the function validateProposal.
	ni := cms.NewInvoice{
		Files:     ei.Files,
		PublicKey: ei.PublicKey,
		Signature: ei.Signature,
	}
	err = p.validateInvoice(ni, u)
	if err != nil {
		return nil, err
	}

	m := backendInvoiceMetadata{
		Version:   backendInvoiceMetadataVersion,
		Timestamp: time.Now().Unix(),
		PublicKey: ei.PublicKey,
		Signature: ei.Signature,
	}
	md, err := encodeBackendInvoiceMetadata(m)
	if err != nil {
		return nil, err
	}

	mds := []pd.MetadataStream{{
		ID:      mdStreamInvoiceGeneral,
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
		FilesAdd:    convertPropFilesFromWWW(ei.Files),
		FilesDel:    delFiles,
	}

	// Send politeiad request
	responseBody, err := p.makeRequest(http.MethodPost, pd.UpdateVettedRoute, e)
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
	c := backendInvoiceStatusChange{
		Version:        backendInvoiceStatusChangeVersion,
		AdminPublicKey: u.PublicKey(),
		Timestamp:      time.Now().Unix(),
		NewStatus:      cms.InvoiceStatusUpdated,
	}
	blob, err := encodeBackendInvoiceStatusChange(c)
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
				ID:      mdStreamInvoiceStatusChanges,
				Payload: string(blob),
			},
		},
	}

	var updateMetaReply pd.UpdateVettedMetadataReply
	responseBody, err = p.makeRequest(http.MethodPost,
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

	// Update the cmsdb
	dbInvoice, err := convertRecordToDatabaseInvoice(pd.Record{
		Files:            convertPropFilesFromWWW(ei.Files),
		Metadata:         mds,
		CensorshipRecord: convertInvoiceCensorFromWWW(invRec.CensorshipRecord),
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

	// Get updated invoice from the cache
	inv, err := p.getInvoice(dbInvoice.Token)
	if err != nil {
		log.Errorf("processEditInvoice: getInvoice %v: %v",
			dbInvoice.Token, err)
	}

	/*
		// Fire off edit proposal event
		p.fireEvent(EventTypeProposalEdited,
			EventDataProposalEdited{
				Proposal: updatedProp,
			},
		)
	*/
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
		payout := cms.Payout{}

		var totalLaborMinutes uint
		var totalExpenses uint
		for _, lineItem := range inv.LineItems {
			switch lineItem.Type {
			case cms.LineItemTypeLabor:
				totalLaborMinutes += lineItem.Labor
			case cms.LineItemTypeExpense, cms.LineItemTypeMisc:
				totalExpenses += lineItem.Expenses
			}
		}

		payout.LaborTotal = totalLaborMinutes * inv.ContractorRate / 60
		payout.ContractorRate = inv.ContractorRate
		payout.ExpenseTotal = totalExpenses

		payout.Address = inv.PaymentAddress
		payout.Token = inv.Token
		payout.ContractorName = inv.ContractorName

		payout.Username = p.getUsernameById(inv.UserID)
		payout.Month = inv.Month
		payout.Year = inv.Year
		payout.Total = payout.LaborTotal + payout.ExpenseTotal
		if inv.ExchangeRate > 0 {
			payout.DCRTotal, err = dcrutil.NewAmount(float64(payout.Total) /
				float64(inv.ExchangeRate))
		}
		payout.ExchangeRate = inv.ExchangeRate

		payouts = append(payouts, payout)
	}
	reply.Payouts = payouts
	return reply, err
}

// getInvoice gets the most recent verions of the given invoice from the cache
// then fills in any missing user fields before returning the invoice record.
func (p *politeiawww) getInvoice(token string) (*cms.InvoiceRecord, error) {
	// Get invoice from cache
	r, err := p.cache.Record(token)
	if err != nil {
		return nil, err
	}
	i := convertInvoiceFromCache(*r)

	// Fill in userID and username fields
	userID, ok := p.getUserIDByPubKey(i.PublicKey)
	if !ok {
		log.Errorf("getInvoice: userID not found for "+
			"pubkey:%v token:%v", i.PublicKey, token)
	}
	i.UserID = userID
	i.Username = p.getUsernameById(userID)

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

// processAdminInvoices fetches all invoices that are currently stored in the
// cmsdb for an administrator, based on request fields (month/year and/or status).
func (p *politeiawww) processAdminInvoices(ai cms.AdminInvoices, user *user.User) (*cms.UserInvoicesReply, error) {
	log.Tracef("processAdminInvoices")

	// Make sure month AND year are set, if any.
	if (ai.Month == 0 && ai.Year != 0) || (ai.Month != 0 && ai.Year == 0) {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidMonthYearRequest,
		}
	}

	// Make sure month and year are sensible inputs
	if ai.Month < 0 || ai.Month > 12 {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidMonthYearRequest,
		}
	}

	// Only accept year inputs for years +/- some constant from the current year.
	const acceptableYearRange = 2
	if ai.Year != 0 && (ai.Year < uint16(time.Now().Year()-acceptableYearRange) ||
		ai.Year > uint16(time.Now().Year()+acceptableYearRange)) {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidMonthYearRequest,
		}
	}

	var dbInvs []database.Invoice
	var err error
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
	case (ai.Month == 0 && ai.Year == 0) && ai.Status != 0:
		dbInvs, err = p.cmsDB.InvoicesByStatus(int(ai.Status))
		if err != nil {
			return nil, err
		}
	default:
		dbInvs, err = p.cmsDB.InvoicesAll()
		if err != nil {
			return nil, err
		}
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

// processCommentsGet returns all comments for a given proposal. If the user is
// logged in the user's last access time for the given comments will also be
// returned.
func (p *politeiawww) processInvoiceComments(token string, u *user.User) (*www.GetCommentsReply, error) {
	log.Tracef("ProcessCommentGet: %v", token)

	ir, err := p.getInvoice(token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: www.ErrorStatusInvoiceNotFound,
			}
		}
		return nil, err
	}

	_, ok := p.userPubkeys[ir.PublicKey]

	// Check to make sure the user is either an admin or the creator of the invoice
	if !u.Admin && !ok {
		err := www.UserError{
			ErrorCode: www.ErrorStatusUserActionNotAllowed,
		}
		return nil, err
	}

	// Fetch proposal comments from cache
	c, err := p.getInvoiceComments(token)
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

func (p *politeiawww) getInvoiceComments(token string) ([]www.Comment, error) {
	log.Tracef("getInvoiceComments: %v", token)

	dc, err := p.decredGetComments(token)
	if err != nil {
		return nil, fmt.Errorf("decredGetComments: %v", err)
	}

	p.RLock()
	defer p.RUnlock()

	// Fill in politeiawww data. Cache usernames to reduce
	// database lookups.
	comments := make([]www.Comment, 0, len(dc))
	usernames := make(map[string]string, len(dc)) // [userID]username
	for _, v := range dc {
		c := convertCommentFromDecred(v)

		// Fill in author info
		userID, ok := p.userPubkeys[c.PublicKey]
		if !ok {
			log.Errorf("getInvoiceComments: userID lookup failed "+
				"pubkey:%v token:%v comment:%v", c.PublicKey,
				c.Token, c.CommentID)
		}
		u, ok := usernames[userID]
		if !ok && userID != "" {
			u = p.getUsernameById(userID)
			usernames[userID] = u
		}
		c.UserID = userID
		c.Username = u

		comments = append(comments, c)
	}

	return comments, nil
}

// backendInvoiceMetadata represents the general metadata for an invoice and is
// stored in the metadata stream mdStreamInvoiceGeneral in politeiad.
type backendInvoiceMetadata struct {
	Version   uint64 `json:"version"`   // Version of the struct
	Timestamp int64  `json:"timestamp"` // Last update of invoice
	PublicKey string `json:"publickey"` // Key used for signature
	Signature string `json:"signature"` // Signature of merkle root
}

// backendInvoiceStatusChange represents an invoice status change and is stored
// in the metadata stream mdStreamInvoiceStatusChanges in politeiad.
type backendInvoiceStatusChange struct {
	Version        uint               `json:"version"`        // Version of the struct
	AdminPublicKey string             `json:"adminpublickey"` // Identity of the administrator
	NewStatus      cms.InvoiceStatusT `json:"newstatus"`      // Status
	Reason         string             `json:"reason"`         // Reason
	Timestamp      int64              `json:"timestamp"`      // Timestamp of the change
}

// encodeBackendInvoiceMetadata encodes a backendInvoiceMetadata into a JSON
// byte slice.
func encodeBackendInvoiceMetadata(md backendInvoiceMetadata) ([]byte, error) {
	b, err := json.Marshal(md)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// decodeBackendInvoiceMetadata decodes a JSON byte slice into a
// backendInvoiceMetadata.
func decodeBackendInvoiceMetadata(payload []byte) (*backendInvoiceMetadata, error) {
	var md backendInvoiceMetadata

	err := json.Unmarshal(payload, &md)
	if err != nil {
		return nil, err
	}

	return &md, nil
}

// encodeBackendInvoiceStatusChange encodes a backendInvoiceStatusChange into a
// JSON byte slice.
func encodeBackendInvoiceStatusChange(md backendInvoiceStatusChange) ([]byte, error) {
	b, err := json.Marshal(md)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// decodeBackendInvoiceStatusChange decodes a JSON byte slice into a slice of
// backendInvoiceStatusChanges.
func decodeBackendInvoiceStatusChanges(payload []byte) ([]backendInvoiceStatusChange, error) {
	var md []backendInvoiceStatusChange

	d := json.NewDecoder(strings.NewReader(string(payload)))
	for {
		var m backendInvoiceStatusChange
		err := d.Decode(&m)
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}

		md = append(md, m)
	}

	return md, nil
}
