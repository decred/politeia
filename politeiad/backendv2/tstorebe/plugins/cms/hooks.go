// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cms

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/decred/dcrd/dcrutil/v3"
	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/plugins/cms"
	"github.com/decred/politeia/politeiad/plugins/comments"
	"github.com/decred/politeia/politeiad/plugins/usermd"
	"github.com/decred/politeia/util"
	"github.com/pkg/errors"
)

const (
	// Accepted MIME types
	mimeTypeText     = "text/plain"
	mimeTypeTextUTF8 = "text/plain; charset=utf-8"
	mimeTypePNG      = "image/png"
)

var (
	// allowedTextFiles contains the filenames of the only text files
	// that are allowed to be submitted as part of an invoice.
	allowedTextFiles = map[string]struct{}{
		cms.FileNameIndexFile:       {},
		cms.FileNameInvoiceMetadata: {},
		// dcc.FileNameVoteMetadata: {},
	}
)

// hookNewRecordPre adds plugin specific validation onto the tstore backend
// RecordNew method.
func (c *cmsPlugin) hookNewRecordPre(payload string) error {
	var nr plugins.HookNewRecordPre
	err := json.Unmarshal([]byte(payload), &nr)
	if err != nil {
		return err
	}

	return c.invoiceFilesVerify(nr.Files)
}

// hookEditRecordPre adds plugin specific validation onto the tstore backend
// RecordEdit method.
func (c *cmsPlugin) hookEditRecordPre(payload string) error {
	var er plugins.HookEditRecord
	err := json.Unmarshal([]byte(payload), &er)
	if err != nil {
		return err
	}

	// Verify invoice files
	err = c.invoiceFilesVerify(er.Files)
	if err != nil {
		return err
	}

	return nil
}

// hookCommentNew adds cms specific validation onto the comments plugin New
// command.
func (c *cmsPlugin) hookCommentNew(token []byte, cmd, payload string) error {
	return c.commentWritesAllowed(token, cmd, payload)
}

// hookCommentDel adds cms specific validation onto the comments plugin Del
// command.
func (c *cmsPlugin) hookCommentDel(token []byte, cmd, payload string) error {
	return c.commentWritesAllowed(token, cmd, payload)
}

// hookCommentVote adds cms specific validation onto the comments plugin Vote
// command.
func (c *cmsPlugin) hookCommentVote(token []byte, cmd, payload string) error {
	// No comment voting for cms, should I remove?
	return nil
}

// hookPluginPre extends plugin write commands from other plugins with cms
// specific validation.
func (c *cmsPlugin) hookPluginPre(payload string) error {
	// Decode payload
	var hpp plugins.HookPluginPre
	err := json.Unmarshal([]byte(payload), &hpp)
	if err != nil {
		return err
	}

	// Call plugin hook
	switch hpp.PluginID {
	case comments.PluginID:
		switch hpp.Cmd {
		case comments.CmdNew:
			return c.hookCommentNew(hpp.Token, hpp.Cmd, hpp.Payload)
		case comments.CmdDel:
			return c.hookCommentDel(hpp.Token, hpp.Cmd, hpp.Payload)
		case comments.CmdVote:
			return c.hookCommentVote(hpp.Token, hpp.Cmd, hpp.Payload)
		}
	}

	return nil
}

// invoiceFieldIsValid returns whether the provided location matches the cms
// plugin invoice field regex.
func (c *cmsPlugin) invoiceFieldIsValid(field string) bool {
	return c.invoiceFieldRegexp.MatchString(field)
}

// nameIsValid returns whether the provided contractor name matches the cms
// plugin name regex.
func (c *cmsPlugin) nameIsValid(name string) bool {
	return c.nameRegexp.MatchString(name)
}

// locationIsValid returns whether the provided location matches the cms plugin
// location regex.
func (c *cmsPlugin) locationIsValid(location string) bool {
	return c.locationRegexp.MatchString(location)
}

// contactIsValid returns whether the provided contact matches the cms plugin
// contact regex.
func (c *cmsPlugin) contactIsValid(contact string) bool {
	return c.contactRegexp.MatchString(contact)
}

// invoiceDomainIsValid returns whether the provided domain is
// is a valid invoice domain.
func (p *cmsPlugin) invoiceDomainIsValid(domain string) bool {
	_, found := p.invoiceDomains[strings.ToLower(domain)]
	return found
}

// invoiceFilesVerify verifies the files adhere to all cms plugin setting
// requirements. If this hook is being executed then the files have already
// passed politeiad validation so we can assume that the file has a unique
// name, a valid base64 payload, and that the file digest and MIME type are
// correct.
func (c *cmsPlugin) invoiceFilesVerify(files []backend.File) error {
	// Sanity check
	if len(files) == 0 {
		return errors.Errorf("no files found")
	}

	// Verify file types and sizes
	var imagesCount uint32
	var csvsCount uint32
	for _, v := range files {
		payload, err := base64.StdEncoding.DecodeString(v.Payload)
		if err != nil {
			return errors.Errorf("invalid base64 %v", v.Name)
		}

		// MIME type specific validation
		switch v.MIME {
		case mimeTypeText, mimeTypeTextUTF8:
			csvsCount++
			// Verify text file is allowed
			_, ok := allowedTextFiles[v.Name]
			if !ok {
				allowed := make([]string, 0, len(allowedTextFiles))
				for name := range allowedTextFiles {
					allowed = append(allowed, name)
				}
				return backend.PluginError{
					PluginID:  cms.PluginID,
					ErrorCode: uint32(cms.ErrorCodeTextFileNameInvalid),
					ErrorContext: fmt.Sprintf("invalid text file name "+
						"%v; allowed text file names are %v",
						v.Name, strings.Join(allowed, ", ")),
				}
			}

			// Verify text file size
			if len(payload) > int(c.textFileSizeMax) {
				return backend.PluginError{
					PluginID:  cms.PluginID,
					ErrorCode: uint32(cms.ErrorCodeTextFileSizeInvalid),
					ErrorContext: fmt.Sprintf("file %v "+
						"size %v exceeds max size %v",
						v.Name, len(payload),
						c.textFileSizeMax),
				}
			}

		case mimeTypePNG:
			imagesCount++

			// Verify image file size
			if len(payload) > int(c.imageFileSizeMax) {
				return backend.PluginError{
					PluginID:  cms.PluginID,
					ErrorCode: uint32(cms.ErrorCodeImageFileSizeInvalid),
					ErrorContext: fmt.Sprintf("image %v "+
						"size %v exceeds max size %v",
						v.Name, len(payload),
						c.imageFileSizeMax),
				}
			}

		default:
			return errors.Errorf("invalid mime: %v", v.MIME)
		}
	}

	// Verify that an index file is present
	var found bool
	for _, v := range files {
		if v.Name == cms.FileNameIndexFile {
			found = true
			break
		}
	}
	if !found {
		return backend.PluginError{
			PluginID:     cms.PluginID,
			ErrorCode:    uint32(cms.ErrorCodeTextFileMissing),
			ErrorContext: cms.FileNameIndexFile,
		}
	}

	err := c.validateIndexFile(files)
	if err != nil {
		return err
	}

	// Verify image file count is acceptable
	if imagesCount > c.imageFileCountMax {
		return backend.PluginError{
			PluginID:  cms.PluginID,
			ErrorCode: uint32(cms.ErrorCodeImageFileCountInvalid),
			ErrorContext: fmt.Sprintf("got %v image files, max "+
				"is %v", imagesCount, c.imageFileCountMax),
		}
	}

	// Verify an invoice metadata has been included
	im, err := invoiceMetadataDecode(files)
	if err != nil {
		return err
	}
	if im == nil {
		return backend.PluginError{
			PluginID:     cms.PluginID,
			ErrorCode:    uint32(cms.ErrorCodeTextFileMissing),
			ErrorContext: cms.FileNameInvoiceMetadata,
		}
	}

	// Validate that the input month is a valid month
	if im.Month < 1 || im.Month > 12 {
		return backend.PluginError{
			PluginID:  cms.PluginID,
			ErrorCode: uint32(cms.ErrorStatusInvalidInvoiceMonthYear),
			ErrorContext: fmt.Sprintf("invalid invoice month %v, "+
				"needs to be between 1 and 12", im.Month),
		}

	}

	// Validate month/year to make sure the first day of the following
	// month is after the current date.  For example, if a user submits
	// an invoice for 03/2019, the first time that they could submit an
	// invoice would be approx. 12:01 AM 04/01/2019
	startOfFollowingMonth := time.Date(int(im.Year),
		time.Month(im.Month+1), 0, 0, 0, 0, 0, time.UTC)
	if startOfFollowingMonth.After(time.Now()) {
		return backend.PluginError{
			PluginID:  cms.PluginID,
			ErrorCode: uint32(cms.ErrorStatusInvalidInvoiceMonthYear),
			ErrorContext: fmt.Sprintf("invoice month/year submitted too soon "+
				"%v before %v", time.Now(), startOfFollowingMonth),
		}
	}

	// Validate Payment Address
	if im.PaymentAddress == "" {
		return backend.PluginError{
			PluginID:  cms.PluginID,
			ErrorCode: uint32(cms.ErrorStatusMissingPaymentAddress),
		}
	}
	_, err = dcrutil.DecodeAddress(strings.TrimSpace(im.PaymentAddress), c.activeNetParams)
	if err != nil {
		return backend.PluginError{
			PluginID:  cms.PluginID,
			ErrorCode: uint32(cms.ErrorStatusInvalidPaymentAddress),
		}
	}
	/*  XXX What to do here since we no longer have access to cmsdb and exchange rate information

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
	*/
	// Validate provided contractor name
	if im.ContractorName == "" {
		return backend.PluginError{
			PluginID:  cms.PluginID,
			ErrorCode: uint32(cms.ErrorStatusInvoiceMissingName),
		}
	}
	if !c.nameIsValid(im.ContractorName) {
		return backend.PluginError{
			PluginID:     cms.PluginID,
			ErrorCode:    uint32(cms.ErrorStatusMalformedName),
			ErrorContext: c.nameRegexp.String(),
		}
	}

	if !c.locationIsValid(im.ContractorLocation) {
		return backend.PluginError{
			PluginID:     cms.PluginID,
			ErrorCode:    uint32(cms.ErrorStatusMalformedLocation),
			ErrorContext: c.locationRegexp.String(),
		}
	}

	// Validate provided contractor email/contact
	if im.ContractorContact == "" {
		return backend.PluginError{
			PluginID:  cms.PluginID,
			ErrorCode: uint32(cms.ErrorStatusInvoiceMissingContact),
		}
	}
	if !c.contactIsValid(im.ContractorContact) {
		return backend.PluginError{
			PluginID:     cms.PluginID,
			ErrorCode:    uint32(cms.ErrorStatusInvoiceMalformedContact),
			ErrorContext: c.contactRegexp.String(),
		}
	}

	// Validate contractor rate
	if im.ContractorRate == 0 {
		return backend.PluginError{
			PluginID:  cms.PluginID,
			ErrorCode: uint32(cms.ErrorStatusInvoiceMissingRate),
		}
	}
	if im.ContractorRate < uint(c.contractorRateMin) || im.ContractorRate > uint(c.contractorRateMax) {
		return backend.PluginError{
			PluginID:  cms.PluginID,
			ErrorCode: uint32(cms.ErrorStatusInvoiceInvalidRate),
			ErrorContext: fmt.Sprintf("got %v rate, "+
				"must be between %v and %v", im.ContractorRate,
				c.contractorRateMin, c.contractorRateMax),
		}
	}

	return nil
}

func (c *cmsPlugin) validateIndexFile(files []backend.File) error {
	for _, v := range files {
		if v.Name != cms.FileNameIndexFile {
			continue
		}

		data, err := base64.StdEncoding.DecodeString(v.Payload)
		if err != nil {
			return backend.PluginError{
				PluginID:     cms.PluginID,
				ErrorCode:    uint32(cms.ErrorStatusMalformedInvoiceFile),
				ErrorContext: fmt.Sprintf("invoice input cannot be parsed %v ", err),
			}
		}
		if len(data) > int(cms.SettingMDSizeMax) {
			return backend.PluginError{
				PluginID:     cms.PluginID,
				ErrorCode:    uint32(cms.ErrorCodeTextFileSizeInvalid),
				ErrorContext: fmt.Sprintf("invoice input cannot be parsed %v ", err),
			}
		}

		// Check to see if the data can be parsed properly into InvoiceInput
		// struct.
		var invInput cms.InvoiceInput
		if err := json.Unmarshal([]byte(string(data)), &invInput); err != nil {
			return backend.PluginError{
				PluginID:     cms.PluginID,
				ErrorCode:    uint32(cms.ErrorStatusMalformedInvoiceFile),
				ErrorContext: fmt.Sprintf("invoice input cannot be parsed %v ", err),
			}
		}

		// Validate line items
		if len(invInput.LineItems) < 1 {
			return backend.PluginError{
				PluginID:  cms.PluginID,
				ErrorCode: uint32(cms.ErrorStatusInvoiceRequireLineItems),
			}
		}
		for _, lineInput := range invInput.LineItems {
			domain := formatLineItemField(lineInput.Domain)
			if !c.invoiceFieldIsValid(domain) {
				return backend.PluginError{
					PluginID:     cms.PluginID,
					ErrorCode:    uint32(cms.ErrorStatusMalformedDomain),
					ErrorContext: c.invoiceFieldRegexp.String(),
				}
			}
			// Validate line item domain.
			if !c.invoiceDomainIsValid(domain) {
				return backend.PluginError{
					PluginID:  cms.PluginID,
					ErrorCode: uint32(cms.ErrorCodeInvoiceDomainInvalid),
					ErrorContext: fmt.Sprintf("got %v domain, "+
						"supported domains are: %v", domain, c.invoiceDomains),
				}
			}
			subdomain := formatLineItemField(lineInput.Subdomain)
			if subdomain != "" && !c.invoiceFieldIsValid(subdomain) {
				return backend.PluginError{
					PluginID:     cms.PluginID,
					ErrorCode:    uint32(cms.ErrorStatusMalformedSubdomain),
					ErrorContext: c.invoiceFieldRegexp.String(),
				}
			}
			description := formatLineItemField(lineInput.Description)
			if !c.invoiceFieldIsValid(description) {
				return backend.PluginError{
					PluginID:     cms.PluginID,
					ErrorCode:    uint32(cms.ErrorStatusMalformedDescription),
					ErrorContext: c.invoiceFieldRegexp.String(),
				}
			}

			piToken := formatLineItemField(lineInput.ProposalToken)
			if piToken != "" && !c.invoiceFieldIsValid(piToken) {
				return backend.PluginError{
					PluginID:     cms.PluginID,
					ErrorCode:    uint32(cms.ErrorStatusMalformedProposalToken),
					ErrorContext: c.invoiceFieldRegexp.String(),
				}
			}

			switch lineInput.Type {
			case cms.LineItemTypeLabor:
				if lineInput.Expenses != 0 {
					return backend.PluginError{
						PluginID:     cms.PluginID,
						ErrorCode:    uint32(cms.ErrorStatusInvalidLaborExpense),
						ErrorContext: "no expense fields when labor type",
					}
				}
				if lineInput.SubRate != 0 {
					return backend.PluginError{
						PluginID:     cms.PluginID,
						ErrorCode:    uint32(cms.ErrorStatusInvoiceInvalidRate),
						ErrorContext: "no sub rates when labor type",
					}
				}
				if lineInput.SubUserID != "" {
					return backend.PluginError{
						PluginID:     cms.PluginID,
						ErrorCode:    uint32(cms.ErrorStatusInvalidSubUserIDLineItem),
						ErrorContext: "no sub user id when labor type",
					}
				}
			case cms.LineItemTypeExpense, cms.LineItemTypeMisc:
				if lineInput.Labor != 0 {
					return backend.PluginError{
						PluginID:     cms.PluginID,
						ErrorCode:    uint32(cms.ErrorStatusInvalidLaborExpense),
						ErrorContext: "labor cannot be populated when not labor type",
					}
				}
			case cms.LineItemTypeSubHours:
				/* What to do about contractor type checks here?
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
				*/
			default:
				return backend.PluginError{
					PluginID:     cms.PluginID,
					ErrorCode:    uint32(cms.ErrorStatusInvalidLineItemType),
					ErrorContext: fmt.Sprintf("invalid line item type %v", lineInput.Type),
				}
			}
		}
	}
	return nil
}

// comments requests all comments on a record from the comments plugin.
func (c *cmsPlugin) comments(token []byte) (*comments.GetAllReply, error) {
	reply, err := c.backend.PluginRead(token, comments.PluginID,
		comments.CmdGetAll, "")
	if err != nil {
		return nil, err
	}
	var gar comments.GetAllReply
	err = json.Unmarshal([]byte(reply), &gar)
	if err != nil {
		return nil, err
	}
	return &gar, nil
}

// isInCommentTree returns whether the leafID is part of the provided comment
// tree. A leaf is considered to be part of the tree if the leaf is a child of
// the root or the leaf references the root itself.
func isInCommentTree(rootID, leafID uint32, cs []comments.Comment) bool {
	if leafID == rootID {
		return true
	}
	// Convert comments slice to a map
	commentsMap := make(map[uint32]comments.Comment, len(cs))
	for _, c := range cs {
		commentsMap[c.CommentID] = c
	}

	// Start with the provided comment leaf and traverse the comment tree up
	// until either the provided root ID is found or we reach the tree head. The
	// tree head will have a comment ID of 0.
	current := commentsMap[leafID]
	for current.ParentID != 0 {
		// Check if next parent in the tree is the rootID.
		if current.ParentID == rootID {
			return true
		}
		leafID = current.ParentID
		current = commentsMap[leafID]
	}
	return false
}

// latestAuthorUpdate gets the latest author update on a record, if
// the record has no author update it returns nil.
func latestAuthorUpdate(token []byte, cs []comments.Comment) *comments.Comment {
	var latestAuthorUpdate comments.Comment
	for _, c := range cs {
		if c.ExtraDataHint != cms.InvoiceUpdateHint {
			continue
		}
		if c.Timestamp > latestAuthorUpdate.Timestamp {
			latestAuthorUpdate = c
		}
	}
	return &latestAuthorUpdate
}

// formatField normalizes a contractor name to lowercase without leading and
// trailing spaces.
func formatField(field string) string {
	return strings.ToLower(strings.TrimSpace(field))
}

// formatLineItemField normalizes a line item field without leading and
// trailing spaces.
func formatLineItemField(field string) string {
	return strings.TrimSpace(field)
}

// recordAuthor returns the author's userID of the record associated with
// the provided token.
func (c *cmsPlugin) recordAuthor(token []byte) (string, error) {
	reply, err := c.backend.PluginRead(token, usermd.PluginID,
		usermd.CmdAuthor, "")
	if err != nil {
		return "", err
	}
	var ar usermd.AuthorReply
	err = json.Unmarshal([]byte(reply), &ar)
	if err != nil {
		return "", err
	}
	return ar.UserID, nil
}

// isValidAuthorUpdate returns whether the given new comment is a valid author
// update.
//
// The comment must include proper invoice update metadata and the comment
// must be submitted by the invoice author for it to be considered a valid
// author update.
func (c *cmsPlugin) isValidAuthorUpdate(token []byte, n comments.New) error {
	// Get the invoice author. The invoice author
	// and the comment author must be the same user.
	recordAuthorID, err := c.recordAuthor(token)
	if err != nil {
		return err
	}
	if recordAuthorID != n.UserID {
		return backend.PluginError{
			PluginID:     cms.PluginID,
			ErrorCode:    uint32(cms.ErrorCodeCommentWriteNotAllowed),
			ErrorContext: "user is not the invoice author",
		}
	}

	// Verify extra data fields
	if n.ExtraDataHint != cms.InvoiceUpdateHint {
		return backend.PluginError{
			PluginID:  cms.PluginID,
			ErrorCode: uint32(cms.ErrorCodeExtraDataHintInvalid),
			ErrorContext: fmt.Sprintf("got %v, want %v",
				n.ExtraDataHint, cms.InvoiceUpdateHint),
		}
	}
	var pum cms.InvoiceUpdateMetadata
	err = json.Unmarshal([]byte(n.ExtraData), &pum)
	if err != nil {
		return backend.PluginError{
			PluginID:  cms.PluginID,
			ErrorCode: uint32(cms.ErrorCodeExtraDataInvalid),
		}
	}

	// Verify update title
	/*
		if !c.titleIsValid(pum.Title) {
			return backend.PluginError{
				PluginID:     cms.PluginID,
				ErrorCode:    uint32(cms.ErrorCodeTitleInvalid),
				ErrorContext: c.titleRegexp.String(),
			}
		}
	*/
	// The comment is a valid author update.
	return nil
}

// commentWritesAllowed verifies that an invoice has an invoice status that
// allows comment writes to be made to the invoice.
func (c *cmsPlugin) commentWritesAllowed(token []byte, cmd, payload string) error {
	// Get invoice status to determine whether to allow author updates
	// or not.
	var bsc *cms.InvoiceStatusChange
	bscs, err := c.invoiceStatusChanges(token)
	if err != nil {
		return err
	}
	if len(bscs) > 0 {
		// Get latest invoice status change
		bsc = &bscs[len(bscs)-1]
		// Check to see if invoice is paid or rejected.
		if bsc.Status == cms.InvoiceStatusPaid || bsc.Status == cms.InvoiceStatusRejected {
			return backend.PluginError{
				PluginID:     cms.PluginID,
				ErrorCode:    uint32(cms.ErrorCodeCommentWriteNotAllowed),
				ErrorContext: "comments are locked",
			}
		}
	}
	return nil
}

// tokenDecode returns the decoded censorship token. An error will be returned
// if the token is not a full length token.
func tokenDecode(token string) ([]byte, error) {
	return util.TokenDecode(util.TokenTypeTstore, token)
}

// invoiceMetadataDecode decodes and returns the InvoiceMetadata from the
// provided backend files. If an InvoiceMetadata is not found, nil is returned.
func invoiceMetadataDecode(files []backend.File) (*cms.InvoiceMetadata, error) {
	var propMD *cms.InvoiceMetadata
	for _, v := range files {
		if v.Name != cms.FileNameInvoiceMetadata {
			continue
		}
		b, err := base64.StdEncoding.DecodeString(v.Payload)
		if err != nil {
			return nil, err
		}
		var m cms.InvoiceMetadata
		err = json.Unmarshal(b, &m)
		if err != nil {
			return nil, err
		}
		propMD = &m
		break
	}
	return propMD, nil
}
