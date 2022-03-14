// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package records

import (
	"github.com/decred/politeia/politeiawww/legacy/user"
)

// cmsHookNewRecordpre executes the new record pre hook for cms.
//
// This function is a temporary function that will be removed once user plugins
// have been implemented.
func (r *Records) cmsHookNewRecordPre(u user.User) error {

	// Check to see if cms user status is correct for submitting invoices?
	/*
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
		// The invalid contractor types for new invoice submission
		invalidNewInvoiceContractorType = map[cms.ContractorTypeT]bool{
			cms.ContractorTypeNominee:         true,
			cms.ContractorTypeInvalid:         true,
			cms.ContractorTypeSubContractor:   true,
			cms.ContractorTypeTempDeactivated: true,
		}
	*/
	return nil
}

// cmsHookNewRecordPost executes the new record post hook for cms.
func (r *Records) cmsHookNewRecordPost(u user.User, token string) error {
	// Do some sort of cmsuserdb update for after invoice submission?
	return nil
}

// cmsHookDetailsPre executes the details pre hook for cms.
func (r *Records) cmsHookDetailsPre(u user.User, token string) error {

	// Confirm that the user is either the invoice owner or an admin

	return nil
}

// cmsHookRecordsPre executes the records pre hook for cms.
func (r *Records) cmsHookRecordsPre(u user.User, token string) error {

	// Currently only invoice owners, shared domains or admins are able to
	// see lists of records.

	// Need to figure out the best way to filter the invoices for delivery

	return nil
}

// cmsHookInvertoryPre executes the inventory pre hook for cms.
func (r *Records) cmsHookInvertoryPre(u user.User) error {

	// Currently only invoice owners, shared domains or admins are able to
	// see lists of inventory. (but needs to be scrubbed for domain folks)

	// Need to figure out the best way to filter the invoices for delivery
	return nil
}

// cmsHookInvertoryOrderedPre executes the inventory ordered pre hook for cms.
func (r *Records) cmsHookInvertoryOrderedPre(u user.User) error {

	// Currently only invoice owners, shared domains or admins are able to
	// see lists of inventory. (but needs to be scrubbed for domain folks)

	// Need to figure out the best way to filter the invoices for delivery
	return nil
}

// cmsHookUserRecordsPre executes the user records pre hook for cms.
func (r *Records) cmsHookUserRecordsPre(u user.User) error {

	// Currently only invoice owners, shared domains or admins are able to
	// see lists of inventory. (but needs to be scrubbed for domain folks)

	// Need to figure out the best way to filter the invoices for delivery
	return nil
}
