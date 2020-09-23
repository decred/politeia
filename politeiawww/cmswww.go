// Copyright (c) 2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/json"
	"net/http"

	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/util"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// handleInviteNewUser handles the invitation of a new contractor by an
// administrator for the Contractor Management System.
func (p *politeiawww) handleInviteNewUser(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleInviteNewUser")

	// Get the new user command.
	var u cms.InviteNewUser
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&u); err != nil {
		RespondWithError(w, r, 0, "handleInviteNewUser: unmarshal", www.UserError{
			ErrorCode: www.ErrorStatusInvalidInput,
		})
		return
	}

	reply, err := p.processInviteNewUser(u)
	if err != nil {
		RespondWithError(w, r, 0, "handleInviteNewUser: ProcessInviteNewUser %v", err)
		return
	}

	// Reply with the verification token.
	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleNewInvoice handles the incoming new invoice command.
func (p *politeiawww) handleNewInvoice(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleNewInvoice")

	// Get the new invoice command.
	var ni cms.NewInvoice
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&ni); err != nil {
		RespondWithError(w, r, 0, "handleNewInvoice: unmarshal", www.UserError{
			ErrorCode: www.ErrorStatusInvalidInput,
		})
		return
	}

	user, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleNewInvoice: getSessionUser %v", err)
		return
	}

	reply, err := p.processNewInvoice(ni, user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleNewInvoice: processNewInvoice %v", err)
		return
	}

	// Reply with the challenge response and censorship token.
	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleInvoiceDetails handles the incoming invoice details command. It fetches
// the complete details for an existing invoice.
func (p *politeiawww) handleInvoiceDetails(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleInvoiceDetails")

	// Get the invoice details command
	var pd cms.InvoiceDetails
	// get version from query string parameters
	err := util.ParseGetParams(r, &pd)
	if err != nil {
		RespondWithError(w, r, 0, "handleInvoiceDetails: ParseGetParams",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	// Get invoice token from path parameters
	pathParams := mux.Vars(r)
	pd.Token = pathParams["token"]

	user, err := p.getSessionUser(w, r)
	if err != nil {
		if err != errSessionNotFound {
			RespondWithError(w, r, 0,
				"handleInvoiceDetails: getSessionUser %v", err)
			return
		}
	}
	reply, err := p.processInvoiceDetails(pd, user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleInvoiceDetails: processInvoiceDetails %v", err)
		return
	}

	// Reply with the proposal details.
	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleUserInvoices handles the request to get all of the invoices from the
// currently logged in user.
func (p *politeiawww) handleUserInvoices(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleUserInvoices")

	user, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleUserInvoices: getSessionUser %v", err)
		return
	}

	reply, err := p.processUserInvoices(user)
	if err != nil {
		RespondWithError(w, r, 0, "handleUserInvoices: processUserInvoices %v", err)
		return
	}

	// Reply with the verification token.
	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleAdminUserInvoices handles the request to get all of the invoices of a
// user by an administrator for the Contractor Management System.
func (p *politeiawww) handleAdminUserInvoices(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleAdminUserInvoices")

	var aui cms.AdminUserInvoices
	// get version from query string parameters
	err := util.ParseGetParams(r, &aui)
	if err != nil {
		RespondWithError(w, r, 0, "handleAdminUserInvoices: ParseGetParams",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	_, err = uuid.Parse(aui.UserID)
	if err != nil {
		RespondWithError(w, r, 0, "handleAdminUserInvoices: ParseUint",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	reply, err := p.processAdminUserInvoices(aui)
	if err != nil {
		RespondWithError(w, r, 0, "handleAdminUserInvoices: processAdminUserInvoices %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleSetInvoiceStatus handles the incoming set invoice status command.
func (p *politeiawww) handleSetInvoiceStatus(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleSetInvoiceStatus")

	// Get set invoice command
	var sis cms.SetInvoiceStatus
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&sis); err != nil {
		RespondWithError(w, r, 0, "handleSetInvoiceStatus: unmarshal", www.UserError{
			ErrorCode: www.ErrorStatusInvalidInput,
		})
		return
	}

	user, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleSetInvoiceStatus: getSessionUser %v", err)
		return
	}

	reply, err := p.processSetInvoiceStatus(sis, user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleSetInvoiceStatus: processSetInvoiceStatus %v", err)
		return
	}

	// Reply with the challenge response and censorship token.
	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleInvoices handles the request to get all of the  of a new contractor by an
// administrator for the Contractor Management System.
func (p *politeiawww) handleInvoices(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleInvoices")
	var ai cms.Invoices
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&ai); err != nil {
		RespondWithError(w, r, 0, "handleInvoices: unmarshal", www.UserError{
			ErrorCode: www.ErrorStatusInvalidInput,
		})
		return
	}

	user, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleInvoices: getSessionUser %v", err)
		return
	}

	reply, err := p.processInvoices(ai, user)
	if err != nil {
		RespondWithError(w, r, 0, "handleInvoices: processInvoices %v", err)
		return
	}

	// Reply with the verification token.
	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleEditInvoice attempts to edit an invoice
func (p *politeiawww) handleEditInvoice(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleEditInvoice")

	// Get edit invoice command
	var ei cms.EditInvoice
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&ei); err != nil {
		RespondWithError(w, r, 0, "handleEditInvoice: unmarshal",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	user, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleEditInvoice: getSessionUser %v", err)
		return
	}

	log.Debugf("handleEditInvoice: %v", ei.Token)

	epr, err := p.processEditInvoice(ei, user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleEditInvoice: processEditInvoice %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, epr)
}

// handleGeneratePayouts handles the request to generate all of the payouts for any
// currently approved invoice.
func (p *politeiawww) handleGeneratePayouts(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleGeneratePayouts")

	// Get generate payouts command
	var gp cms.GeneratePayouts
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&gp); err != nil {
		RespondWithError(w, r, 0, "handleGeneratePayouts: unmarshal",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	user, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleGeneratePayouts: getSessionUser %v", err)
		return
	}

	reply, err := p.processGeneratePayouts(gp, user)
	if err != nil {
		RespondWithError(w, r, 0, "handleGeneratePayouts: processGeneratePayouts %v", err)
		return
	}

	// Reply with the generated payouts
	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleNewCommentInvoice handles incomming comments for invoices.
func (p *politeiawww) handleNewCommentInvoice(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleNewCommentInvoice")

	var sc www.NewComment
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&sc); err != nil {
		RespondWithError(w, r, 0, "handleNewCommentInvoice: unmarshal",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	user, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleNewCommentInvoice: getSessionUser %v", err)
		return
	}

	cr, err := p.processNewCommentInvoice(sc, user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleNewCommentInvoice: processNewCommentInvoice: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, cr)
}

// handleInvoiceComments handles batched invoice comments get.
func (p *politeiawww) handleInvoiceComments(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleInvoiceComments")

	pathParams := mux.Vars(r)
	token := pathParams["token"]

	user, err := p.getSessionUser(w, r)
	if err != nil {
		if err != errSessionNotFound {
			RespondWithError(w, r, 0,
				"handleInvoiceComments: getSessionUser %v", err)
			return
		}
	}
	gcr, err := p.processInvoiceComments(token, user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleInvoiceComments: processInvoiceComments %v", err)
		return
	}
	util.RespondWithJSON(w, http.StatusOK, gcr)
}

// handleInvoiceExchangeRate handles incoming requests for monthly exchange rate
func (p *politeiawww) handleInvoiceExchangeRate(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleInvoiceExchangeRate")

	var ier cms.InvoiceExchangeRate
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&ier); err != nil {
		RespondWithError(w, r, 0, "handleInvoiceExchangeRate: unmarshal",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	ierr, err := p.processInvoiceExchangeRate(ier)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleInvoiceExchangeRate: processNewCommentInvoice: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, ierr)
}

func (p *politeiawww) handleCMSPolicy(w http.ResponseWriter, r *http.Request) {
	// Get the policy command.
	log.Tracef("handlePolicy")
	reply := &cms.PolicyReply{
		MinPasswordLength:             www.PolicyMinPasswordLength,
		MinUsernameLength:             www.PolicyMinUsernameLength,
		MaxUsernameLength:             www.PolicyMaxUsernameLength,
		MaxImages:                     cms.PolicyMaxImages,
		MaxImageSize:                  www.PolicyMaxImageSize,
		MaxMDs:                        www.PolicyMaxMDs,
		MaxMDSize:                     www.PolicyMaxMDSize,
		ValidMIMETypes:                cms.PolicyValidMimeTypes,
		MinLineItemColLength:          cms.PolicyMinLineItemColLength,
		MaxLineItemColLength:          cms.PolicyMaxLineItemColLength,
		MaxNameLength:                 cms.PolicyMaxNameLength,
		MinNameLength:                 cms.PolicyMinNameLength,
		MaxLocationLength:             cms.PolicyMaxLocationLength,
		MinLocationLength:             cms.PolicyMinLocationLength,
		MaxContactLength:              cms.PolicyMaxContactLength,
		MinContactLength:              cms.PolicyMinContactLength,
		InvoiceFieldSupportedChars:    cms.PolicyInvoiceFieldSupportedChars,
		UsernameSupportedChars:        www.PolicyUsernameSupportedChars,
		CMSNameLocationSupportedChars: cms.PolicyCMSNameLocationSupportedChars,
		CMSContactSupportedChars:      cms.PolicyCMSContactSupportedChars,
		CMSStatementSupportedChars:    cms.PolicySponsorStatementSupportedChars,
		CMSSupportedDomains:           cms.PolicySupportedCMSDomains,
		CMSSupportedLineItemTypes:     cms.PolicyCMSSupportedLineItemTypes,
	}

	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handlePayInvoices handles the request to generate all of the payouts for any
// currently approved invoice.
func (p *politeiawww) handlePayInvoices(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handlePayInvoices")

	user, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handlePayInvoices: getSessionUser %v", err)
		return
	}

	reply, err := p.processPayInvoices(user)
	if err != nil {
		RespondWithError(w, r, 0, "handlePayInvoices: processPayInvoices %v",
			err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleEditCMSUser handles the request to edit a given user's
// additional user information.
func (p *politeiawww) handleEditCMSUser(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleEditCMSUser")

	var eu cms.EditUser
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&eu); err != nil {
		RespondWithError(w, r, 0, "handleEditCMSUser: unmarshal",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	user, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleEditCMSUser: getSessionUser %v", err)
		return
	}

	reply, err := p.processEditCMSUser(eu, user)
	if err != nil {
		RespondWithError(w, r, 0, "handleEditCMSUser: "+
			"processUpdateUserInformation %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleManageCMSUser handles the request to edit a given user's
// additional user information.
func (p *politeiawww) handleManageCMSUser(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleManageCMSUser")

	var mu cms.CMSManageUser
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&mu); err != nil {
		RespondWithError(w, r, 0, "handleManageCMSUser: unmarshal",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	reply, err := p.processManageCMSUser(mu)
	if err != nil {
		RespondWithError(w, r, 0, "handleManageCMSUser: "+
			"processManageCMSUser %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, reply)
}

func (p *politeiawww) handleCMSUserDetails(w http.ResponseWriter, r *http.Request) {
	// Add the path param to the struct.
	log.Tracef("handleCMSUserDetails")
	pathParams := mux.Vars(r)
	var ud cms.UserDetails
	ud.UserID = pathParams["userid"]

	userID, err := uuid.Parse(ud.UserID)
	if err != nil {
		RespondWithError(w, r, 0, "handleCMSUserDetails: ParseUint",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	user, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleCMSUserDetails: getSessionUser %v", err)
		return
	}

	reply, err := p.processCMSUserDetails(&ud,
		user != nil && user.ID == userID,
		user != nil && user.Admin,
	)

	if err != nil {
		RespondWithError(w, r, 0, "handleCMSUserDetails: "+
			"processCMSUserDetails %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleInvoicePayouts handles incoming requests for invoice payout information
func (p *politeiawww) handleInvoicePayouts(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleInvoicePayouts")

	var lip cms.InvoicePayouts
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&lip); err != nil {
		RespondWithError(w, r, 0, "handleInvoicePayouts: unmarshal",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	lipr, err := p.processInvoicePayouts(lip)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleInvoicePayouts: processInvoicePayouts: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, lipr)
}

func (p *politeiawww) handleNewDCC(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleNewDCC")

	var nd cms.NewDCC
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&nd); err != nil {
		RespondWithError(w, r, 0, "handleNewDCC: unmarshal",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}
	u, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleNewDCC: getSessionUser %v", err)
		return
	}

	ndr, err := p.processNewDCC(nd, u)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleNewDCC: processNewDCC: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, ndr)
}

func (p *politeiawww) handleDCCDetails(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleDCCDetails")

	var gd cms.DCCDetails
	// get version from query string parameters
	err := util.ParseGetParams(r, &gd)
	if err != nil {
		RespondWithError(w, r, 0, "handleDCCDetails: ParseGetParams",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}
	// Get dcc token from path parameters
	pathParams := mux.Vars(r)
	gd.Token = pathParams["token"]

	gdr, err := p.processDCCDetails(gd)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleDCCDetails: processDCCDetails: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, gdr)
}

func (p *politeiawww) handleGetDCCs(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleGetDCCs")

	var gds cms.GetDCCs
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&gds); err != nil {
		RespondWithError(w, r, 0, "handleGetDCCs: unmarshal",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}
	_, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleGetDCCs: getSessionUser %v", err)
		return
	}

	gdsr, err := p.processGetDCCs(gds)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleGetDCCs: processGetDCCs: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, gdsr)
}

func (p *politeiawww) handleSupportOpposeDCC(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleSupportOpposeDCC")

	var sd cms.SupportOpposeDCC
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&sd); err != nil {
		RespondWithError(w, r, 0, "handleSupportOpposeDCC: unmarshal",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}
	u, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleSupportOpposeDCC: getSessionUser %v", err)
		return
	}

	sdr, err := p.processSupportOpposeDCC(sd, u)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleSupportOpposeDCC: processSupportOpposeDCC: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, sdr)
}

// handleNewCommentDCC handles incomming comments for DCC.
func (p *politeiawww) handleNewCommentDCC(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleNewCommentDCC")

	var sc www.NewComment
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&sc); err != nil {
		RespondWithError(w, r, 0, "handleNewCommentDCC: unmarshal",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	user, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleNewCommentDCC: getSessionUser %v", err)
		return
	}

	cr, err := p.processNewCommentDCC(sc, user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleNewCommentDCC: processNewCommentDCC: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, cr)
}

// handleDCCComments handles batched comments get.
func (p *politeiawww) handleDCCComments(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleDCCComments")

	pathParams := mux.Vars(r)
	token := pathParams["token"]

	user, err := p.getSessionUser(w, r)
	if err != nil {
		if err != errSessionNotFound {
			RespondWithError(w, r, 0,
				"handleDCCComments: getSessionUser %v", err)
			return
		}
	}
	gcr, err := p.processDCCComments(token, user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleDCCComments: processDCCComments %v", err)
		return
	}
	util.RespondWithJSON(w, http.StatusOK, gcr)
}

func (p *politeiawww) handleSetDCCStatus(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleSetDCCStatus")

	var ad cms.SetDCCStatus
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&ad); err != nil {
		RespondWithError(w, r, 0, "handleSetDCCStatus: unmarshal",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}
	u, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleSetDCCStatus: getSessionUser %v", err)
		return
	}

	adr, err := p.processSetDCCStatus(ad, u)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleSetDCCStatus: processSetDCCStatus: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, adr)
}

func (p *politeiawww) handleUserSubContractors(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleUserSubContractors")

	u, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleUserSubContractors: getSessionUser %v", err)
		return
	}

	uscr, err := p.processUserSubContractors(u)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleUserSubContractors: processUserSubContractors: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, uscr)
}

func (p *politeiawww) handleProposalOwner(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleProposalOwner")

	var po cms.ProposalOwner
	err := util.ParseGetParams(r, &po)
	if err != nil {
		RespondWithError(w, r, 0, "handleProposalOwner: ParseGetParams",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}
	por, err := p.processProposalOwner(po)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleProposalOwner: processProposalOwner: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, por)
}

func (p *politeiawww) handleProposalBilling(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleProposalBilling")

	var pb cms.ProposalBilling
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&pb); err != nil {
		RespondWithError(w, r, 0, "handleProposalBilling: unmarshal",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}
	u, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleProposalBilling: getSessionUser %v", err)
		return
	}

	pbr, err := p.processProposalBilling(pb, u)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleProposalBilling: processSetDCCStatus: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, pbr)
}

func (p *politeiawww) handleCastVoteDCC(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleCastVoteDCC")

	var cv cms.CastVote
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&cv); err != nil {
		RespondWithError(w, r, 0, "handleCastVoteDCC: unmarshal", www.UserError{
			ErrorCode: www.ErrorStatusInvalidInput,
		})
		return
	}

	u, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleCastVoteDCC: getSessionUser %v", err)
		return
	}

	cvr, err := p.processCastVoteDCC(cv, u)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleCastVoteDCC: processCastVoteDCC: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, cvr)
}

func (p *politeiawww) handleVoteDetailsDCC(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleVoteDetailsDCC")

	var vd cms.VoteDetails
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&vd); err != nil {
		RespondWithError(w, r, 0, "handleVoteDetailsDCC: unmarshal", www.UserError{
			ErrorCode: www.ErrorStatusInvalidInput,
		})
		return
	}

	vdr, err := p.processVoteDetailsDCC(vd.Token)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleVoteDetailsDCC: processVoteDetailsDCC: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, vdr)
}

// handleActiveVoteDCC returns all active dccs that have an active vote.
func (p *politeiawww) handleActiveVoteDCC(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleActiveVoteDCC")

	avr, err := p.processActiveVoteDCC()
	if err != nil {
		RespondWithError(w, r, 0,
			"handleActiveVoteDCC: processActiveVoteDCC %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, avr)
}

// handleStartVoteDCC handles the dcc StartVote route.
func (p *politeiawww) handleStartVoteDCC(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleStartVoteDCC")

	var sv cms.StartVote
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&sv); err != nil {
		RespondWithError(w, r, 0, "handleStartVoteDCC: unmarshal",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	user, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleStartVoteDCC: getSessionUser %v", err)
		return
	}

	// Sanity
	if !user.Admin {
		RespondWithError(w, r, 0,
			"handleStartVoteDCC: admin %v", user.Admin)
		return
	}

	svr, err := p.processStartVoteDCC(sv, user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleStartVoteDCC: processStartVoteDCC %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, svr)
}

func (p *politeiawww) handlePassThroughTokenInventory(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handlePassThroughTokenInventory")

	data, err := p.makeProposalsRequest(http.MethodGet, www.RouteTokenInventory, nil)
	if err != nil {
		RespondWithError(w, r, 0,
			"handlePassThroughTokenInventory: makeProposalsRequest: %v", err)
		return
	}
	util.RespondRaw(w, http.StatusOK, data)
}

func (p *politeiawww) handlePassThroughBatchProposals(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handlePassThroughBatchProposals")

	var bp www.BatchProposals
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&bp); err != nil {
		RespondWithError(w, r, 0, "handlePassThroughBatchProposals: unmarshal",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	data, err := p.makeProposalsRequest(http.MethodPost, www.RouteBatchProposals, bp)
	if err != nil {
		RespondWithError(w, r, 0,
			"handlePassThroughBatchProposals: makeProposalsRequest: %v", err)
		return
	}
	util.RespondRaw(w, http.StatusOK, data)
}

func (p *politeiawww) handleProposalBillingSummary(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleProposalBillingSummary")

	var pbs cms.ProposalBillingSummary
	// get version from query string parameters
	err := util.ParseGetParams(r, &pbs)
	if err != nil {
		RespondWithError(w, r, 0, "handleProposalBillingSummary: ParseGetParams",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	pbsr, err := p.processProposalBillingSummary(pbs)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleProposalBillingSummary: processProposalBillingSummary %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, pbsr)
}

func (p *politeiawww) handleProposalBillingDetails(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleProposalBillingDetails")

	var pbd cms.ProposalBillingDetails
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&pbd); err != nil {
		RespondWithError(w, r, 0, "handleProposalBillingDetails: unmarshal",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	svr, err := p.processProposalBillingDetails(pbd)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleProposalBillingDetails: processProposalBillingDetails %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, svr)
}

// makeProposalsRequest submits pass through requests to the proposals sites
// (testnet or mainnet).  It takes a http method type, proposals route and a
// request interface as arguments.  It returns the response body as byte array
// (which can then be decoded as though a response directly from proposals).
func (p *politeiawww) makeProposalsRequest(method string, route string, v interface{}) ([]byte, error) {
	var (
		requestBody  []byte
		responseBody []byte
		cookies      []*http.Cookie
		csrf         string
		err          error
	)
	if v != nil {
		requestBody, err = json.Marshal(v)
		if err != nil {
			return nil, err
		}
	}

	client, err := util.NewClient(false, "")
	if err != nil {
		return nil, err
	}

	dest := cms.ProposalsMainnet
	if p.cfg.TestNet {
		dest = cms.ProposalsTestnet
	}

	route = dest + "/api/v1" + route

	// We have to special case post requests since they require to first get
	// cookies and csrf headers from a Version GET request.
	if method == http.MethodPost {
		versionRoute := dest + "/api/v1" + www.RouteVersion
		req, err := http.NewRequest(http.MethodGet, versionRoute, nil)
		if err != nil {
			return nil, err
		}

		r, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer r.Body.Close()

		cookies = r.Cookies()
		csrf = r.Header.Get(www.CsrfToken)
	}

	req, err := http.NewRequest(method, route,
		bytes.NewReader(requestBody))
	if err != nil {
		return nil, err
	}

	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}

	req.Header.Set(www.CsrfToken, csrf)

	r, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusT(r.StatusCode),
		}
	}

	responseBody = util.ConvertBodyToByteArray(r.Body, false)
	return responseBody, nil
}

func (p *politeiawww) setCMSWWWRoutes() {
	// Templates
	//p.addTemplate(templateNewProposalSubmittedName,
	//	templateNewProposalSubmittedRaw)

	// Static content.
	// XXX disable static for now.  This code is broken and it needs to
	// point to a sane directory.  If a directory is not set it SHALL be
	// disabled.
	//p.router.PathPrefix("/static/").Handler(http.StripPrefix("/static/",
	//	http.FileServer(http.Dir("."))))

	// Public routes.
	p.router.HandleFunc("/", closeBody(logging(p.handleVersion))).Methods(http.MethodGet)
	p.router.NotFoundHandler = closeBody(p.handleNotFound)
	p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteVersion, p.handleVersion,
		permissionPublic)

	p.addRoute(http.MethodGet, cms.APIRoute,
		www.RoutePolicy, p.handleCMSPolicy,
		permissionPublic)

	// Routes that require being logged in.
	p.addRoute(http.MethodPost, cms.APIRoute,
		www.RouteNewComment, p.handleNewCommentInvoice,
		permissionLogin)
	p.addRoute(http.MethodPost, cms.APIRoute,
		cms.RouteNewInvoice, p.handleNewInvoice,
		permissionLogin)
	p.addRoute(http.MethodPost, cms.APIRoute,
		cms.RouteEditInvoice, p.handleEditInvoice,
		permissionLogin)
	p.addRoute(http.MethodGet, cms.APIRoute,
		cms.RouteInvoiceDetails, p.handleInvoiceDetails,
		permissionLogin)
	p.addRoute(http.MethodGet, cms.APIRoute,
		cms.RouteUserInvoices, p.handleUserInvoices,
		permissionLogin)
	p.addRoute(http.MethodPost, cms.APIRoute,
		cms.RouteInvoices, p.handleInvoices,
		permissionLogin)
	p.addRoute(http.MethodGet, cms.APIRoute,
		cms.RouteInvoiceComments, p.handleInvoiceComments,
		permissionLogin)
	p.addRoute(http.MethodPost, cms.APIRoute,
		cms.RouteInvoiceExchangeRate, p.handleInvoiceExchangeRate,
		permissionLogin)
	p.addRoute(http.MethodPost, cms.APIRoute,
		cms.RouteNewDCC, p.handleNewDCC,
		permissionLogin)
	p.addRoute(http.MethodGet, cms.APIRoute,
		cms.RouteDCCDetails, p.handleDCCDetails,
		permissionLogin)
	p.addRoute(http.MethodPost, cms.APIRoute,
		cms.RouteGetDCCs, p.handleGetDCCs,
		permissionLogin)
	p.addRoute(http.MethodPost, cms.APIRoute,
		cms.RouteSupportOpposeDCC, p.handleSupportOpposeDCC,
		permissionLogin)
	p.addRoute(http.MethodPost, cms.APIRoute,
		cms.RouteNewCommentDCC, p.handleNewCommentDCC,
		permissionLogin)
	p.addRoute(http.MethodGet, cms.APIRoute,
		cms.RouteDCCComments, p.handleDCCComments,
		permissionLogin)
	p.addRoute(http.MethodGet, cms.APIRoute,
		cms.RouteUserSubContractors, p.handleUserSubContractors,
		permissionLogin)
	p.addRoute(http.MethodGet, cms.APIRoute,
		cms.RouteProposalOwner, p.handleProposalOwner,
		permissionLogin)
	p.addRoute(http.MethodPost, cms.APIRoute,
		cms.RouteProposalBilling, p.handleProposalBilling,
		permissionLogin)
	p.addRoute(http.MethodPost, cms.APIRoute,
		cms.RouteCastVoteDCC, p.handleCastVoteDCC,
		permissionLogin)
	p.addRoute(http.MethodPost, cms.APIRoute,
		cms.RouteVoteDetailsDCC, p.handleVoteDetailsDCC,
		permissionLogin)
	p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
		cms.RouteActiveVotesDCC, p.handleActiveVoteDCC,
		permissionLogin)
	p.addRoute(http.MethodGet, cms.APIRoute,
		www.RouteTokenInventory, p.handlePassThroughTokenInventory,
		permissionLogin)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteBatchProposals, p.handlePassThroughBatchProposals,
		permissionLogin)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteSetTOTP, p.handleSetTOTP,
		permissionLogin)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteVerifyTOTP, p.handleVerifyTOTP,
		permissionLogin)

	// Unauthenticated websocket
	p.addRoute("", www.PoliteiaWWWAPIRoute,
		www.RouteUnauthenticatedWebSocket, p.handleUnauthenticatedWebsocket,
		permissionPublic)
	// Authenticated websocket
	p.addRoute("", www.PoliteiaWWWAPIRoute,
		www.RouteAuthenticatedWebSocket, p.handleAuthenticatedWebsocket,
		permissionLogin)

	// Routes that require being logged in as an admin user.
	p.addRoute(http.MethodPost, cms.APIRoute,
		cms.RouteInviteNewUser, p.handleInviteNewUser,
		permissionAdmin)
	p.addRoute(http.MethodPost, cms.APIRoute,
		cms.RouteSetInvoiceStatus, p.handleSetInvoiceStatus,
		permissionAdmin)
	p.addRoute(http.MethodPost, cms.APIRoute,
		cms.RouteGeneratePayouts, p.handleGeneratePayouts,
		permissionAdmin)
	p.addRoute(http.MethodGet, cms.APIRoute,
		cms.RoutePayInvoices, p.handlePayInvoices,
		permissionAdmin)
	p.addRoute(http.MethodPost, cms.APIRoute,
		cms.RouteInvoicePayouts, p.handleInvoicePayouts,
		permissionAdmin)
	p.addRoute(http.MethodGet, cms.APIRoute,
		cms.RouteAdminUserInvoices, p.handleAdminUserInvoices,
		permissionAdmin)
	p.addRoute(http.MethodPost, cms.APIRoute,
		cms.RouteSetDCCStatus, p.handleSetDCCStatus,
		permissionAdmin)
	p.addRoute(http.MethodPost, cms.APIRoute,
		cms.RouteStartVoteDCC, p.handleStartVoteDCC,
		permissionAdmin)
	p.addRoute(http.MethodGet, cms.APIRoute,
		cms.RouteProposalBillingSummary, p.handleProposalBillingSummary,
		permissionAdmin)
	p.addRoute(http.MethodPost, cms.APIRoute,
		cms.RouteProposalBillingDetails, p.handleProposalBillingDetails,
		permissionAdmin)
}
