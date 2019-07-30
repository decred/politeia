// Copyright (c) 2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"net/http"
	"text/template"

	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/util"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

var (
	templateInvoiceNotification = template.Must(
		template.New("invoice_notification").Parse(templateInvoiceNotificationRaw))
	templateNewInvoiceComment = template.Must(
		template.New("invoice_comment").Parse(templateNewInvoiceCommentRaw))
	templateNewInvoiceStatusUpdate = template.Must(
		template.New("invoice_status_update").Parse(templateNewInvoiceStatusUpdateRaw))
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
		if err != ErrSessionUUIDNotFound {
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

// handleAdminInvoices handles the request to get all of the  of a new contractor by an
// administrator for the Contractor Management System.
func (p *politeiawww) handleAdminInvoices(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleAdminInvoices")
	var ai cms.AdminInvoices
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&ai); err != nil {
		RespondWithError(w, r, 0, "handleAdminInvoices: unmarshal", www.UserError{
			ErrorCode: www.ErrorStatusInvalidInput,
		})
		return
	}

	user, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleAdminInvoices: getSessionUser %v", err)
		return
	}

	reply, err := p.processAdminInvoices(ai, user)
	if err != nil {
		RespondWithError(w, r, 0, "handleAdminInvoices: processAdminInvoices %v", err)
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
		RespondWithError(w, r, 0, "handleGeneratePayouts: processAdminInvoices %v", err)
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

// handleCommentsGet handles batched comments get.
func (p *politeiawww) handleInvoiceComments(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleCommentsGet")

	pathParams := mux.Vars(r)
	token := pathParams["token"]

	user, err := p.getSessionUser(w, r)
	if err != nil {
		if err != ErrSessionUUIDNotFound {
			RespondWithError(w, r, 0,
				"handleCommentsGet: getSessionUser %v", err)
			return
		}
	}
	gcr, err := p.processInvoiceComments(token, user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleCommentsGet: processCommentsGet %v", err)
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
		MaxImages:                     www.PolicyMaxImages,
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
		CMSUsernameSupportedChars:     www.PolicyUsernameSupportedChars,
		CMSNameLocationSupportedChars: cms.PolicyCMSNameLocationSupportedChars,
		CMSContactSupportedChars:      cms.PolicyCMSContactSupportedChars,
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
		RespondWithError(w, r, 0, "handlePayInvoices: processAdminInvoices %v",
			err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleLineItemPayouts handles incoming requests for line item payout information
func (p *politeiawww) handleLineItemPayouts(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleLineItemPayouts")

	var lip cms.LineItemPayouts
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&lip); err != nil {
		RespondWithError(w, r, 0, "handleLineItemPayouts: unmarshal",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	lipr, err := p.processLineItemPayouts(lip)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleLineItemPayouts: processLineItemPayouts: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, lipr)
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
	p.addRoute(http.MethodGet, www.RouteVersion, p.handleVersion,
		permissionPublic)

	p.addRoute(http.MethodGet, www.RoutePolicy, p.handleCMSPolicy,
		permissionPublic)

	// Routes that require being logged in.
	p.addRoute(http.MethodPost, www.RouteNewComment,
		p.handleNewCommentInvoice, permissionLogin)
	p.addRoute(http.MethodPost, cms.RouteNewInvoice,
		p.handleNewInvoice, permissionLogin)
	p.addRoute(http.MethodPost, cms.RouteEditInvoice,
		p.handleEditInvoice, permissionLogin)
	p.addRoute(http.MethodGet, cms.RouteInvoiceDetails,
		p.handleInvoiceDetails, permissionLogin)
	p.addRoute(http.MethodGet, cms.RouteUserInvoices,
		p.handleUserInvoices, permissionLogin)
	p.addRoute(http.MethodGet, cms.RouteInvoiceComments,
		p.handleInvoiceComments, permissionLogin)
	p.addRoute(http.MethodPost, cms.RouteInvoiceExchangeRate,
		p.handleInvoiceExchangeRate, permissionLogin)

	// Unauthenticated websocket
	p.addRoute("", www.RouteUnauthenticatedWebSocket,
		p.handleUnauthenticatedWebsocket, permissionPublic)
	// Authenticated websocket
	p.addRoute("", www.RouteAuthenticatedWebSocket,
		p.handleAuthenticatedWebsocket, permissionLogin)

	// Routes that require being logged in as an admin user.
	p.addRoute(http.MethodPost, cms.RouteInviteNewUser, p.handleInviteNewUser,
		permissionAdmin)
	p.addRoute(http.MethodPost, www.RouteCensorComment,
		p.handleCensorComment, permissionAdmin)
	p.addRoute(http.MethodPost, cms.RouteAdminInvoices,
		p.handleAdminInvoices, permissionAdmin)
	p.addRoute(http.MethodPost, cms.RouteSetInvoiceStatus,
		p.handleSetInvoiceStatus, permissionAdmin)
	p.addRoute(http.MethodPost, cms.RouteGeneratePayouts,
		p.handleGeneratePayouts, permissionAdmin)
	p.addRoute(http.MethodGet, cms.RoutePayInvoices,
		p.handlePayInvoices, permissionAdmin)
	p.addRoute(http.MethodPost, cms.RouteLineItemPayouts,
		p.handleLineItemPayouts, permissionAdmin)
	p.addRoute(http.MethodGet, cms.RouteAdminUserInvoices,
		p.handleAdminUserInvoices, permissionAdmin)
}
