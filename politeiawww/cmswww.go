package main

import (
	"encoding/json"
	"net/http"
	"strconv"

	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/util"
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

// handleInviteNewUser handles the invitation of a new contractor by an
// administrator for the Contractor Management System.
func (p *politeiawww) handleRegisterUser(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleRegister")

	// Get the new user command.
	var u cms.RegisterUser
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&u); err != nil {
		RespondWithError(w, r, 0, "handleRegisterUser: unmarshal", www.UserError{
			ErrorCode: www.ErrorStatusInvalidInput,
		})
		return
	}

	reply, err := p.processRegisterUser(u)
	if err != nil {
		RespondWithError(w, r, 0, "handleRegisterUser: ProcessRegisterUser %v", err)
		return
	}

	// Reply with the verification token.
	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleNewInvoice handles the incoming new invoice command.
func (p *politeiawww) handleNewInvoice(w http.ResponseWriter, r *http.Request) {
	// Get the new proposal command.
	log.Tracef("handleNewInvoice")
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
	// Add the path param to the struct.
	log.Tracef("handleInvoiceDetails")
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

	// Get proposal token from path parameters
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

// handleUserInvoices handles the request to get all of the  of a new contractor by an
// administrator for the Contractor Management System.
func (p *politeiawww) handleUserInvoices(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleUserInvoices")

	user, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleNewInvoice: getSessionUser %v", err)
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

// handleAdminInvoices handles the request to get all of the  of a new contractor by an
// administrator for the Contractor Management System.
func (p *politeiawww) handleAdminInvoices(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleAdminInvoices")
	var ai cms.AdminInvoices

	// get version from query string parameters
	err := util.ParseGetParams(r, &ai)
	if err != nil {
		RespondWithError(w, r, 0, "handleInvoiceDetails: ParseGetParams",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	// Get proposal token from path parameters
	pathParams := mux.Vars(r)
	month := pathParams["month"]
	year := pathParams["year"]
	status := pathParams["status"]

	ai.Month = 0
	ai.Year = 0
	ai.Status = -1

	if month != "" {
		aiMonth, err := strconv.Atoi(month)
		if err != nil {
			RespondWithError(w, r, 0, "handleInvoiceDetails: ParseGetParams",
				www.UserError{
					ErrorCode: www.ErrorStatusInvalidInput,
				})
		}
		ai.Month = uint16(aiMonth)
	}

	if year != "" {
		aiYear, err := strconv.Atoi(year)
		if err != nil {
			RespondWithError(w, r, 0, "handleInvoiceDetails: ParseGetParams",
				www.UserError{
					ErrorCode: www.ErrorStatusInvalidInput,
				})
		}
		ai.Year = uint16(aiYear)
	}

	if status != "" {
		aiStatus, err := strconv.Atoi(status)
		if err != nil {
			RespondWithError(w, r, 0, "handleInvoiceDetails: ParseGetParams",
				www.UserError{
					ErrorCode: www.ErrorStatusInvalidInput,
				})
		}
		ai.Status = cms.InvoiceStatusT(aiStatus)
	}

	user, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleNewInvoice: getSessionUser %v", err)
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

	p.addRoute(http.MethodGet, www.RoutePolicy, p.handlePolicy,
		permissionPublic)
	p.addRoute(http.MethodGet, www.RouteCommentsGet, p.handleCommentsGet,
		permissionPublic)

	// Routes that require being logged in.
	p.addRoute(http.MethodPost, www.RouteNewComment,
		p.handleNewComment, permissionLogin)
	p.addRoute(http.MethodPost, cms.RouteNewInvoice,
		p.handleNewInvoice, permissionLogin)
	p.addRoute(http.MethodGet, cms.RouteInvoiceDetails,
		p.handleInvoiceDetails, permissionLogin)
	p.addRoute(http.MethodGet, cms.RouteUserInvoices,
		p.handleUserInvoices, permissionLogin)

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
	p.addRoute(http.MethodGet, cms.RouteAdminInvoices,
		p.handleAdminInvoices, permissionAdmin)

	// Routes for Contractor Management System

	// Publicish routes
	p.addRoute(http.MethodPost, cms.RouteRegisterUser, p.handleRegisterUser,
		permissionPublic)

	// Admin Routes
}
