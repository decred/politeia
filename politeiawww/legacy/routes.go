// Copyright (c) 2019-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package legacy

import (
	"net/http"
	"strings"

	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/util"
)

type permission uint

const (
	permissionPublic permission = iota
	permissionLogin
	permissionAdmin
)

// setUserWWWRoutes setsup the user routes.
func (p *LegacyPoliteiawww) SetUserWWWRoutes() {
	// Public routes
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteNewUser, p.handleNewUser,
		permissionPublic)
	p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteVerifyNewUser, p.handleVerifyNewUser,
		permissionPublic)
	/*
		p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
			www.RouteResendVerification, p.handleResendVerification,
			permissionPublic)
		p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
			www.RouteLogout, p.handleLogout,
			permissionPublic)
		p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
			www.RouteResetPassword, p.handleResetPassword,
			permissionPublic)
		p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
			www.RouteVerifyResetPassword, p.handleVerifyResetPassword,
			permissionPublic)
		p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
			www.RouteUserDetails, p.handleUserDetails,
			permissionPublic)
		p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
			www.RouteUsers, p.handleUsers,
			permissionPublic)

		// Setup the login route.
		p.addLoginRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
			www.RouteLogin, p.handleLogin)

		// Routes that require being logged in.
		p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
			www.RouteSecret, p.handleSecret,
			permissionLogin)
		p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
			www.RouteUserMe, p.handleMe,
			permissionLogin)
		p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
			www.RouteUpdateUserKey, p.handleUpdateUserKey,
			permissionLogin)
		p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
			www.RouteVerifyUpdateUserKey, p.handleVerifyUpdateUserKey,
			permissionLogin)
		p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
			www.RouteChangeUsername, p.handleChangeUsername,
			permissionLogin)
		p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
			www.RouteChangePassword, p.handleChangePassword,
			permissionLogin)
		p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
			www.RouteEditUser, p.handleEditUser,
			permissionLogin)
		p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
			www.RouteUserRegistrationPayment, p.handleUserRegistrationPayment,
			permissionLogin)
		p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
			www.RouteUserProposalPaywall, p.handleUserProposalPaywall,
			permissionLogin)
		p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
			www.RouteUserProposalPaywallTx, p.handleUserProposalPaywallTx,
			permissionLogin)
		p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
			www.RouteUserProposalCredits, p.handleUserProposalCredits,
			permissionLogin)
		p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
			www.RouteSetTOTP, p.handleSetTOTP,
			permissionLogin)
		p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
			www.RouteVerifyTOTP, p.handleVerifyTOTP,
			permissionLogin)

		// Routes that require being logged in as an admin user.
		p.addRoute(http.MethodPut, www.PoliteiaWWWAPIRoute,
			www.RouteUserPaymentsRescan, p.handleUserPaymentsRescan,
			permissionAdmin)
		p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
			www.RouteManageUser, p.handleManageUser,
			permissionAdmin)
	*/
}

/*
// setCMSUserWWWRoutes setsup the user routes for cms mode
func (p *LegacyPoliteiawwww) setCMSUserWWWRoutes() {
	// Public routes
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteLogout, p.handleLogout,
		permissionPublic)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteResetPassword, p.handleResetPassword,
		permissionPublic)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteVerifyResetPassword, p.handleVerifyResetPassword,
		permissionPublic)
	p.addRoute(http.MethodPost, cms.APIRoute,
		cms.RouteRegisterUser, p.handleRegisterUser,
		permissionPublic)

	// Setup the login route.
	p.addLoginRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteLogin, p.handleLogin)

	// Routes that require being logged in.
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteSecret, p.handleSecret,
		permissionLogin)
	p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteUserMe, p.handleMe,
		permissionLogin)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteUpdateUserKey, p.handleUpdateUserKey,
		permissionLogin)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteVerifyUpdateUserKey, p.handleVerifyUpdateUserKey,
		permissionLogin)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteChangeUsername, p.handleChangeUsername,
		permissionLogin)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteChangePassword, p.handleChangePassword,
		permissionLogin)
	p.addRoute(http.MethodGet, cms.APIRoute,
		www.RouteUserDetails, p.handleCMSUserDetails,
		permissionLogin)
	p.addRoute(http.MethodPost, cms.APIRoute,
		www.RouteEditUser, p.handleEditCMSUser,
		permissionLogin)
	p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteUsers, p.handleUsers,
		permissionLogin)
	p.addRoute(http.MethodGet, cms.APIRoute,
		cms.RouteCMSUsers, p.handleCMSUsers,
		permissionLogin)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteSetTOTP, p.handleSetTOTP,
		permissionLogin)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteVerifyTOTP, p.handleVerifyTOTP,
		permissionLogin)

	// Routes that require being logged in as an admin user.
	p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteUsers, p.handleUsers,
		permissionAdmin)
	p.addRoute(http.MethodPost, cms.APIRoute,
		cms.RouteManageCMSUser, p.handleManageCMSUser,
		permissionAdmin)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteManageUser, p.handleManageUser,
		permissionAdmin)
}

func (p *LegacyPoliteiawww) setCMSWWWRoutes() {
	// Return a 404 when a route is not found
	p.router.NotFoundHandler = http.HandlerFunc(p.handleNotFound)

	// The version routes set the CSRF token and thus need to be part
	// of the CSRF protected auth router.
	p.auth.HandleFunc("/", p.handleVersion).Methods(http.MethodGet)
	p.auth.StrictSlash(true).
		HandleFunc(www.PoliteiaWWWAPIRoute+www.RouteVersion, p.handleVersion).
		Methods(http.MethodGet)

	// Public routes.
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
	p.addRoute(http.MethodGet, cms.APIRoute,
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
	p.addRoute(http.MethodPost, cms.APIRoute,
		cms.RouteUserCodeStats, p.handleUserCodeStats,
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
*/

// addRoute sets up a handler for a specific method+route. If method is not
// specified it adds a websocket.
func (p *LegacyPoliteiawww) addRoute(method string, routeVersion string, route string, handler http.HandlerFunc, perm permission) {
	// Sanity check. The login route is special. It must be registered
	// using the addLoginRoute() function.
	if strings.Contains(route, "login") {
		panic("you cannot use this function to register the login route")
	}

	fullRoute := routeVersion + route
	switch perm {
	case permissionAdmin:
		handler = p.isLoggedInAsAdmin(handler)
	case permissionLogin:
		handler = p.isLoggedIn(handler)
	}

	if method == "" {
		// Websocket
		log.Tracef("Adding websocket: %v", fullRoute)
		p.router.StrictSlash(true).HandleFunc(fullRoute, handler)
		return
	}

	switch perm {
	case permissionAdmin, permissionLogin:
		// Add route to auth router
		p.auth.StrictSlash(true).HandleFunc(fullRoute, handler).Methods(method)
	default:
		// Add route to public router
		p.router.StrictSlash(true).HandleFunc(fullRoute, handler).Methods(method)
	}
}

// isLoggedIn ensures that a user is logged in before calling the next
// function.
func (p *LegacyPoliteiawww) isLoggedIn(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Tracef("%v isLoggedIn: %v %v %v",
			util.RemoteAddr(r), r.Method, r.URL, r.Proto)

		id, err := p.sessions.GetSessionUserID(w, r)
		if err != nil {
			util.RespondWithJSON(w, http.StatusUnauthorized, www.UserError{
				ErrorCode: www.ErrorStatusNotLoggedIn,
			})
			return
		}

		// Check if user is authenticated
		if id == "" {
			util.RespondWithJSON(w, http.StatusUnauthorized, www.UserError{
				ErrorCode: www.ErrorStatusNotLoggedIn,
			})
			return
		}

		f(w, r)
	}
}

// isAdmin returns true if the current session has admin privileges.
func (p *LegacyPoliteiawww) isAdmin(w http.ResponseWriter, r *http.Request) (bool, error) {
	user, err := p.sessions.GetSessionUser(w, r)
	if err != nil {
		return false, err
	}

	return user.Admin, nil
}

// isLoggedInAsAdmin ensures that a user is logged in as an admin user
// before calling the next function.
func (p *LegacyPoliteiawww) isLoggedInAsAdmin(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Tracef("%v isLoggedInAsAdmin: %v %v %v",
			util.RemoteAddr(r), r.Method, r.URL, r.Proto)

		// Check if user is admin
		isAdmin, err := p.isAdmin(w, r)
		if err != nil {
			log.Errorf("isLoggedInAsAdmin: isAdmin %v", err)
			util.RespondWithJSON(w, http.StatusUnauthorized, www.UserError{
				ErrorCode: www.ErrorStatusNotLoggedIn,
			})
			return
		}
		if !isAdmin {
			log.Debugf("%v user is not an admin", http.StatusForbidden)
			util.RespondWithJSON(w, http.StatusForbidden, www.UserError{})
			return
		}

		f(w, r)
	}
}
