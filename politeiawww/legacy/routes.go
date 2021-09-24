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
	/*
		p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
			www.RouteVerifyNewUser, p.handleVerifyNewUser,
			permissionPublic)
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
