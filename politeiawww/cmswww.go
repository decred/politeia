package main

import (
	"net/http"

	v1 "github.com/decred/politeia/politeiawww/api/v1"
)

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
	p.addRoute(http.MethodGet, v1.RouteVersion, p.handleVersion,
		permissionPublic)

	p.addRoute(http.MethodGet, v1.RoutePolicy, p.handlePolicy,
		permissionPublic)
	p.addRoute(http.MethodGet, v1.RouteCommentsGet, p.handleCommentsGet,
		permissionPublic)

	// Routes that require being logged in.
	p.addRoute(http.MethodPost, v1.RouteNewComment,
		p.handleNewComment, permissionLogin)

	// Unauthenticated websocket
	p.addRoute("", v1.RouteUnauthenticatedWebSocket,
		p.handleUnauthenticatedWebsocket, permissionPublic)
	// Authenticated websocket
	p.addRoute("", v1.RouteAuthenticatedWebSocket,
		p.handleAuthenticatedWebsocket, permissionLogin)

	// Routes that require being logged in as an admin user.
	p.addRoute(http.MethodPost, v1.RouteInviteNewUser, p.handleInviteNewUser,
		permissionAdmin)
	p.addRoute(http.MethodPost, v1.RouteCensorComment,
		p.handleCensorComment, permissionAdmin)

	// Routes for Contractor Management System

	// Publicish routes
	p.addRoute(http.MethodPost, v1.RouteRegisterUser, p.handleRegisterUser,
		permissionPublic)

	// Admin Routes
}
