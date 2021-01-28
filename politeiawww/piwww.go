// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"net/http"

	cmv1 "github.com/decred/politeia/politeiawww/api/comments/v1"
	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
	tkv1 "github.com/decred/politeia/politeiawww/api/ticketvote/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/comments"
	"github.com/decred/politeia/politeiawww/records"
	"github.com/decred/politeia/politeiawww/ticketvote"
	"github.com/google/uuid"
)

// setupPiRoutes sets up the API routes for piwww mode.
func (p *politeiawww) setupPiRoutes(r *records.Records, c *comments.Comments, t *ticketvote.TicketVote) {
	// Return a 404 when a route is not found
	p.router.NotFoundHandler = http.HandlerFunc(p.handleNotFound)

	// The version routes set the CSRF token and thus need to be part
	// of the CSRF protected auth router.
	p.auth.HandleFunc("/", p.handleVersion).Methods(http.MethodGet)
	p.auth.StrictSlash(true).
		HandleFunc(www.PoliteiaWWWAPIRoute+www.RouteVersion, p.handleVersion).
		Methods(http.MethodGet)

	// www routes. These routes have been DEPRECATED.
	p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RoutePolicy, p.handlePolicy,
		permissionPublic)
	p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteTokenInventory, p.handleTokenInventory,
		permissionPublic)
	p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteAllVetted, p.handleAllVetted,
		permissionPublic)
	p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteProposalDetails, p.handleProposalDetails,
		permissionPublic)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteBatchProposals, p.handleBatchProposals,
		permissionPublic)
	p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteActiveVote, p.handleActiveVote,
		permissionPublic)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteCastVotes, p.handleCastVotes,
		permissionPublic)
	p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteVoteResults, p.handleVoteResults,
		permissionPublic)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteBatchVoteSummary, p.handleBatchVoteSummary,
		permissionPublic)

	// Record routes
	p.addRoute(http.MethodPost, rcv1.APIRoute,
		rcv1.RouteNew, r.HandleNew,
		permissionLogin)
	p.addRoute(http.MethodPost, rcv1.APIRoute,
		rcv1.RouteEdit, r.HandleEdit,
		permissionLogin)
	p.addRoute(http.MethodPost, rcv1.APIRoute,
		rcv1.RouteSetStatus, r.HandleSetStatus,
		permissionAdmin)
	p.addRoute(http.MethodPost, rcv1.APIRoute,
		rcv1.RouteInventory, r.HandleInventory,
		permissionPublic)
	p.addRoute(http.MethodPost, rcv1.APIRoute,
		rcv1.RouteTimestamps, r.HandleTimestamps,
		permissionPublic)

	// Comment routes
	p.addRoute(http.MethodPost, cmv1.APIRoute,
		cmv1.RouteNew, c.HandleNew,
		permissionLogin)
	p.addRoute(http.MethodPost, cmv1.APIRoute,
		cmv1.RouteVote, c.HandleVote,
		permissionLogin)
	p.addRoute(http.MethodPost, cmv1.APIRoute,
		cmv1.RouteDel, c.HandleDel,
		permissionAdmin)
	p.addRoute(http.MethodPost, cmv1.APIRoute,
		cmv1.RouteComments, c.HandleComments,
		permissionPublic)
	p.addRoute(http.MethodPost, cmv1.APIRoute,
		cmv1.RouteVotes, c.HandleVotes,
		permissionPublic)
	p.addRoute(http.MethodPost, cmv1.APIRoute,
		cmv1.RouteTimestamps, c.HandleTimestamps,
		permissionPublic)

	// Ticket vote routes
	p.addRoute(http.MethodPost, tkv1.APIRoute,
		tkv1.RouteAuthorize, t.HandleAuthorize,
		permissionLogin)
	p.addRoute(http.MethodPost, tkv1.APIRoute,
		tkv1.RouteStart, t.HandleStart,
		permissionAdmin)
	p.addRoute(http.MethodPost, tkv1.APIRoute,
		tkv1.RouteCastBallot, t.HandleCastBallot,
		permissionPublic)
	p.addRoute(http.MethodPost, tkv1.APIRoute,
		tkv1.RouteDetails, t.HandleDetails,
		permissionPublic)
	p.addRoute(http.MethodPost, tkv1.APIRoute,
		tkv1.RouteResults, t.HandleResults,
		permissionPublic)
	p.addRoute(http.MethodPost, tkv1.APIRoute,
		tkv1.RouteSummaries, t.HandleSummaries,
		permissionPublic)
	p.addRoute(http.MethodPost, tkv1.APIRoute,
		tkv1.RouteInventory, t.HandleInventory,
		permissionPublic)
	p.addRoute(http.MethodPost, tkv1.APIRoute,
		tkv1.RouteTimestamps, t.HandleTimestamps,
		permissionPublic)

	/*
		// Pi routes
		p.addRoute(http.MethodPost, piv1.APIRoute,
			piv1.RouteProposals, p.handleProposals,
			permissionPublic)
		p.addRoute(http.MethodPost, piv1.APIRoute,
			piv1.RouteVoteInventory, p.handleVoteInventory,
			permissionPublic)
	*/
}

func (p *politeiawww) setupPi() error {
	// Setup api contexts
	c := comments.New(p.cfg, p.politeiad, p.db, p.sessions, p.events)
	tv := ticketvote.New(p.cfg, p.politeiad, p.sessions, p.events)
	r := records.New(p.cfg, p.politeiad, p.sessions, p.events)

	// Setup routes
	p.setUserWWWRoutes()
	p.setupPiRoutes(r, c, tv)

	// Verify paywall settings
	switch {
	case p.cfg.PaywallAmount != 0 && p.cfg.PaywallXpub != "":
		// Paywall is enabled
		paywallAmountInDcr := float64(p.cfg.PaywallAmount) / 1e8
		log.Infof("Paywall : %v DCR", paywallAmountInDcr)

	case p.cfg.PaywallAmount == 0 && p.cfg.PaywallXpub == "":
		// Paywall is disabled
		log.Infof("Paywall: DISABLED")

	default:
		// Invalid paywall setting
		return fmt.Errorf("paywall settings invalid, both an amount " +
			"and public key MUST be set")
	}

	// Setup paywall pool
	p.userPaywallPool = make(map[uuid.UUID]paywallPoolMember)
	err := p.initPaywallChecker()
	if err != nil {
		return err
	}

	// Setup event manager
	p.setupEventListenersPi()

	// TODO Verify politeiad plugins

	return nil
}
