// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"net/http"

	cmplugin "github.com/decred/politeia/politeiad/plugins/comments"
	piplugin "github.com/decred/politeia/politeiad/plugins/pi"
	tkplugin "github.com/decred/politeia/politeiad/plugins/ticketvote"
	umplugin "github.com/decred/politeia/politeiad/plugins/usermd"
	cmv1 "github.com/decred/politeia/politeiawww/api/comments/v1"
	piv1 "github.com/decred/politeia/politeiawww/api/pi/v1"
	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
	tkv1 "github.com/decred/politeia/politeiawww/api/ticketvote/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/comments"
	"github.com/decred/politeia/politeiawww/pi"
	"github.com/decred/politeia/politeiawww/records"
	"github.com/decred/politeia/politeiawww/ticketvote"
	"github.com/google/uuid"
)

// setupPiRoutes sets up the API routes for piwww mode.
func (p *politeiawww) setupPiRoutes(r *records.Records, c *comments.Comments, t *ticketvote.TicketVote, pic *pi.Pi) {
	// Return a 404 when a route is not found
	p.router.NotFoundHandler = http.HandlerFunc(p.handleNotFound)

	// The version routes set the CSRF token and thus need to be part
	// of the CSRF protected auth router.
	p.auth.HandleFunc("/", p.handleVersion).Methods(http.MethodGet)
	p.auth.StrictSlash(true).
		HandleFunc(www.PoliteiaWWWAPIRoute+www.RouteVersion, p.handleVersion).
		Methods(http.MethodGet)

	// Legacy www routes. These routes have been DEPRECATED. Support
	// will be removed in a future release.
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
		www.RouteVoteStatus, p.handleVoteStatus,
		permissionPublic)
	p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteAllVoteStatus, p.handleAllVoteStatus,
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
		rcv1.RoutePolicy, r.HandlePolicy,
		permissionPublic)
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
		rcv1.RouteDetails, r.HandleDetails,
		permissionPublic)
	p.addRoute(http.MethodPost, rcv1.APIRoute,
		rcv1.RouteTimestamps, r.HandleTimestamps,
		permissionPublic)
	p.addRoute(http.MethodPost, rcv1.APIRoute,
		rcv1.RouteRecords, r.HandleRecords,
		permissionPublic)
	p.addRoute(http.MethodPost, rcv1.APIRoute,
		rcv1.RouteInventory, r.HandleInventory,
		permissionPublic)
	p.addRoute(http.MethodPost, rcv1.APIRoute,
		rcv1.RouteInventoryOrdered, r.HandleInventoryOrdered,
		permissionPublic)
	p.addRoute(http.MethodPost, rcv1.APIRoute,
		rcv1.RouteUserRecords, r.HandleUserRecords,
		permissionPublic)

	// Comment routes
	p.addRoute(http.MethodPost, cmv1.APIRoute,
		cmv1.RoutePolicy, c.HandlePolicy,
		permissionPublic)
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
		cmv1.RouteCount, c.HandleCount,
		permissionPublic)
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
		tkv1.RoutePolicy, t.HandlePolicy,
		permissionPublic)
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
		tkv1.RouteSubmissions, t.HandleSubmissions,
		permissionPublic)
	p.addRoute(http.MethodPost, tkv1.APIRoute,
		tkv1.RouteInventory, t.HandleInventory,
		permissionPublic)
	p.addRoute(http.MethodPost, tkv1.APIRoute,
		tkv1.RouteTimestamps, t.HandleTimestamps,
		permissionPublic)

	// Pi routes
	p.addRoute(http.MethodPost, piv1.APIRoute,
		piv1.RoutePolicy, pic.HandlePolicy,
		permissionPublic)
	p.addRoute(http.MethodPost, piv1.APIRoute,
		piv1.RouteSetBillingStatus, pic.HandleSetBillingStatus,
		permissionAdmin)
	p.addRoute(http.MethodPost, piv1.APIRoute,
		piv1.RouteSummaries, pic.HandleSummaries,
		permissionPublic)
}

func (p *politeiawww) setupPi() error {
	// Get politeiad plugins
	plugins, err := p.getPluginInventory()
	if err != nil {
		return fmt.Errorf("getPluginInventory: %v", err)
	}

	// Verify all required politeiad plugins have been registered
	required := map[string]bool{
		piplugin.PluginID: false,
		cmplugin.PluginID: false,
		tkplugin.PluginID: false,
		umplugin.PluginID: false,
	}
	for _, v := range plugins {
		_, ok := required[v.ID]
		if !ok {
			// Not a required plugin. Skip.
			continue
		}
		required[v.ID] = true
	}
	notFound := make([]string, 0, len(required))
	for pluginID, wasFound := range required {
		if !wasFound {
			notFound = append(notFound, pluginID)
		}
	}
	if len(notFound) > 0 {
		return fmt.Errorf("required politeiad plugins not found: %v", notFound)
	}

	// Setup api contexts
	recordsCtx := records.New(p.cfg, p.politeiad, p.db, p.sessions, p.events)
	commentsCtx, err := comments.New(p.cfg, p.politeiad, p.db,
		p.sessions, p.events, plugins)
	if err != nil {
		return fmt.Errorf("new comments api: %v", err)
	}
	voteCtx, err := ticketvote.New(p.cfg, p.politeiad,
		p.sessions, p.events, plugins)
	if err != nil {
		return fmt.Errorf("new ticketvote api: %v", err)
	}
	piCtx, err := pi.New(p.cfg, p.politeiad, p.db, p.mail,
		p.sessions, p.events, plugins)
	if err != nil {
		return fmt.Errorf("new pi api: %v", err)
	}

	// Setup routes
	p.setUserWWWRoutes()
	p.setupPiRoutes(recordsCtx, commentsCtx, voteCtx, piCtx)

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
	err = p.initPaywallChecker()
	if err != nil {
		return err
	}

	return nil
}
