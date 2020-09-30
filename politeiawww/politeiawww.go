// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/politeia/politeiad/api/v1/mime"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/cmsdatabase"
	"github.com/decred/politeia/politeiawww/user"
	utilwww "github.com/decred/politeia/politeiawww/util"
	"github.com/decred/politeia/util"
	"github.com/decred/politeia/util/version"
	"github.com/decred/politeia/wsdcrdata"
	"github.com/google/uuid"
	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/gorilla/websocket"
	"github.com/robfig/cron"
)

// wsContext is the websocket context. If uuid == "" then it is an
// unauthenticated websocket.
type wsContext struct {
	uuid          string
	rid           string
	conn          *websocket.Conn
	wg            sync.WaitGroup
	subscriptions map[string]struct{}
	errorC        chan www.WSError
	pingC         chan struct{}
	done          chan struct{} // SHUT...DOWN...EVERYTHING...
}

func (w *wsContext) String() string {
	u := w.uuid
	if u == "" {
		u = "anon"
	}
	return u + " " + w.rid
}

// IsAuthenticated returns true if the websocket is authenticated.
func (w *wsContext) isAuthenticated() bool {
	return w.uuid != ""
}

// politeiawww represents the politeiawww server.
type politeiawww struct {
	sync.RWMutex
	cfg          *config
	params       *chaincfg.Params
	router       *mux.Router
	client       *http.Client
	smtp         *smtp
	db           user.Database
	sessions     sessions.Store
	eventManager *eventManager
	plugins      []plugin

	// Client websocket connections
	ws    map[string]map[string]*wsContext // [uuid][]*context
	wsMtx sync.RWMutex

	// userEmails contains a mapping of all user emails to user ID.
	// This is required for now because the email is stored as part of
	// the encrypted user blob in the user database, but we also allow
	// the user to sign in using their email address, requiring a user
	// lookup by email. This is a temporary measure and should be
	// removed once all user by email lookups have been taken out.
	userEmails map[string]uuid.UUID // [email]userID

	// These fields are only used during piwww mode
	userPaywallPool map[uuid.UUID]paywallPoolMember // [userid][paywallPoolMember]

	// These fields are use only during cmswww mode
	cmsDB     cmsdatabase.Database
	cron      *cron.Cron
	wsDcrdata *wsdcrdata.Client

	// The following fields are only used during testing.
	test bool
}

// handleNotFound is a generic handler for an invalid route.
func (p *politeiawww) handleNotFound(w http.ResponseWriter, r *http.Request) {
	// Log incoming connection
	log.Debugf("Invalid route: %v %v %v %v", remoteAddr(r), r.Method, r.URL,
		r.Proto)

	// Trace incoming request
	log.Tracef("%v", newLogClosure(func() string {
		trace, err := httputil.DumpRequest(r, true)
		if err != nil {
			trace = []byte(fmt.Sprintf("logging: "+
				"DumpRequest %v", err))
		}
		return string(trace)
	}))

	util.RespondWithJSON(w, http.StatusNotFound, www.ErrorReply{})
}

// version is an HTTP GET to determine the lowest API route version that this
// backend supports.  Additionally it is used to obtain a CSRF token.
func (p *politeiawww) handleVersion(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleVersion")

	versionReply := www.VersionReply{
		Version:      www.PoliteiaWWWAPIVersion,
		Route:        www.PoliteiaWWWAPIRoute,
		BuildVersion: version.BuildMainVersion(),
		PubKey:       hex.EncodeToString(p.cfg.Identity.Key[:]),
		TestNet:      p.cfg.TestNet,
		Mode:         p.cfg.Mode,
	}

	_, err := p.getSessionUser(w, r)
	if err == nil {
		versionReply.ActiveUserSession = true
	}

	vr, err := json.Marshal(versionReply)
	if err != nil {
		RespondWithError(w, r, 0, "handleVersion: Marshal %v", err)
		return
	}

	w.Header().Set("Strict-Transport-Security",
		"max-age=63072000; includeSubDomains")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set(www.CsrfToken, csrf.Token(r))

	w.WriteHeader(http.StatusOK)
	w.Write(vr)
}

func (p *politeiawww) handlePolicy(w http.ResponseWriter, r *http.Request) {
	// Get the policy command.
	log.Tracef("handlePolicy")

	reply := &www.PolicyReply{
		MinPasswordLength:          www.PolicyMinPasswordLength,
		MinUsernameLength:          www.PolicyMinUsernameLength,
		MaxUsernameLength:          www.PolicyMaxUsernameLength,
		UsernameSupportedChars:     www.PolicyUsernameSupportedChars,
		ProposalListPageSize:       www.ProposalListPageSize,
		UserListPageSize:           www.UserListPageSize,
		MaxImages:                  www.PolicyMaxImages,
		MaxImageSize:               www.PolicyMaxImageSize,
		MaxMDs:                     www.PolicyMaxMDs,
		MaxMDSize:                  www.PolicyMaxMDSize,
		PaywallEnabled:             p.paywallIsEnabled(),
		ValidMIMETypes:             mime.ValidMimeTypes(),
		MinProposalNameLength:      www.PolicyMinProposalNameLength,
		MaxProposalNameLength:      www.PolicyMaxProposalNameLength,
		ProposalNameSupportedChars: www.PolicyProposalNameSupportedChars,
		MaxCommentLength:           www.PolicyMaxCommentLength,
		TokenPrefixLength:          www.TokenPrefixLength,
		BuildInformation:           version.BuildInformation(),
		IndexFilename:              www.PolicyIndexFilename,
		MinLinkByPeriod:            p.linkByPeriodMin(),
		MaxLinkByPeriod:            p.linkByPeriodMax(),
		MinVoteDuration:            p.cfg.VoteDurationMin,
		MaxVoteDuration:            p.cfg.VoteDurationMax,
	}

	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleTokenInventory returns the tokens of all proposals in the inventory.
func (p *politeiawww) handleTokenInventory(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleTokenInventory")

	// Get session user. This is a public route so one might not exist.
	user, err := p.getSessionUser(w, r)
	if err != nil && !errors.Is(err, errSessionNotFound) {
		RespondWithError(w, r, 0,
			"handleTokenInventory: getSessionUser %v", err)
		return
	}

	isAdmin := user != nil && user.Admin
	reply, err := p.processTokenInventory(isAdmin)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleTokenInventory: processTokenInventory: %v", err)
		return
	}
	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleProposalDetails handles the incoming proposal details command. It
// fetches the complete details for an existing proposal.
func (p *politeiawww) handleProposalDetails(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleProposalDetails")

	// Get version from query string parameters
	var pd www.ProposalsDetails
	err := util.ParseGetParams(r, &pd)
	if err != nil {
		RespondWithError(w, r, 0, "handleProposalDetails: ParseGetParams",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	// Get proposal token from path parameters
	pathParams := mux.Vars(r)
	pd.Token = pathParams["token"]

	// Get session user. This is a public route so one might not exist.
	user, err := p.getSessionUser(w, r)
	if err != nil && err != errSessionNotFound {
		RespondWithError(w, r, 0,
			"handleProposalDetails: getSessionUser %v", err)
		return
	}

	reply, err := p.processProposalDetails(pd, user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleProposalDetails: processProposalDetails %v", err)
		return
	}

	// Reply with the proposal details.
	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleBatchProposals handles the incoming batch proposals command. It
// returns a ProposalRecord for each of the provided censorship tokens.
func (p *politeiawww) handleBatchProposals(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleBatchProposals")

	var bp www.BatchProposals
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&bp); err != nil {
		RespondWithError(w, r, 0, "handleBatchProposals: unmarshal",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	// Get session user. This is a public route so one might not exist.
	user, err := p.getSessionUser(w, r)
	if err != nil && err != errSessionNotFound {
		RespondWithError(w, r, 0,
			"handleBatchProposals: getSessionUser %v", err)
		return
	}

	reply, err := p.processBatchProposals(bp, user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleBatchProposals: processBatchProposals %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleCastVotes casts dcr ticket votes for a proposal vote.
func (p *politeiawww) handleCastVotes(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleCastVotes")

	var cv www.Ballot
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&cv); err != nil {
		RespondWithError(w, r, 0, "handleCastVotes: unmarshal", www.UserError{
			ErrorCode: www.ErrorStatusInvalidInput,
		})
		return
	}

	avr, err := p.processCastVotes(&cv)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleCastVotes: processCastVotes %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, avr)
}

// handleVoteResultsWWW returns a proposal + all voting action.
func (p *politeiawww) handleVoteResultsWWW(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleVoteResultsWWW")

	pathParams := mux.Vars(r)
	token := pathParams["token"]

	vrr, err := p.processVoteResultsWWW(token)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleVoteResultsWWW: processVoteResultsWWW %v",
			err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, vrr)
}

// handleBatchVoteSummary handles the incoming batch vote summary command. It
// returns a VoteSummary for each of the provided censorship tokens.
func (p *politeiawww) handleBatchVoteSummary(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleBatchVoteSummary")

	var bvs www.BatchVoteSummary
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&bvs); err != nil {
		RespondWithError(w, r, 0, "handleBatchVoteSummary: unmarshal",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	reply, err := p.processBatchVoteSummary(bvs)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleBatchVoteSummary: processBatchVoteSummary %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, reply)
}

// websocketPing is used to verify that websockets are operational.
func (p *politeiawww) websocketPing(id string) {
	log.Tracef("websocketPing %v", id)
	defer log.Tracef("websocketPing exit %v", id)

	p.wsMtx.RLock()
	defer p.wsMtx.RUnlock()

	for _, v := range p.ws[id] {
		if _, ok := v.subscriptions[www.WSCPing]; !ok {
			continue
		}

		select {
		case v.pingC <- struct{}{}:
		default:
		}
	}
}

// handleWebsocketRead reads a websocket command off the socket and tries to
// handle it. Currently it only supports subscribing to websocket events.
func (p *politeiawww) handleWebsocketRead(wc *wsContext) {
	defer wc.wg.Done()

	log.Tracef("handleWebsocketRead %v", wc)
	defer log.Tracef("handleWebsocketRead exit %v", wc)

	for {
		cmd, id, payload, err := utilwww.WSRead(wc.conn)
		if err != nil {
			log.Tracef("handleWebsocketRead read %v %v", wc, err)
			close(wc.done) // force handlers to quit
			return
		}
		switch cmd {
		case www.WSCSubscribe:
			subscribe, ok := payload.(www.WSSubscribe)
			if !ok {
				// We are treating this a hard error so that
				// the client knows they sent in something
				// wrong.
				log.Errorf("handleWebsocketRead invalid "+
					"subscribe type %v %v", wc,
					spew.Sdump(payload))
				return
			}

			//log.Tracef("subscribe: %v %v", wc.uuid,
			//	spew.Sdump(subscribe))

			subscriptions := make(map[string]struct{})
			var errors []string
			for _, v := range subscribe.RPCS {
				if !utilwww.ValidSubscription(v) {
					log.Tracef("invalid subscription %v %v",
						wc, v)
					errors = append(errors,
						fmt.Sprintf("invalid "+
							"subscription %v", v))
					continue
				}
				if utilwww.SubsciptionReqAuth(v) &&
					!wc.isAuthenticated() {
					log.Tracef("requires auth %v %v", wc, v)
					errors = append(errors,
						fmt.Sprintf("requires "+
							"authentication %v", v))
					continue
				}
				subscriptions[v] = struct{}{}
			}

			if len(errors) == 0 {
				// Replace old subscriptions
				p.wsMtx.Lock()
				wc.subscriptions = subscriptions
				p.wsMtx.Unlock()
			} else {
				wc.errorC <- www.WSError{
					Command: www.WSCSubscribe,
					ID:      id,
					Errors:  errors,
				}
			}
		}
	}
}

// handleWebsocketWrite attempts to notify a subscribed websocket. Currently
// only ping is supported.
func (p *politeiawww) handleWebsocketWrite(wc *wsContext) {
	defer wc.wg.Done()
	log.Tracef("handleWebsocketWrite %v", wc)
	defer log.Tracef("handleWebsocketWrite exit %v", wc)

	for {
		var (
			cmd, id string
			payload interface{}
		)
		select {
		case <-wc.done:
			return
		case e, ok := <-wc.errorC:
			if !ok {
				log.Tracef("handleWebsocketWrite error not ok"+
					" %v", wc)
				return
			}
			cmd = www.WSCError
			id = e.ID
			payload = e
		case _, ok := <-wc.pingC:
			if !ok {
				log.Tracef("handleWebsocketWrite ping not ok"+
					" %v", wc)
				return
			}
			cmd = www.WSCPing
			id = ""
			payload = www.WSPing{Timestamp: time.Now().Unix()}
		}

		err := utilwww.WSWrite(wc.conn, cmd, id, payload)
		if err != nil {
			log.Tracef("handleWebsocketWrite write %v %v", wc, err)
			return
		}
	}
}

// handleWebsocket upgrades a regular HTTP connection to a websocket.
func (p *politeiawww) handleWebsocket(w http.ResponseWriter, r *http.Request, id string) {
	log.Tracef("handleWebsocket: %v", id)
	defer log.Tracef("handleWebsocket exit: %v", id)

	// Setup context
	wc := wsContext{
		uuid:          id,
		subscriptions: make(map[string]struct{}),
		pingC:         make(chan struct{}),
		errorC:        make(chan www.WSError),
		done:          make(chan struct{}),
	}

	var upgrader = websocket.Upgrader{
		EnableCompression: true,
	}

	var err error
	wc.conn, err = upgrader.Upgrade(w, r, nil)
	if err != nil {
		http.Error(w, "Could not open websocket connection",
			http.StatusBadRequest)
		return
	}
	defer wc.conn.Close() // causes read to exit as well

	// Create and assign session to map
	p.wsMtx.Lock()
	if _, ok := p.ws[id]; !ok {
		p.ws[id] = make(map[string]*wsContext)
	}
	for {
		rid, err := util.Random(16)
		if err != nil {
			p.wsMtx.Unlock()
			http.Error(w, "Could not create random session id",
				http.StatusBadRequest)
			return
		}
		wc.rid = hex.EncodeToString(rid)
		if _, ok := p.ws[id][wc.rid]; !ok {
			break
		}
	}
	p.ws[id][wc.rid] = &wc
	p.wsMtx.Unlock()

	// Reads
	wc.wg.Add(1)
	go p.handleWebsocketRead(&wc)

	// Writes
	wc.wg.Add(1)
	go p.handleWebsocketWrite(&wc)

	// XXX Example of a server side notifcation. Remove once other commands
	// can be used as examples.
	// time.Sleep(2 * time.Second)
	// p.websocketPing(id)

	wc.wg.Wait()

	// Remove session id
	p.wsMtx.Lock()
	delete(p.ws[id], wc.rid)
	if len(p.ws[id]) == 0 {
		// Remove uuid since it was the last one
		delete(p.ws, id)
	}
	p.wsMtx.Unlock()
}

// handleUnauthenticatedWebsocket attempts to upgrade the current
// unauthenticated connection to a websocket connection.
func (p *politeiawww) handleUnauthenticatedWebsocket(w http.ResponseWriter, r *http.Request) {
	// We are retrieving the uuid here to make sure it is NOT set. This
	// check looks backwards but is correct.
	id, err := p.getSessionUserID(w, r)
	if err != nil && !errors.Is(err, errSessionNotFound) {
		http.Error(w, "Could not get session uuid",
			http.StatusBadRequest)
		return
	}
	if id != "" {
		http.Error(w, "Invalid session uuid", http.StatusBadRequest)
		return
	}
	log.Tracef("handleUnauthenticatedWebsocket: %v", id)
	defer log.Tracef("handleUnauthenticatedWebsocket exit: %v", id)

	p.handleWebsocket(w, r, id)
}

// handleAuthenticatedWebsocket attempts to upgrade the current authenticated
// connection to a websocket connection.
func (p *politeiawww) handleAuthenticatedWebsocket(w http.ResponseWriter, r *http.Request) {
	id, err := p.getSessionUserID(w, r)
	if err != nil {
		http.Error(w, "Could not get session uuid",
			http.StatusBadRequest)
		return
	}

	log.Tracef("handleAuthenticatedWebsocket: %v", id)
	defer log.Tracef("handleAuthenticatedWebsocket exit: %v", id)

	p.handleWebsocket(w, r, id)
}

// setPoliteiaWWWRoutes sets up the politeia routes.
func (p *politeiawww) setPoliteiaWWWRoutes() {
	// Home
	p.router.HandleFunc("/", closeBody(logging(p.handleVersion))).
		Methods(http.MethodGet)

	// Not found
	p.router.NotFoundHandler = closeBody(p.handleNotFound)

	// Public routes
	p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteVersion, p.handleVersion,
		permissionPublic)
	p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RoutePolicy, p.handlePolicy,
		permissionPublic)
	p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteTokenInventory, p.handleTokenInventory,
		permissionPublic)
	p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteProposalDetails, p.handleProposalDetails,
		permissionPublic)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteBatchProposals, p.handleBatchProposals,
		permissionPublic)
	p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteCastVotes, p.handleCastVotes,
		permissionPublic)
	p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteVoteResults, p.handleVoteResultsWWW,
		permissionPublic)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteBatchVoteSummary, p.handleBatchVoteSummary,
		permissionPublic)

	// Unauthenticated websocket
	p.addRoute("", www.PoliteiaWWWAPIRoute,
		www.RouteUnauthenticatedWebSocket, p.handleUnauthenticatedWebsocket,
		permissionPublic)
	// Authenticated websocket
	p.addRoute("", www.PoliteiaWWWAPIRoute,
		www.RouteAuthenticatedWebSocket, p.handleAuthenticatedWebsocket,
		permissionLogin)
}
