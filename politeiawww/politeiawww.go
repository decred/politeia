package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"sync"
	"text/template"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/decred/dcrd/chaincfg"
	exptypes "github.com/decred/dcrdata/explorer/types/v2"
	pstypes "github.com/decred/dcrdata/pubsub/types/v3"
	"github.com/thi4go/politeia/politeiad/api/v1/mime"
	"github.com/thi4go/politeia/politeiad/cache"
	www "github.com/thi4go/politeia/politeiawww/api/www/v1"
	www2 "github.com/thi4go/politeia/politeiawww/api/www/v2"
	"github.com/thi4go/politeia/politeiawww/cmsdatabase"
	"github.com/thi4go/politeia/politeiawww/user"
	utilwww "github.com/thi4go/politeia/politeiawww/util"
	"github.com/thi4go/politeia/util"
	"github.com/thi4go/politeia/util/version"
	"github.com/google/uuid"
	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/gorilla/websocket"
	"github.com/robfig/cron"
)

var (
	templateNewProposalSubmitted = template.Must(
		template.New("new_proposal_submitted_template").Parse(templateNewProposalSubmittedRaw))
	templateProposalVetted = template.Must(
		template.New("proposal_vetted_template").Parse(templateProposalVettedRaw))
	templateProposalEdited = template.Must(
		template.New("proposal_edited_template").Parse(templateProposalEditedRaw))
	templateProposalVoteStarted = template.Must(
		template.New("proposal_vote_started_template").Parse(templateProposalVoteStartedRaw))
	templateProposalVoteAuthorized = template.Must(
		template.New("proposal_vote_authorized_template").Parse(templateProposalVoteAuthorizedRaw))
	templateProposalVettedForAuthor = template.Must(
		template.New("proposal_vetted_for_author_template").Parse(templateProposalVettedForAuthorRaw))
	templateProposalCensoredForAuthor = template.Must(
		template.New("proposal_censored_for_author_template").Parse(templateProposalCensoredForAuthorRaw))
	templateProposalVoteStartedForAuthor = template.Must(
		template.New("proposal_vote_started_for_author_template").Parse(templateProposalVoteStartedForAuthorRaw))
	templateCommentReplyOnProposal = template.Must(
		template.New("comment_reply_on_proposal").Parse(templateCommentReplyOnProposalRaw))
	templateCommentReplyOnComment = template.Must(
		template.New("comment_reply_on_comment").Parse(templateCommentReplyOnCommentRaw))
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

// politeiawww application context.
type politeiawww struct {
	cfg      *config
	router   *mux.Router
	sessions sessions.Store

	ws    map[string]map[string]*wsContext // [uuid][]*context
	wsMtx sync.RWMutex

	// Cache
	cache   cache.Cache
	plugins []Plugin

	// Politeiad client
	client *http.Client

	// SMTP client
	smtp *smtp

	templates map[string]*template.Template
	tmplMtx   sync.RWMutex

	// XXX This needs to be abstracted away
	sync.RWMutex // XXX This needs to be the first entry in struct

	db           user.Database // User database XXX GOT TO GO
	params       *chaincfg.Params
	eventManager *EventManager

	// These properties are only used for testing.
	test bool

	// Following entries require locks
	userPaywallPool map[uuid.UUID]paywallPoolMember // [userid][paywallPoolMember]
	commentVotes    map[string]counters             // [token+commentID]counters

	// voteSummaries is a lazy loaded cache of the votes summaries of
	// proposals whose voting period has ended.
	voteSummaries map[string]www.VoteSummary // [token]VoteSummary

	// XXX userEmails is a temporary measure until the user by email
	// lookups are completely removed from politeiawww.
	userEmails map[string]uuid.UUID // [email]userID

	// Following entries are use only during cmswww mode
	cmsDB cmsdatabase.Database
	cron  *cron.Cron

	// wsDcrdata contains the client and list of current subscriptions to
	// dcrdata's public subscription websocket
	wsDcrdata *wsDcrdata

	// The current best block is cached and updated using a websocket
	// subscription to dcrdata. If the websocket connection is not active,
	// the dcrdata best block route of politeiad is used as a fallback.
	bestBlock uint64
	bbMtx     sync.RWMutex
}

// XXX rig this up
func (p *politeiawww) addTemplate(templateName, templateContent string) {
	p.tmplMtx.Lock()
	defer p.tmplMtx.Unlock()

	p.templates[templateName] = template.Must(
		template.New(templateName).Parse(templateContent))
}

// XXX rig this up
func (p *politeiawww) getTemplate(templateName string) *template.Template {
	p.tmplMtx.RLock()
	defer p.tmplMtx.RUnlock()
	return p.templates[templateName]
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

// handleAllVetted replies with the list of vetted proposals.
func (p *politeiawww) handleAllVetted(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleAllVetted")

	// Get the all vetted command.
	var v www.GetAllVetted
	err := util.ParseGetParams(r, &v)
	if err != nil {
		RespondWithError(w, r, 0, "handleAllVetted: ParseGetParams",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	vr, err := p.processAllVetted(v)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleAllVetted: processAllVetted %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, vr)
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
		ValidMIMETypes:             mime.ValidMimeTypes(),
		MinProposalNameLength:      www.PolicyMinProposalNameLength,
		MaxProposalNameLength:      www.PolicyMaxProposalNameLength,
		ProposalNameSupportedChars: www.PolicyProposalNameSupportedChars,
		MaxCommentLength:           www.PolicyMaxCommentLength,
		BuildInformation:           version.BuildInformation(),
	}

	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleCommentsGet handles batched comments get.
func (p *politeiawww) handleCommentsGet(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleCommentsGet")

	pathParams := mux.Vars(r)
	token := pathParams["token"]

	// Get session user. This is a public route so one might not exist.
	user, err := p.getSessionUser(w, r)
	if err != nil && err != errSessionNotFound {
		RespondWithError(w, r, 0,
			"handleCommentsGet: getSessionUser %v", err)
		return
	}

	gcr, err := p.processCommentsGet(token, user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleCommentsGet: processCommentsGet %v", err)
		return
	}
	util.RespondWithJSON(w, http.StatusOK, gcr)
}

// handleUserProposals returns the proposals for the given user.
func (p *politeiawww) handleUserProposals(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleUserProposals")

	// Get the user proposals command.
	var up www.UserProposals
	err := util.ParseGetParams(r, &up)
	if err != nil {
		RespondWithError(w, r, 0, "handleUserProposals: ParseGetParams",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	userId, err := uuid.Parse(up.UserId)
	if err != nil {
		RespondWithError(w, r, 0, "handleUserProposals: ParseUint",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	// Get session user. This is a public route so one might not exist.
	user, err := p.getSessionUser(w, r)
	if err != nil && err != errSessionNotFound {
		RespondWithError(w, r, 0,
			"handleUserProposals: getSessionUser %v", err)
		return
	}

	upr, err := p.processUserProposals(
		&up,
		user != nil && user.ID == userId,
		user != nil && user.Admin)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleUserProposals: processUserProposals %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, upr)
}

// handleActiveVote returns all active proposals that have an active vote.
func (p *politeiawww) handleActiveVote(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleActiveVote")

	avr, err := p.processActiveVote()
	if err != nil {
		RespondWithError(w, r, 0,
			"handleActiveVote: processActiveVote %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, avr)
}

// handleCastVotes records the user votes in politeiad.
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

// handleVoteResults returns a proposal + all voting action.
func (p *politeiawww) handleVoteResults(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleVoteResults")

	pathParams := mux.Vars(r)
	token := pathParams["token"]

	vrr, err := p.processVoteResults(token)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleVoteResults: processVoteResults %v",
			err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, vrr)
}

// handleVoteDetails returns the vote details for the given proposal token.
func (p *politeiawww) handleVoteDetailsV2(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleVoteDetailsV2")

	pathParams := mux.Vars(r)
	token := pathParams["token"]

	vrr, err := p.processVoteDetailsV2(token)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleVoteDetailsV2: processVoteDetailsV2: %v",
			err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, vrr)
}

// handleGetAllVoteStatus returns the voting status of all public proposals.
func (p *politeiawww) handleGetAllVoteStatus(w http.ResponseWriter, r *http.Request) {
	gasvr, err := p.processGetAllVoteStatus()
	if err != nil {
		RespondWithError(w, r, 0,
			"handleGetAllVoteStatus: processGetAllVoteStatus %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, gasvr)
}

// handleVoteStatus returns the vote status for a given proposal.
func (p *politeiawww) handleVoteStatus(w http.ResponseWriter, r *http.Request) {
	pathParams := mux.Vars(r)
	vsr, err := p.processVoteStatus(pathParams["token"])
	if err != nil {
		RespondWithError(w, r, 0,
			"handleVoteStatus: ProcessVoteStatus: %v", err)
		return
	}
	util.RespondWithJSON(w, http.StatusOK, vsr)
}

// handleTokenInventory returns the tokens of all proposals in the inventory.
func (p *politeiawww) handleTokenInventory(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleTokenInventory")

	// Get session user. This is a public route so one might not exist.
	user, err := p.getSessionUser(w, r)
	if err != nil && err != errSessionNotFound {
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

// handleProposalPaywallDetails returns paywall details that allows the user to
// purchase proposal credits.
func (p *politeiawww) handleProposalPaywallDetails(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleProposalPaywallDetails")

	user, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleProposalPaywallDetails: getSessionUser %v", err)
		return
	}

	reply, err := p.processProposalPaywallDetails(user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleProposalPaywallDetails: processProposalPaywallDetails  %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleNewProposal handles the incoming new proposal command.
func (p *politeiawww) handleNewProposal(w http.ResponseWriter, r *http.Request) {
	// Get the new proposal command.
	log.Tracef("handleNewProposal")
	var np www.NewProposal
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&np); err != nil {
		RespondWithError(w, r, 0, "handleNewProposal: unmarshal", www.UserError{
			ErrorCode: www.ErrorStatusInvalidInput,
		})
		return
	}

	user, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleNewProposal: getSessionUser %v", err)
		return
	}

	reply, err := p.processNewProposal(np, user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleNewProposal: processNewProposal %v", err)
		return
	}

	// Reply with the challenge response and censorship token.
	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleNewComment handles incomming comments.
func (p *politeiawww) handleNewComment(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleNewComment")

	var sc www.NewComment
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&sc); err != nil {
		RespondWithError(w, r, 0, "handleNewComment: unmarshal",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	user, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleNewComment: getSessionUser %v", err)
		return
	}

	cr, err := p.processNewComment(sc, user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleNewComment: processNewComment: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, cr)
}

// handleLikeComment handles up or down voting of commentd.
func (p *politeiawww) handleLikeComment(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleLikeComment")

	var lc www.LikeComment
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&lc); err != nil {
		RespondWithError(w, r, 0, "handleLikeComment: unmarshal",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	user, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleLikeComment: getSessionUser %v", err)
		return
	}

	cr, err := p.processLikeComment(lc, user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleLikeComment: processLikeComment %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, cr)
}

// handleEditProposal attempts to edit a proposal
func (p *politeiawww) handleEditProposal(w http.ResponseWriter, r *http.Request) {
	var ep www.EditProposal
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&ep); err != nil {
		RespondWithError(w, r, 0, "handleEditProposal: unmarshal",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	user, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleEditProposal: getSessionUser %v", err)
		return
	}

	log.Debugf("handleEditProposal: %v", ep.Token)

	epr, err := p.processEditProposal(ep, user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleEditProposal: processEditProposal %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, epr)
}

// handleAuthorizeVote handles authorizing a proposal vote.
func (p *politeiawww) handleAuthorizeVote(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleAuthorizeVote")
	var av www.AuthorizeVote
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&av); err != nil {
		RespondWithError(w, r, 0, "handleAuthorizeVote: unmarshal",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}
	user, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleAuthorizeVote: getSessionUser %v", err)
		return
	}
	avr, err := p.processAuthorizeVote(av, user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleAuthorizeVote: processAuthorizeVote %v", err)
		return
	}
	util.RespondWithJSON(w, http.StatusOK, avr)
}

// handleProposalPaywallPayment returns the payment details for a pending
// proposal paywall payment.
func (p *politeiawww) handleProposalPaywallPayment(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleProposalPaywallPayment")

	user, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleProposalPaywallPayment: getSessionUser %v", err)
		return
	}

	reply, err := p.processProposalPaywallPayment(user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleProposalPaywallPayment: "+
				"processProposalPaywallPayment %v", err)
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

// updateBestBlock updates the cached best block.
func (p *politeiawww) updateBestBlock(bestBlock uint64) {
	p.bbMtx.Lock()
	defer p.bbMtx.Unlock()
	p.bestBlock = bestBlock
}

// getBestBlock returns the cached best block if there is an active websocket
// connection to dcrdata. Otherwise, it requests the best block from politeiad
// using the the decred plugin best block command.
func (p *politeiawww) getBestBlock() (uint64, error) {
	p.bbMtx.RLock()
	bb := p.bestBlock
	p.bbMtx.RUnlock()

	// the cached best block will equal 0 if there is no active websocket
	// connection to dcrdata, or if no new block messages have been received
	// since a connection was established.
	if bb == 0 {
		return p.getBestBlockDecredPlugin()
	}

	return bb, nil
}

// resetPiDcrdataWSSubs is responsible for resetting the wsDcrdata connection
// and making necessary changes to the required changes to the politeiawww
// state so that the service continues to function properly during and after
// the reconnection.
func (p *politeiawww) resetPiDcrdataWSSubs() error {
	// The cached best block is set to zero so that in the time between
	// reconnection and receiving the first new block message, instead of
	// using the old cached value, politeiad is queried for the best block.
	p.updateBestBlock(0)

	return p.wsDcrdata.reconnect()
}

// setupPiDcrdataWSSubs subscribes and listens to websocket messages from
// dcrdata that are needed for pi.
func (p *politeiawww) setupPiDcrdataWSSubs() error {
	err := p.wsDcrdata.subscribe(newBlockSub)
	if err != nil {
		return err
	}

	go func() {
		for {
			receiver, err := p.wsDcrdata.receive()
			if err == errShutdown {
				log.Infof("Dcrdata websocket closed")
				return
			} else if err != nil {
				log.Errorf("wsDcrdata receive: %v", err)
				log.Infof("Dcrdata websocket closed")
				return
			}

			msg, ok := <-receiver

			if !ok {
				// This check is here to avoid a spew of unnecessary error
				// messages. The channel is expected to be closed if wsDcrdata
				// is shut down.
				if p.wsDcrdata.isShutdown() {
					return
				}

				log.Errorf("wsDcrdata receive channel closed. Will reconnect.")
				err = p.resetPiDcrdataWSSubs()
				if err == errShutdown {
					log.Infof("Dcrdata websocket closed")
					return
				} else if err != nil {
					log.Errorf("resetPiDcrdataWSSub: %v", err)
					log.Infof("Dcrdata websocket closed")
					return
				}

				continue
			}

			switch m := msg.Message.(type) {
			case *exptypes.WebsocketBlock:
				log.Debugf("wsDcrdata message WebsocketBlock(height=%v)",
					m.Block.Height)
				p.updateBestBlock(uint64(m.Block.Height))
			case *pstypes.HangUp:
				log.Infof("Dcrdata has hung up. Will reconnect.")
				err = p.resetPiDcrdataWSSubs()
				if err == errShutdown {
					log.Infof("Dcrdata websocket closed")
					return
				} else if err != nil {
					log.Errorf("resetPiDcrdataWSSub: %v", err)
					log.Infof("Dcrdata websocket closed")
					return
				}
				log.Infof("Successfully reconnected to dcrdata")
			case int:
				// Ping messages are of type int
			default:
				log.Errorf("wsDcrdata message of type %v unhandled. %v",
					msg.EventId, m)
			}
		}
	}()

	return nil
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
	if err != nil && err != errSessionNotFound {
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

// handleSetProposalStatus handles the incoming set proposal status command.
// It's used for either publishing or censoring a proposal.
func (p *politeiawww) handleSetProposalStatus(w http.ResponseWriter, r *http.Request) {
	// Get the proposal status command.
	log.Tracef("handleSetProposalStatus")
	var sps www.SetProposalStatus
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&sps); err != nil {
		RespondWithError(w, r, 0, "handleSetProposalStatus: unmarshal",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	user, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleSetProposalStatus: getSessionUser %v", err)
		return
	}

	// Set status
	reply, err := p.processSetProposalStatus(sps, user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleSetProposalStatus: processSetProposalStatus %v",
			err)
		return
	}

	// Reply with the new proposal status.
	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleStartVote handles the v2 StartVote route.
func (p *politeiawww) handleStartVoteV2(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleStartVoteV2")

	var sv www2.StartVote
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&sv); err != nil {
		RespondWithError(w, r, 0, "handleStartVoteV2: unmarshal",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	user, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleStartVoteV2: getSessionUser %v", err)
		return
	}

	// Sanity
	if !user.Admin {
		RespondWithError(w, r, 0,
			"handleStartVoteV2: admin %v", user.Admin)
		return
	}

	svr, err := p.processStartVoteV2(sv, user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleStartVoteV2: processStartVoteV2 %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, svr)
}

// handleCensorComment handles the censoring of a comment by an admin.
func (p *politeiawww) handleCensorComment(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleCensorComment")

	var cc www.CensorComment
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&cc); err != nil {
		RespondWithError(w, r, 0, "handleCensorComment: unmarshal",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	user, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleCensorComment: getSessionUser %v", err)
		return
	}

	cr, err := p.processCensorComment(cc, user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleCensorComment: processCensorComment %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, cr)
}

// setPoliteiaWWWRoutes sets up the politeia routes.
func (p *politeiawww) setPoliteiaWWWRoutes() {
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

	p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteAllVetted, p.handleAllVetted,
		permissionPublic)
	p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteProposalDetails, p.handleProposalDetails,
		permissionPublic)
	p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RoutePolicy, p.handlePolicy,
		permissionPublic)
	p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteCommentsGet, p.handleCommentsGet,
		permissionPublic)
	p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteUserProposals, p.handleUserProposals,
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
	p.addRoute(http.MethodGet, www2.APIRoute,
		www2.RouteVoteDetails, p.handleVoteDetailsV2,
		permissionPublic)
	p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteAllVoteStatus, p.handleGetAllVoteStatus,
		permissionPublic)
	p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteVoteStatus, p.handleVoteStatus,
		permissionPublic)
	p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteTokenInventory, p.handleTokenInventory,
		permissionPublic)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteBatchProposals, p.handleBatchProposals,
		permissionPublic)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteBatchVoteSummary, p.handleBatchVoteSummary,
		permissionPublic)

	// Routes that require being logged in.
	p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteProposalPaywallDetails, p.handleProposalPaywallDetails,
		permissionLogin)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteNewProposal, p.handleNewProposal,
		permissionLogin)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteNewComment, p.handleNewComment,
		permissionLogin) // XXX comments need to become a setting
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteLikeComment, p.handleLikeComment,
		permissionLogin) // XXX comments need to become a setting
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteEditProposal, p.handleEditProposal,
		permissionLogin)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteAuthorizeVote, p.handleAuthorizeVote,
		permissionLogin)
	p.addRoute(http.MethodGet, www.PoliteiaWWWAPIRoute,
		www.RouteProposalPaywallPayment, p.handleProposalPaywallPayment,
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
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteSetProposalStatus, p.handleSetProposalStatus,
		permissionAdmin)
	p.addRoute(http.MethodPost, www2.APIRoute,
		www2.RouteStartVote, p.handleStartVoteV2,
		permissionAdmin)
	p.addRoute(http.MethodPost, www.PoliteiaWWWAPIRoute,
		www.RouteCensorComment, p.handleCensorComment,
		permissionAdmin)
}
