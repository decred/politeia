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
	client "github.com/decred/dcrdata/pubsub/psclient"
	"github.com/decred/politeia/politeiad/api/v1/mime"
	"github.com/decred/politeia/politeiad/cache"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/cmsdatabase"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/decred/politeia/util"
	"github.com/google/uuid"
	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/gorilla/websocket"
	"github.com/robfig/cron"
)

const (
//templateNewProposalSubmittedName = "templateNewProposalSubmitted"
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

// wsDcrdata is the context for the dcrdata websocket connection.
type wsDcrdata struct {
	client      *client.Client
	currentSubs []string
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
	cfg    *config
	router *mux.Router

	store *sessions.FilesystemStore

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
	commentScores   map[string]int64                // [token+commentID]resultVotes

	// voteStatuses is a lazy loaded cache of the votes statuses of
	// proposals whose voting period has ended.
	voteStatuses map[string]www.VoteStatusReply // [token]VoteStatusReply

	// XXX userEmails is a temporary measure until the user by email
	// lookups are completely removed from politeiawww.
	userEmails map[string]uuid.UUID // [email]userID

	// Following entries are use only during cmswww mode
	cmsDB cmsdatabase.Database
	cron  *cron.Cron

	// pubSubDcrdata contains the client and list of current subscriptions to
	// dcrdata's public subscription websocket
	pubSubDcrdata *wsDcrdata
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

// version is an HTTP GET to determine what version and API route this backend
// is using.  Additionally it is used to obtain a CSRF token.
func (p *politeiawww) handleVersion(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleVersion")

	versionReply := www.VersionReply{
		Version: www.PoliteiaWWWAPIVersion,
		Route:   www.PoliteiaWWWAPIRoute,
		PubKey:  hex.EncodeToString(p.cfg.Identity.Key[:]),
		TestNet: p.cfg.TestNet,
		Mode:    p.cfg.Mode,
	}

	// Check if there's an active AND invalid session.
	session, err := p.getSession(r)
	if err != nil && session != nil {
		// Create and save a new session for the user.
		session := sessions.NewSession(p.store, www.CookieSession)
		opts := *p.store.Options
		session.Options = &opts
		session.IsNew = true
		err = session.Save(r, w)
		if err != nil {
			RespondWithError(w, r, 0, "handleVersion: session.Save %v", err)
			return
		}
	}

	_, err = p.getSessionUser(w, r)
	if err == nil {
		versionReply.ActiveUserSession = true
	}

	vr, err := json.Marshal(versionReply)
	if err != nil {
		RespondWithError(w, r, 0, "handleVersion: Marshal %v", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Add("Strict-Transport-Security",
		"max-age=63072000; includeSubDomains")
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

// handleProposalDetails handles the incoming proposal details command. It fetches
// the complete details for an existing proposal.
func (p *politeiawww) handleProposalDetails(w http.ResponseWriter, r *http.Request) {
	// Add the path param to the struct.
	log.Tracef("handleProposalDetails")
	var pd www.ProposalsDetails

	// get version from query string parameters
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

	user, err := p.getSessionUser(w, r)
	if err != nil {
		if err != ErrSessionUUIDNotFound {
			RespondWithError(w, r, 0,
				"handleProposalDetails: getSessionUser %v", err)
			return
		}
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
	}

	util.RespondWithJSON(w, http.StatusOK, reply)
}

// handleCommentsGet handles batched comments get.
func (p *politeiawww) handleCommentsGet(w http.ResponseWriter, r *http.Request) {
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

	user, err := p.getSessionUser(w, r)
	if err != nil {
		// since having a logged in user isn't required, simply log the error
		log.Infof("handleUserProposals: could not get session user %v", err)
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

// handleGetAllVoteStatus returns the voting status of all public proposals.
func (p *politeiawww) handleGetAllVoteStatus(w http.ResponseWriter, r *http.Request) {
	gasvr, err := p.processGetAllVoteStatus()
	if err != nil {
		RespondWithError(w, r, 0,
			"handleGetAllVoteStatus: processGetAllVoteStatus %v", err)
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

// handleProposalsStats returns the counting of proposals aggrouped by each proposal status
func (p *politeiawww) handleProposalsStats(w http.ResponseWriter, r *http.Request) {
	psr, err := p.processProposalsStats()
	if err != nil {
		RespondWithError(w, r, 0,
			"handleProposalsStats: processProposalsStats %v", err)
		return
	}
	util.RespondWithJSON(w, http.StatusOK, psr)
}

// handleTokenInventory returns the tokens of all proposals in the inventory.
func (p *politeiawww) handleTokenInventory(w http.ResponseWriter, r *http.Request) {
	reply, err := p.processTokenInventory()
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
		cmd, id, payload, err := util.WSRead(wc.conn)
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
				if !util.ValidSubscription(v) {
					log.Tracef("invalid subscription %v %v",
						wc, v)
					errors = append(errors,
						fmt.Sprintf("invalid "+
							"subscription %v", v))
					continue
				}
				if util.SubsciptionReqAuth(v) &&
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

		err := util.WSWrite(wc.conn, cmd, id, payload)
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
	id, err := p.getSessionUUID(r)
	if err != nil && err != ErrSessionUUIDNotFound {
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
	id, err := p.getSessionUUID(r)
	if err != nil {
		http.Error(w, "Could not get session uuid",
			http.StatusBadRequest)
		return
	}

	log.Tracef("handleAuthenticatedWebsocket: %v", id)
	defer log.Tracef("handleAuthenticatedWebsocket exit: %v", id)

	p.handleWebsocket(w, r, id)
}

// handleAllUnvetted replies with the list of unvetted proposals.
func (p *politeiawww) handleAllUnvetted(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleAllUnvetted")

	// Get the all unvetted command.
	var u www.GetAllUnvetted
	err := util.ParseGetParams(r, &u)
	if err != nil {
		RespondWithError(w, r, 0, "handleAllUnvetted: ParseGetParams",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	ur, err := p.processAllUnvetted(u)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleAllUnvetted: processAllUnvetted %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, ur)
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

// handleStartVote handles starting a vote.
func (p *politeiawww) handleStartVote(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleStartVote")

	var sv www.StartVote
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&sv); err != nil {
		RespondWithError(w, r, 0, "handleStartVote: unmarshal",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	user, err := p.getSessionUser(w, r)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleStartVote: getSessionUser %v", err)
		return
	}

	// Sanity
	if !user.Admin {
		RespondWithError(w, r, 0,
			"handleStartVote: admin %v", user.Admin)
		return
	}

	svr, err := p.processStartVote(sv, user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleStartVote: processStartVote %v", err)
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
	p.addRoute(http.MethodGet, www.RouteVersion, p.handleVersion,
		permissionPublic)

	p.addRoute(http.MethodGet, www.RouteAllVetted, p.handleAllVetted,
		permissionPublic)
	p.addRoute(http.MethodGet, www.RouteProposalDetails,
		p.handleProposalDetails, permissionPublic)
	p.addRoute(http.MethodGet, www.RoutePolicy, p.handlePolicy,
		permissionPublic)
	p.addRoute(http.MethodGet, www.RouteCommentsGet, p.handleCommentsGet,
		permissionPublic)
	p.addRoute(http.MethodGet, www.RouteUserProposals, p.handleUserProposals,
		permissionPublic)
	p.addRoute(http.MethodGet, www.RouteActiveVote, p.handleActiveVote,
		permissionPublic)
	p.addRoute(http.MethodPost, www.RouteCastVotes, p.handleCastVotes,
		permissionPublic)
	p.addRoute(http.MethodGet, www.RouteVoteResults,
		p.handleVoteResults, permissionPublic)
	p.addRoute(http.MethodGet, www.RouteAllVoteStatus,
		p.handleGetAllVoteStatus, permissionPublic)
	p.addRoute(http.MethodGet, www.RouteVoteStatus,
		p.handleVoteStatus, permissionPublic)
	p.addRoute(http.MethodGet, www.RoutePropsStats,
		p.handleProposalsStats, permissionPublic)
	p.addRoute(http.MethodGet, www.RouteTokenInventory,
		p.handleTokenInventory, permissionPublic)

	// Routes that require being logged in.
	p.addRoute(http.MethodGet, www.RouteProposalPaywallDetails,
		p.handleProposalPaywallDetails, permissionLogin)
	p.addRoute(http.MethodPost, www.RouteNewProposal, p.handleNewProposal,
		permissionLogin)
	p.addRoute(http.MethodPost, www.RouteNewComment,
		p.handleNewComment, permissionLogin) // XXX comments need to become a setting
	p.addRoute(http.MethodPost, www.RouteLikeComment,
		p.handleLikeComment, permissionLogin) // XXX comments need to become a setting
	p.addRoute(http.MethodPost, www.RouteEditProposal,
		p.handleEditProposal, permissionLogin)
	p.addRoute(http.MethodPost, www.RouteAuthorizeVote,
		p.handleAuthorizeVote, permissionLogin)
	p.addRoute(http.MethodGet, www.RouteProposalPaywallPayment,
		p.handleProposalPaywallPayment, permissionLogin)

	// Unauthenticated websocket
	p.addRoute("", www.RouteUnauthenticatedWebSocket,
		p.handleUnauthenticatedWebsocket, permissionPublic)
	// Authenticated websocket
	p.addRoute("", www.RouteAuthenticatedWebSocket,
		p.handleAuthenticatedWebsocket, permissionLogin)

	// Routes that require being logged in as an admin user.
	p.addRoute(http.MethodGet, www.RouteAllUnvetted, p.handleAllUnvetted,
		permissionAdmin)
	p.addRoute(http.MethodPost, www.RouteSetProposalStatus,
		p.handleSetProposalStatus, permissionAdmin)
	p.addRoute(http.MethodPost, www.RouteStartVote,
		p.handleStartVote, permissionAdmin)
	p.addRoute(http.MethodPost, www.RouteCensorComment,
		p.handleCensorComment, permissionAdmin)
}
