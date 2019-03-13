package main

import (
	"net/http"
	"sync"
	"text/template"

	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/politeia/politeiad/cache"
	v1 "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
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
	userPubkeys     map[string]string               // [pubkey][userid]
	userPaywallPool map[uuid.UUID]paywallPoolMember // [userid][paywallPoolMember]
	commentScores   map[string]int64                // [token+commentID]resultVotes
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
	p.addRoute(http.MethodGet, v1.RouteVersion, p.handleVersion,
		permissionPublic)

	p.addRoute(http.MethodGet, v1.RouteAllVetted, p.handleAllVetted,
		permissionPublic)
	p.addRoute(http.MethodGet, v1.RouteProposalDetails,
		p.handleProposalDetails, permissionPublic)
	p.addRoute(http.MethodGet, v1.RoutePolicy, p.handlePolicy,
		permissionPublic)
	p.addRoute(http.MethodGet, v1.RouteCommentsGet, p.handleCommentsGet,
		permissionPublic)
	p.addRoute(http.MethodGet, v1.RouteUserProposals, p.handleUserProposals,
		permissionPublic)
	p.addRoute(http.MethodGet, v1.RouteActiveVote, p.handleActiveVote,
		permissionPublic)
	p.addRoute(http.MethodPost, v1.RouteCastVotes, p.handleCastVotes,
		permissionPublic)
	p.addRoute(http.MethodGet, v1.RouteVoteResults,
		p.handleVoteResults, permissionPublic)
	p.addRoute(http.MethodGet, v1.RouteAllVoteStatus,
		p.handleGetAllVoteStatus, permissionPublic)
	p.addRoute(http.MethodGet, v1.RouteVoteStatus,
		p.handleVoteStatus, permissionPublic)
	p.addRoute(http.MethodGet, v1.RoutePropsStats,
		p.handleProposalsStats, permissionPublic)

	// Routes that require being logged in.
	p.addRoute(http.MethodGet, v1.RouteProposalPaywallDetails,
		p.handleProposalPaywallDetails, permissionLogin)
	p.addRoute(http.MethodPost, v1.RouteNewProposal, p.handleNewProposal,
		permissionLogin)
	p.addRoute(http.MethodPost, v1.RouteNewComment,
		p.handleNewComment, permissionLogin)
	p.addRoute(http.MethodPost, v1.RouteLikeComment,
		p.handleLikeComment, permissionLogin)
	p.addRoute(http.MethodGet, v1.RouteUserCommentsLikes,
		p.handleUserCommentsLikes, permissionLogin)
	p.addRoute(http.MethodGet, v1.RouteUserProposalCredits,
		p.handleUserProposalCredits, permissionLogin)
	p.addRoute(http.MethodPost, v1.RouteEditProposal,
		p.handleEditProposal, permissionLogin)
	p.addRoute(http.MethodPost, v1.RouteAuthorizeVote,
		p.handleAuthorizeVote, permissionLogin)
	p.addRoute(http.MethodGet, v1.RouteProposalPaywallPayment,
		p.handleProposalPaywallPayment, permissionLogin)

	// Unauthenticated websocket
	p.addRoute("", v1.RouteUnauthenticatedWebSocket,
		p.handleUnauthenticatedWebsocket, permissionPublic)
	// Authenticated websocket
	p.addRoute("", v1.RouteAuthenticatedWebSocket,
		p.handleAuthenticatedWebsocket, permissionLogin)

	// Routes that require being logged in as an admin user.
	p.addRoute(http.MethodGet, v1.RouteAllUnvetted, p.handleAllUnvetted,
		permissionAdmin)
	p.addRoute(http.MethodPost, v1.RouteSetProposalStatus,
		p.handleSetProposalStatus, permissionAdmin)
	p.addRoute(http.MethodPost, v1.RouteStartVote,
		p.handleStartVote, permissionAdmin)
	p.addRoute(http.MethodPost, v1.RouteCensorComment,
		p.handleCensorComment, permissionAdmin)
}
