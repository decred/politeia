// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package comments

import (
	"encoding/json"
	"net/http"

	pdclient "github.com/decred/politeia/politeiad/client"
	cmv1 "github.com/decred/politeia/politeiawww/api/comments/v1"
	"github.com/decred/politeia/politeiawww/config"
	"github.com/decred/politeia/politeiawww/events"
	"github.com/decred/politeia/politeiawww/sessions"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/decred/politeia/util"
)

// Comments is the context that handles the comments API.
type Comments struct {
	cfg       *config.Config
	politeiad *pdclient.Client
	userdb    user.Database
	sessions  sessions.Sessions
	events    *events.Manager
}

// HandleNew is the request handler for the comments v1 New route.
func (c *Comments) HandleNew(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandleNew")

	var n cmv1.New
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&n); err != nil {
		respondWithError(w, r, "HandleNew: unmarshal",
			cmv1.UserErrorReply{
				ErrorCode: cmv1.ErrorCodeInputInvalid,
			})
		return
	}

	u, err := c.sessions.GetSessionUser(w, r)
	if err != nil {
		respondWithError(w, r,
			"HandleNew: GetSessionUser: %v", err)
		return
	}

	nr, err := c.processNew(r.Context(), n, *u)
	if err != nil {
		respondWithError(w, r,
			"HandleNew: processNew: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, nr)
}

// HandleVote is the request handler for the comments v1 Vote route.
func (c *Comments) HandleVote(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandleVote")

	var v cmv1.Vote
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&v); err != nil {
		respondWithError(w, r, "HandleVote: unmarshal",
			cmv1.UserErrorReply{
				ErrorCode: cmv1.ErrorCodeInputInvalid,
			})
		return
	}

	u, err := c.sessions.GetSessionUser(w, r)
	if err != nil {
		respondWithError(w, r,
			"HandleVote: GetSessionUser: %v", err)
		return
	}

	vr, err := c.processVote(r.Context(), v, *u)
	if err != nil {
		respondWithError(w, r,
			"HandleVote: processVote: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, vr)
}

// HandleDel is the request handler for the comments v1 Del route.
func (c *Comments) HandleDel(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandleDel")

	var d cmv1.Del
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&d); err != nil {
		respondWithError(w, r, "HandleDel: unmarshal",
			cmv1.UserErrorReply{
				ErrorCode: cmv1.ErrorCodeInputInvalid,
			})
		return
	}

	u, err := c.sessions.GetSessionUser(w, r)
	if err != nil {
		respondWithError(w, r,
			"HandleDel: GetSessionUser: %v", err)
		return
	}

	dr, err := c.processDel(r.Context(), d, *u)
	if err != nil {
		respondWithError(w, r,
			"HandleDel: processDel: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, dr)
}

// HandleCount is the request handler for the comments v1 Count route.
func (c *Comments) HandleCount(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandleCount")

	var ct cmv1.Count
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&c); err != nil {
		respondWithError(w, r, "HandleCount: unmarshal",
			cmv1.UserErrorReply{
				ErrorCode: cmv1.ErrorCodeInputInvalid,
			})
		return
	}

	cr, err := c.processCount(r.Context(), ct)
	if err != nil {
		respondWithError(w, r,
			"HandleCount: processCount: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, cr)
}

// HandleComments is the request handler for the comments v1 Comments route.
func (c *Comments) HandleComments(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandleComments")

	var cs cmv1.Comments
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&cs); err != nil {
		respondWithError(w, r, "HandleComments: unmarshal",
			cmv1.UserErrorReply{
				ErrorCode: cmv1.ErrorCodeInputInvalid,
			})
		return
	}

	// Lookup session user. This is a public route so a session may not
	// exist. Ignore any session not found errors.
	u, err := c.sessions.GetSessionUser(w, r)
	if err != nil && err != sessions.ErrSessionNotFound {
		respondWithError(w, r,
			"HandleComments: GetSessionUser: %v", err)
		return
	}

	cr, err := c.processComments(r.Context(), cs, u)
	if err != nil {
		respondWithError(w, r,
			"HandleComments: processComments: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, cr)
}

// HandleVotes is the request handler for the comments v1 Votes route.
func (c *Comments) HandleVotes(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandleVotes")

	var v cmv1.Votes
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&v); err != nil {
		respondWithError(w, r, "HandleVotes: unmarshal",
			cmv1.UserErrorReply{
				ErrorCode: cmv1.ErrorCodeInputInvalid,
			})
		return
	}

	vr, err := c.processVotes(r.Context(), v)
	if err != nil {
		respondWithError(w, r,
			"HandleVotes: processVotes: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, vr)
}

// HandleTimestamps is the request handler for the comments v1 Timestamps
// route.
func (c *Comments) HandleTimestamps(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandleTimestamps")

	var t cmv1.Timestamps
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&t); err != nil {
		respondWithError(w, r, "HandleTimestamps: unmarshal",
			cmv1.UserErrorReply{
				ErrorCode: cmv1.ErrorCodeInputInvalid,
			})
		return
	}

	// Lookup session user. This is a public route so a session may not
	// exist. Ignore any session not found errors.
	u, err := c.sessions.GetSessionUser(w, r)
	if err != nil && err != sessions.ErrSessionNotFound {
		respondWithError(w, r,
			"HandleTimestamps: GetSessionUser: %v", err)
		return
	}

	isAdmin := u != nil && u.Admin
	tr, err := c.processTimestamps(r.Context(), t, isAdmin)
	if err != nil {
		respondWithError(w, r,
			"HandleTimestamps: processTimestamps: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, tr)
}

// New returns a new Comments context.
func New(cfg *config.Config, politeiad *pdclient.Client, userdb user.Database) *Comments {
	return &Comments{
		cfg:       cfg,
		politeiad: politeiad,
		userdb:    userdb,
	}
}
