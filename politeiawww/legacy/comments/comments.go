// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package comments

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	pdv2 "github.com/decred/politeia/politeiad/api/v2"
	pdclient "github.com/decred/politeia/politeiad/client"
	"github.com/decred/politeia/politeiad/plugins/comments"
	v1 "github.com/decred/politeia/politeiawww/api/comments/v1"
	"github.com/decred/politeia/politeiawww/config"
	"github.com/decred/politeia/politeiawww/events"
	"github.com/decred/politeia/politeiawww/legacy/sessions"
	"github.com/decred/politeia/politeiawww/legacy/user"
	"github.com/decred/politeia/util"
)

// Comments is the context for the comments API.
type Comments struct {
	cfg       *config.Config
	politeiad *pdclient.Client
	userdb    user.Database
	sessions  *sessions.Sessions
	events    *events.Manager
	policy    *v1.PolicyReply
}

// HandlePolicy is the request handler for the comments v1 Policy route.
func (c *Comments) HandlePolicy(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandlePolicy")

	util.RespondWithJSON(w, http.StatusOK, c.policy)
}

// HandleNew is the request handler for the comments v1 New route.
func (c *Comments) HandleNew(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandleNew")

	var n v1.New
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&n); err != nil {
		respondWithError(w, r, "HandleNew: unmarshal",
			v1.UserErrorReply{
				ErrorCode: v1.ErrorCodeInputInvalid,
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

	var v v1.Vote
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&v); err != nil {
		respondWithError(w, r, "HandleVote: unmarshal",
			v1.UserErrorReply{
				ErrorCode: v1.ErrorCodeInputInvalid,
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

	var d v1.Del
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&d); err != nil {
		respondWithError(w, r, "HandleDel: unmarshal",
			v1.UserErrorReply{
				ErrorCode: v1.ErrorCodeInputInvalid,
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

	var ct v1.Count
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&ct); err != nil {
		respondWithError(w, r, "HandleCount: unmarshal",
			v1.UserErrorReply{
				ErrorCode: v1.ErrorCodeInputInvalid,
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

	var cs v1.Comments
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&cs); err != nil {
		respondWithError(w, r, "HandleComments: unmarshal",
			v1.UserErrorReply{
				ErrorCode: v1.ErrorCodeInputInvalid,
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

	var v v1.Votes
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&v); err != nil {
		respondWithError(w, r, "HandleVotes: unmarshal",
			v1.UserErrorReply{
				ErrorCode: v1.ErrorCodeInputInvalid,
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

	var t v1.Timestamps
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&t); err != nil {
		respondWithError(w, r, "HandleTimestamps: unmarshal",
			v1.UserErrorReply{
				ErrorCode: v1.ErrorCodeInputInvalid,
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
func New(cfg *config.Config, pdc *pdclient.Client, udb user.Database, s *sessions.Sessions, e *events.Manager, plugins []pdv2.Plugin) (*Comments, error) {
	// Parse plugin settings
	var (
		lengthMax      uint32
		voteChangesMax uint32
		allowExtraData bool
	)
	for _, p := range plugins {
		if p.ID != comments.PluginID {
			// Not the comments plugin; skip
			continue
		}
		for _, v := range p.Settings {
			switch v.Key {
			case comments.SettingKeyCommentLengthMax:
				u, err := strconv.ParseUint(v.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				lengthMax = uint32(u)

			case comments.SettingKeyVoteChangesMax:
				u, err := strconv.ParseUint(v.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				voteChangesMax = uint32(u)

			case comments.SettingKeyAllowExtraData:
				b, err := strconv.ParseBool(v.Value)
				if err != nil {
					return nil, err
				}
				allowExtraData = b

			default:
				// Skip unknown settings
				log.Warnf("Unknown plugin setting %v; Skipping...", v.Key)
			}
		}
	}

	// Verify all plugin settings have been provided
	switch {
	case lengthMax == 0:
		return nil, fmt.Errorf("plugin setting not found: %v",
			comments.SettingKeyCommentLengthMax)
	case voteChangesMax == 0:
		return nil, fmt.Errorf("plugin setting not found: %v",
			comments.SettingKeyVoteChangesMax)
	}

	return &Comments{
		cfg:       cfg,
		politeiad: pdc,
		userdb:    udb,
		sessions:  s,
		events:    e,
		policy: &v1.PolicyReply{
			LengthMax:          lengthMax,
			VoteChangesMax:     voteChangesMax,
			AllowExtraData:     allowExtraData,
			CountPageSize:      v1.CountPageSize,
			TimestampsPageSize: v1.TimestampsPageSize,
		},
	}, nil
}
