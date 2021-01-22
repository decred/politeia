// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package comments

import (
	"encoding/json"
	"net/http"

	pdclient "github.com/decred/politeia/politeiad/client"
	tkv1 "github.com/decred/politeia/politeiawww/api/ticketvote/v1"
	"github.com/decred/politeia/politeiawww/config"
	"github.com/decred/politeia/politeiawww/events"
	"github.com/decred/politeia/politeiawww/sessions"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/decred/politeia/util"
)

// TicketVote is the context that handles the ticketvote API.
type TicketVote struct {
	cfg       *config.Config
	politeiad *pdclient.Client
	userdb    user.Database
	sessions  sessions.Sessions
	events    *events.Manager
}

func (p *politeiawww) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleAuthorize")

	var a tkv1.Authorize
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&va); err != nil {
		respondWithError(w, r, "handleAuthorize: unmarshal",
			tkv1.UserErrorReply{
				ErrorCode: tkv1.ErrorStatusInputInvalid,
			})
		return
	}

	u, err := p.sessions.GetSessionUser(w, r)
	if err != nil {
		respondWithError(w, r,
			"handleAuthorize: GetSessionUser: %v", err)
		return
	}

	ar, err := p.processAuthorize(r.Context(), a, *u)
	if err != nil {
		respondWithError(w, r,
			"handleAuthorize: processAuthorize: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, vr)
}

func (p *politeiawww) HandleStart(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandleStart")

	var vs piv1.VoteStart
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&vs); err != nil {
		respondWithPiError(w, r, "HandleStart: unmarshal",
			piv1.UserErrorReply{
				ErrorCode: piv1.ErrorStatusInputInvalid,
			})
		return
	}

	usr, err := p.sessions.GetSessionUser(w, r)
	if err != nil {
		respondWithPiError(w, r,
			"HandleStart: GetSessionUser: %v", err)
		return
	}

	vsr, err := p.processVoteStart(r.Context(), vs, *usr)
	if err != nil {
		respondWithPiError(w, r,
			"HandleStart: processVoteStart: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, vsr)
}

func (p *politeiawww) handleCastBallot(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleCastBallot")

	var vb piv1.CastBallot
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&vb); err != nil {
		respondWithPiError(w, r, "handleCastBallot: unmarshal",
			piv1.UserErrorReply{
				ErrorCode: piv1.ErrorStatusInputInvalid,
			})
		return
	}

	vbr, err := p.processCastBallot(r.Context(), vb)
	if err != nil {
		respondWithPiError(w, r,
			"handleCastBallot: processCastBallot: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, vbr)
}

func (p *politeiawww) handleVotes(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleVotes")

	var v piv1.Votes
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&v); err != nil {
		respondWithPiError(w, r, "handleVotes: unmarshal",
			piv1.UserErrorReply{
				ErrorCode: piv1.ErrorStatusInputInvalid,
			})
		return
	}

	vr, err := p.processVotes(r.Context(), v)
	if err != nil {
		respondWithPiError(w, r,
			"handleVotes: processVotes: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, vr)
}

func (p *politeiawww) handleVoteResultsPi(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleVoteResults")

	var vr piv1.VoteResults
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&vr); err != nil {
		respondWithPiError(w, r, "handleVoteResults: unmarshal",
			piv1.UserErrorReply{
				ErrorCode: piv1.ErrorStatusInputInvalid,
			})
		return
	}

	vrr, err := p.processVoteResultsPi(r.Context(), vr)
	if err != nil {
		respondWithPiError(w, r,
			"handleVoteResults: prcoessVoteResults: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, vrr)
}

func (p *politeiawww) handleVoteSummaries(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleVoteSummaries")

	var vs piv1.VoteSummaries
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&vs); err != nil {
		respondWithPiError(w, r, "handleVoteSummaries: unmarshal",
			piv1.UserErrorReply{
				ErrorCode: piv1.ErrorStatusInputInvalid,
			})
		return
	}

	vsr, err := p.processVoteSummaries(r.Context(), vs)
	if err != nil {
		respondWithPiError(w, r, "handleVoteSummaries: processVoteSummaries: %v",
			err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, vsr)
}

func (p *politeiawww) handleVoteInventory(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleVoteInventory")

	var vi piv1.VoteInventory
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&vi); err != nil {
		respondWithPiError(w, r, "handleVoteInventory: unmarshal",
			piv1.UserErrorReply{
				ErrorCode: piv1.ErrorStatusInputInvalid,
			})
		return
	}

	vir, err := p.processVoteInventory(r.Context())
	if err != nil {
		respondWithPiError(w, r, "handleVoteInventory: processVoteInventory: %v",
			err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, vir)
}
