// Copyright (c) 2017-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package legacy

import (
	"encoding/json"
	"errors"
	"net/http"

	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/sessions"
	"github.com/decred/politeia/util"
	"github.com/gorilla/mux"
)

func (p *LegacyPoliteiawww) handleTokenInventory(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleTokenInventory")

	// Get session user. This is a public route so one might not exist.
	user, err := p.sessions.GetSessionUser(w, r)
	if err != nil && !errors.Is(err, sessions.ErrSessionNotFound) {
		RespondWithError(w, r, 0,
			"handleTokenInventory: getSessionUser %v", err)
		return
	}

	isAdmin := user != nil && user.Admin
	reply, err := p.processTokenInventory(r.Context(), isAdmin)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleTokenInventory: processTokenInventory: %v", err)
		return
	}
	util.RespondWithJSON(w, http.StatusOK, reply)
}

func (p *LegacyPoliteiawww) handleAllVetted(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleAllVetted")

	var v www.GetAllVetted
	err := util.ParseGetParams(r, &v)
	if err != nil {
		RespondWithError(w, r, 0, "handleAllVetted: ParseGetParams",
			www.UserError{
				ErrorCode: www.ErrorStatusInvalidInput,
			})
		return
	}

	vr, err := p.processAllVetted(r.Context(), v)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleAllVetted: processAllVetted %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, vr)
}

func (p *LegacyPoliteiawww) handleProposalDetails(w http.ResponseWriter, r *http.Request) {
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
	user, err := p.sessions.GetSessionUser(w, r)
	if err != nil && err != sessions.ErrSessionNotFound {
		RespondWithError(w, r, 0,
			"handleProposalDetails: getSessionUser %v", err)
		return
	}

	reply, err := p.processProposalDetails(r.Context(), pd, user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleProposalDetails: processProposalDetails %v", err)
		return
	}

	// Reply with the proposal details.
	util.RespondWithJSON(w, http.StatusOK, reply)
}

func (p *LegacyPoliteiawww) handleBatchProposals(w http.ResponseWriter, r *http.Request) {
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
	user, err := p.sessions.GetSessionUser(w, r)
	if err != nil && err != sessions.ErrSessionNotFound {
		RespondWithError(w, r, 0,
			"handleBatchProposals: getSessionUser %v", err)
		return
	}

	reply, err := p.processBatchProposals(r.Context(), bp, user)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleBatchProposals: processBatchProposals %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, reply)
}

func (p *LegacyPoliteiawww) handleBatchVoteSummary(w http.ResponseWriter, r *http.Request) {
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

	reply, err := p.processBatchVoteSummary(r.Context(), bvs)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleBatchVoteSummary: processBatchVoteSummary %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, reply)
}

func (p *LegacyPoliteiawww) handleVoteStatus(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleVoteStatus")

	pathParams := mux.Vars(r)
	token := pathParams["token"]

	reply, err := p.processVoteStatus(r.Context(), token)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleVoteStatus: processVoteStatus %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, reply)
}

func (p *LegacyPoliteiawww) handleAllVoteStatus(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleAllVoteStatus")

	reply, err := p.processAllVoteStatus(r.Context())
	if err != nil {
		RespondWithError(w, r, 0,
			"handleAllVoteStatus: processAllVoteStatus %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, reply)
}

func (p *LegacyPoliteiawww) handleActiveVote(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleActiveVote")

	avr, err := p.processActiveVote(r.Context())
	if err != nil {
		RespondWithError(w, r, 0,
			"handleActiveVote: processActiveVote %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, avr)
}

func (p *LegacyPoliteiawww) handleCastVotes(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleCastVotes")

	var cv www.Ballot
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&cv); err != nil {
		RespondWithError(w, r, 0, "handleCastVotes: unmarshal", www.UserError{
			ErrorCode: www.ErrorStatusInvalidInput,
		})
		return
	}

	avr, err := p.processCastVotes(r.Context(), &cv)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleCastVotes: processCastVotes %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, avr)
}

func (p *LegacyPoliteiawww) handleVoteResults(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleVoteResults")

	pathParams := mux.Vars(r)
	token := pathParams["token"]

	vrr, err := p.processVoteResults(r.Context(), token)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleVoteResults: processVoteResults %v",
			err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, vrr)
}
