// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import (
	"encoding/json"
	"net/http"

	pdclient "github.com/decred/politeia/politeiad/client"
	v1 "github.com/decred/politeia/politeiawww/api/ticketvote/v1"
	"github.com/decred/politeia/politeiawww/config"
	"github.com/decred/politeia/politeiawww/events"
	"github.com/decred/politeia/politeiawww/sessions"
	"github.com/decred/politeia/util"
)

// TicketVote is the context for the ticketvote API.
type TicketVote struct {
	cfg       *config.Config
	politeiad *pdclient.Client
	sessions  *sessions.Sessions
	events    *events.Manager
}

// HandleAuthorize is the request handler for the ticketvote v1 Authorize
// route.
func (t *TicketVote) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandleAuthorize")

	var a v1.Authorize
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&a); err != nil {
		respondWithError(w, r, "HandleAuthorize: unmarshal",
			v1.UserErrorReply{
				ErrorCode: v1.ErrorCodeInputInvalid,
			})
		return
	}

	u, err := t.sessions.GetSessionUser(w, r)
	if err != nil {
		respondWithError(w, r,
			"HandleAuthorize: GetSessionUser: %v", err)
		return
	}

	ar, err := t.processAuthorize(r.Context(), a, *u)
	if err != nil {
		respondWithError(w, r,
			"HandleAuthorize: processAuthorize: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, ar)
}

// HandleStart is the requeset handler for the ticketvote v1 Start route.
func (t *TicketVote) HandleStart(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandleStart")

	var s v1.Start
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&s); err != nil {
		respondWithError(w, r, "HandleStart: unmarshal",
			v1.UserErrorReply{
				ErrorCode: v1.ErrorCodeInputInvalid,
			})
		return
	}

	u, err := t.sessions.GetSessionUser(w, r)
	if err != nil {
		respondWithError(w, r,
			"HandleStart: GetSessionUser: %v", err)
		return
	}

	sr, err := t.processStart(r.Context(), s, *u)
	if err != nil {
		respondWithError(w, r,
			"HandleStart: processStart: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, sr)
}

// HandleCastBallot is the request handler for the ticketvote v1 CastBallot
// route.
func (t *TicketVote) HandleCastBallot(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandleCastBallot")

	var cb v1.CastBallot
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&cb); err != nil {
		respondWithError(w, r, "HandleCastBallot: unmarshal",
			v1.UserErrorReply{
				ErrorCode: v1.ErrorCodeInputInvalid,
			})
		return
	}

	cbr, err := t.processCastBallot(r.Context(), cb)
	if err != nil {
		respondWithError(w, r,
			"HandleCastBallot: processCastBallot: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, cbr)
}

// HandleDetails is the request handler for the ticketvote v1 Details route.
func (t *TicketVote) HandleDetails(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandleDetails")

	var d v1.Details
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&d); err != nil {
		respondWithError(w, r, "HandleDetails: unmarshal",
			v1.UserErrorReply{
				ErrorCode: v1.ErrorCodeInputInvalid,
			})
		return
	}

	dr, err := t.processDetails(r.Context(), d)
	if err != nil {
		respondWithError(w, r,
			"HandleDetails: processDetails: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, dr)
}

// HandleResults is the request handler for the ticketvote v1 Results route.
func (t *TicketVote) HandleResults(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandleResults")

	var rs v1.Results
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&rs); err != nil {
		respondWithError(w, r, "HandleResults: unmarshal",
			v1.UserErrorReply{
				ErrorCode: v1.ErrorCodeInputInvalid,
			})
		return
	}

	rsr, err := t.processResults(r.Context(), rs)
	if err != nil {
		respondWithError(w, r,
			"HandleResults: processResults: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, rsr)
}

// HandleSummaries is the request handler for the ticketvote v1 Summaries
// route.
func (t *TicketVote) HandleSummaries(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandleSummaries")

	var s v1.Summaries
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&s); err != nil {
		respondWithError(w, r, "HandleSummaries: unmarshal",
			v1.UserErrorReply{
				ErrorCode: v1.ErrorCodeInputInvalid,
			})
		return
	}

	sr, err := t.processSummaries(r.Context(), s)
	if err != nil {
		respondWithError(w, r, "HandleSummaries: processSummaries: %v",
			err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, sr)
}

// HandleLinkedFrom is the request handler for the ticketvote v1 LinkedFrom
// route.
func (t *TicketVote) HandleLinkedFrom(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandleLinkedFrom")

	var lf v1.LinkedFrom
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&lf); err != nil {
		respondWithError(w, r, "HandleLinkedFrom: unmarshal",
			v1.UserErrorReply{
				ErrorCode: v1.ErrorCodeInputInvalid,
			})
		return
	}

	lfr, err := t.processLinkedFrom(r.Context(), lf)
	if err != nil {
		respondWithError(w, r, "HandleLinkedFrom: processLinkedFrom: %v",
			err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, lfr)
}

// HandleInventory is the request handler for the ticketvote v1 Inventory
// route.
func (t *TicketVote) HandleInventory(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandleInventory")

	ir, err := t.processInventory(r.Context())
	if err != nil {
		respondWithError(w, r, "HandleInventory: processInventory: %v",
			err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, ir)
}

// HandleTimestamps is the request handler for the ticketvote v1 Timestamps
// route.
func (t *TicketVote) HandleTimestamps(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandleTimestamps")

	var ts v1.Timestamps
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&t); err != nil {
		respondWithError(w, r, "HandleTimestamps: unmarshal",
			v1.UserErrorReply{
				ErrorCode: v1.ErrorCodeInputInvalid,
			})
		return
	}

	tsr, err := t.processTimestamps(r.Context(), ts)
	if err != nil {
		respondWithError(w, r,
			"HandleTimestamps: processTimestamps: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, tsr)
}

// New returns a new TicketVote context.
func New(cfg *config.Config, pdc *pdclient.Client, s *sessions.Sessions, e *events.Manager) *TicketVote {
	return &TicketVote{
		cfg:       cfg,
		politeiad: pdc,
		sessions:  s,
		events:    e,
	}
}
