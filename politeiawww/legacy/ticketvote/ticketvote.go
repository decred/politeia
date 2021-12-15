// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	pdv2 "github.com/decred/politeia/politeiad/api/v2"
	pdclient "github.com/decred/politeia/politeiad/client"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	v1 "github.com/decred/politeia/politeiawww/api/ticketvote/v1"
	"github.com/decred/politeia/politeiawww/config"
	"github.com/decred/politeia/politeiawww/events"
	"github.com/decred/politeia/politeiawww/legacy/sessions"
	"github.com/decred/politeia/util"
)

// TicketVote is the context for the ticketvote API.
type TicketVote struct {
	cfg       *config.Config
	politeiad *pdclient.Client
	sessions  *sessions.Sessions
	events    *events.Manager
	policy    *v1.PolicyReply
}

// HandlePolicy is the request handler for the ticketvote v1 Policy route.
func (t *TicketVote) HandlePolicy(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandlePolicy")

	util.RespondWithJSON(w, http.StatusOK, t.policy)
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

// HandleSubmissions is the request handler for the ticketvote v1 Submissions
// route.
func (t *TicketVote) HandleSubmissions(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandleSubmissions")

	var s v1.Submissions
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&s); err != nil {
		respondWithError(w, r, "HandleSubmissions: unmarshal",
			v1.UserErrorReply{
				ErrorCode: v1.ErrorCodeInputInvalid,
			})
		return
	}

	sr, err := t.processSubmissions(r.Context(), s)
	if err != nil {
		respondWithError(w, r, "HandleSubmissions: processSubmissions: %v",
			err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, sr)
}

// HandleInventory is the request handler for the ticketvote v1 Inventory
// route.
func (t *TicketVote) HandleInventory(w http.ResponseWriter, r *http.Request) {
	log.Tracef("HandleInventory")

	var i v1.Inventory
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&i); err != nil {
		respondWithError(w, r, "HandleInventory: unmarshal",
			v1.UserErrorReply{
				ErrorCode: v1.ErrorCodeInputInvalid,
			})
		return
	}

	ir, err := t.processInventory(r.Context(), i)
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
	if err := decoder.Decode(&ts); err != nil {
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
func New(cfg *config.Config, pdc *pdclient.Client, s *sessions.Sessions, e *events.Manager, plugins []pdv2.Plugin) (*TicketVote, error) {
	// Parse plugin settings
	var (
		linkByPeriodMin    int64
		linkByPeriodMax    int64
		voteDurationMin    uint32
		voteDurationMax    uint32
		summariesPageSize  uint32
		inventoryPageSize  uint32
		timestampsPageSize uint32
	)
	for _, p := range plugins {
		if p.ID != ticketvote.PluginID {
			// Wrong plugin; skip
			continue
		}
		for _, v := range p.Settings {
			switch v.Key {
			case ticketvote.SettingKeyLinkByPeriodMin:
				i, err := strconv.ParseInt(v.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				linkByPeriodMin = i
			case ticketvote.SettingKeyLinkByPeriodMax:
				i, err := strconv.ParseInt(v.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				linkByPeriodMax = i
			case ticketvote.SettingKeyVoteDurationMin:
				u, err := strconv.ParseUint(v.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				voteDurationMin = uint32(u)
			case ticketvote.SettingKeyVoteDurationMax:
				u, err := strconv.ParseUint(v.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				voteDurationMax = uint32(u)
			case ticketvote.SettingKeySummariesPageSize:
				u, err := strconv.ParseUint(v.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				summariesPageSize = uint32(u)
			case ticketvote.SettingKeyInventoryPageSize:
				u, err := strconv.ParseUint(v.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				inventoryPageSize = uint32(u)
			case ticketvote.SettingKeyTimestampsPageSize:
				u, err := strconv.ParseUint(v.Value, 10, 64)
				if err != nil {
					return nil, err
				}
				timestampsPageSize = uint32(u)
			default:
				log.Warnf("Unknown plugin setting %v; Skipping...", v.Key)
			}
		}
	}

	// Verify all plugin settings have been provided
	switch {
	case linkByPeriodMin == 0:
		return nil, fmt.Errorf("plugin setting not found: %v",
			ticketvote.SettingKeyLinkByPeriodMin)
	case linkByPeriodMax == 0:
		return nil, fmt.Errorf("plugin setting not found: %v",
			ticketvote.SettingKeyLinkByPeriodMax)
	case voteDurationMin == 0:
		return nil, fmt.Errorf("plugin setting not found: %v",
			ticketvote.SettingKeyVoteDurationMin)
	case voteDurationMax == 0:
		return nil, fmt.Errorf("plugin setting not found: %v",
			ticketvote.SettingKeyVoteDurationMax)
	case summariesPageSize == 0:
		return nil, fmt.Errorf("plugin setting not found: %v",
			ticketvote.SettingKeySummariesPageSize)
	case inventoryPageSize == 0:
		return nil, fmt.Errorf("plugin setting not found: %v",
			ticketvote.SettingKeyInventoryPageSize)
	case timestampsPageSize == 0:
		return nil, fmt.Errorf("plugin setting not found: %v",
			ticketvote.SettingKeyTimestampsPageSize)
	}

	return &TicketVote{
		cfg:       cfg,
		politeiad: pdc,
		sessions:  s,
		events:    e,
		policy: &v1.PolicyReply{
			LinkByPeriodMin:    linkByPeriodMin,
			LinkByPeriodMax:    linkByPeriodMax,
			VoteDurationMin:    voteDurationMin,
			VoteDurationMax:    voteDurationMax,
			SummariesPageSize:  summariesPageSize,
			InventoryPageSize:  inventoryPageSize,
			TimestampsPageSize: timestampsPageSize,
		},
	}, nil
}
