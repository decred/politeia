// Copyright (c) 2017-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/decred/politeia/decredplugin"
	pdv1 "github.com/decred/politeia/politeiad/api/v1"
	v1 "github.com/decred/politeia/politeiad/api/v1"
	piplugin "github.com/decred/politeia/politeiad/plugins/pi"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	tkplugin "github.com/decred/politeia/politeiad/plugins/ticketvote"
	umplugin "github.com/decred/politeia/politeiad/plugins/usermd"
	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/sessions"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/decred/politeia/util"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

func (p *politeiawww) proposal(ctx context.Context, token, version string) (*www.ProposalRecord, error) {
	// Get record
	r, err := p.politeiad.GetVetted(ctx, token, version)
	if err != nil {
		return nil, err
	}
	pr, err := convertRecordToProposal(*r)
	if err != nil {
		return nil, err
	}

	// Get submissions list if this is an RFP
	if pr.LinkBy != 0 {
		subs, err := p.politeiad.TicketVoteSubmissions(ctx, token)
		if err != nil {
			return nil, err
		}
		pr.LinkedFrom = subs
	}

	// Fill in user data
	userID := userIDFromMetadataStreams(r.Metadata)
	uid, err := uuid.Parse(userID)
	u, err := p.db.UserGetById(uid)
	if err != nil {
		return nil, err
	}
	pr.Username = u.Username

	return pr, nil
}

func (p *politeiawww) proposals(ctx context.Context, reqs []pdv1.RecordRequest) (map[string]www.ProposalRecord, error) {
	records, err := p.politeiad.GetVettedBatch(ctx, reqs)
	if err != nil {
		return nil, err
	}

	proposals := make(map[string]www.ProposalRecord, len(records))
	for k, v := range records {
		// Convert to a proposal
		pr, err := convertRecordToProposal(v)
		if err != nil {
			return nil, err
		}

		// Get submissions list if this is an RFP
		if pr.LinkBy != 0 {
			subs, err := p.politeiad.TicketVoteSubmissions(ctx,
				pr.CensorshipRecord.Token)
			if err != nil {
				return nil, err
			}
			pr.LinkedFrom = subs
		}

		// Fill in user data
		userID := userIDFromMetadataStreams(v.Metadata)
		uid, err := uuid.Parse(userID)
		u, err := p.db.UserGetById(uid)
		if err != nil {
			return nil, err
		}
		pr.Username = u.Username

		proposals[k] = *pr
	}

	return proposals, nil
}

func (p *politeiawww) processTokenInventory(ctx context.Context, isAdmin bool) (*www.TokenInventoryReply, error) {
	log.Tracef("processTokenInventory")

	// Get record inventory
	ir, err := p.politeiad.InventoryByStatus(ctx, "",
		pdv1.RecordStatusInvalid, 0)
	if err != nil {
		return nil, err
	}

	// Get vote inventory
	ti := ticketvote.Inventory{}
	vir, err := p.politeiad.TicketVoteInventory(ctx, ti)
	if err != nil {
		return nil, err
	}

	var (
		// Unvetted
		unvetted        = ir.Unvetted[pdv1.RecordStatusNotReviewed]
		unvettedChanges = ir.Unvetted[pdv1.RecordStatusUnreviewedChanges]
		unreviewed      = append(unvetted, unvettedChanges...)
		censored        = ir.Unvetted[pdv1.RecordStatusCensored]

		// Human readable vote statuses
		statusUnauth   = tkplugin.VoteStatuses[tkplugin.VoteStatusUnauthorized]
		statusAuth     = tkplugin.VoteStatuses[tkplugin.VoteStatusAuthorized]
		statusStarted  = tkplugin.VoteStatuses[tkplugin.VoteStatusStarted]
		statusApproved = tkplugin.VoteStatuses[tkplugin.VoteStatusApproved]
		statusRejected = tkplugin.VoteStatuses[tkplugin.VoteStatusRejected]

		// Vetted
		unauth    = vir.Tokens[statusUnauth]
		auth      = vir.Tokens[statusAuth]
		pre       = append(unauth, auth...)
		active    = vir.Tokens[statusStarted]
		approved  = vir.Tokens[statusApproved]
		rejected  = vir.Tokens[statusRejected]
		abandoned = ir.Vetted[pdv1.RecordStatusArchived]
	)

	// Only return unvetted tokens to admins
	if isAdmin {
		unreviewed = []string{}
		censored = []string{}
	}

	// Return empty arrays and not nils
	if unreviewed == nil {
		unreviewed = []string{}
	}
	if censored == nil {
		censored = []string{}
	}
	if pre == nil {
		pre = []string{}
	}
	if active == nil {
		active = []string{}
	}
	if approved == nil {
		approved = []string{}
	}
	if rejected == nil {
		rejected = []string{}
	}
	if abandoned == nil {
		abandoned = []string{}
	}

	return &www.TokenInventoryReply{
		Unreviewed: unreviewed,
		Censored:   censored,
		Pre:        pre,
		Active:     active,
		Approved:   approved,
		Rejected:   rejected,
		Abandoned:  abandoned,
	}, nil
}

func (p *politeiawww) processAllVetted(ctx context.Context, gav www.GetAllVetted) (*www.GetAllVettedReply, error) {
	log.Tracef("processAllVetted: %v %v", gav.Before, gav.After)
	// TODO

	return nil, nil
}

func (p *politeiawww) processProposalDetails(ctx context.Context, pd www.ProposalsDetails, u *user.User) (*www.ProposalDetailsReply, error) {
	log.Tracef("processProposalDetails: %v", pd.Token)

	// This route will now only return vetted proposal. This is fine
	// since API consumers of this legacy route will only need public
	// proposals.

	// Remove files if the user is not an admin or the author

	return nil, nil
}

func (p *politeiawww) processBatchProposals(ctx context.Context, bp www.BatchProposals, u *user.User) (*www.BatchProposalsReply, error) {
	log.Tracef("processBatchProposals: %v", bp.Tokens)

	return nil, nil
}

func (p *politeiawww) processBatchVoteSummary(ctx context.Context, bvs www.BatchVoteSummary) (*www.BatchVoteSummaryReply, error) {
	log.Tracef("processBatchVoteSummary: %v", bvs.Tokens)

	// Get vote summaries
	vs, err := p.politeiad.TicketVoteSummaries(ctx, bvs.Tokens)
	if err != nil {
		return nil, err
	}

	// Prepare reply
	var bestBlock uint32
	summaries := make(map[string]www.VoteSummary, len(vs))
	for token, v := range vs {
		bestBlock = v.BestBlock
		results := make([]www.VoteOptionResult, len(v.Results))
		for k, r := range v.Results {
			results[k] = www.VoteOptionResult{
				VotesReceived: r.Votes,
				Option: www.VoteOption{
					Id:          r.ID,
					Description: r.Description,
					Bits:        r.VoteBit,
				},
			}
		}
		summaries[token] = www.VoteSummary{
			Status:           convertVoteStatusToWWW(v.Status),
			Type:             convertVoteTypeToWWW(v.Type),
			Approved:         v.Status == tkplugin.VoteStatusApproved,
			EligibleTickets:  v.EligibleTickets,
			Duration:         v.Duration,
			EndHeight:        uint64(v.EndBlockHeight),
			QuorumPercentage: v.QuorumPercentage,
			PassPercentage:   v.PassPercentage,
			Results:          results,
		}
	}

	return &www.BatchVoteSummaryReply{
		Summaries: summaries,
		BestBlock: uint64(bestBlock),
	}, nil
}

func convertVoteDetails(vd tkplugin.VoteDetails) (www.StartVote, www.StartVoteReply) {
	options := make([]www.VoteOption, 0, len(vd.Params.Options))
	for _, v := range vd.Params.Options {
		options = append(options, www.VoteOption{
			Id:          v.ID,
			Description: v.Description,
			Bits:        v.Bit,
		})
	}
	sv := www.StartVote{
		Vote: www.Vote{
			Token:            vd.Params.Token,
			Mask:             vd.Params.Mask,
			Duration:         vd.Params.Duration,
			QuorumPercentage: vd.Params.QuorumPercentage,
			PassPercentage:   vd.Params.PassPercentage,
			Options:          options,
		},
		PublicKey: vd.PublicKey,
		Signature: vd.Signature,
	}
	svr := www.StartVoteReply{
		StartBlockHeight: strconv.FormatUint(uint64(vd.StartBlockHeight), 10),
		StartBlockHash:   vd.StartBlockHash,
		EndHeight:        strconv.FormatUint(uint64(vd.EndBlockHeight), 10),
		EligibleTickets:  vd.EligibleTickets,
	}

	return sv, svr
}

func (p *politeiawww) processActiveVote(ctx context.Context) (*www.ActiveVoteReply, error) {
	log.Tracef("processActiveVotes")

	// Get a page of ongoing votes. This route is deprecated and should
	// be deleted before the time comes when more than a page of ongoing
	// votes is required.
	i := ticketvote.Inventory{}
	ir, err := p.politeiad.TicketVoteInventory(ctx, i)
	if err != nil {
		return nil, err
	}
	s := ticketvote.VoteStatuses[ticketvote.VoteStatusStarted]
	started := ir.Tokens[s]

	if len(started) == 0 {
		// No active votes
		return &www.ActiveVoteReply{
			Votes: []www.ProposalVoteTuple{},
		}, nil
	}

	// Get proposals
	reqs := make([]pdv1.RecordRequest, 0, len(started))
	for _, v := range started {
		reqs = append(reqs, pdv1.RecordRequest{
			Token: v,
			Filenames: []string{
				piplugin.FileNameProposalMetadata,
				tkplugin.FileNameVoteMetadata,
			},
		})
	}
	props, err := p.proposals(ctx, reqs)
	if err != nil {
		return nil, err
	}

	// Get vote details
	voteDetails := make(map[string]tkplugin.VoteDetails, len(started))
	for _, v := range started {
		dr, err := p.politeiad.TicketVoteDetails(ctx, v)
		if err != nil {
			return nil, err
		}
		if dr.Vote == nil {
			continue
		}
		voteDetails[v] = *dr.Vote
	}

	// Prepare reply
	votes := make([]www.ProposalVoteTuple, 0, len(started))
	for _, v := range started {
		var (
			proposal www.ProposalRecord
			sv       www.StartVote
			svr      www.StartVoteReply
			ok       bool
		)
		proposal, ok = props[v]
		if !ok {
			continue
		}
		vd, ok := voteDetails[v]
		if ok {
			sv, svr = convertVoteDetails(vd)
			votes = append(votes, www.ProposalVoteTuple{
				Proposal:       proposal,
				StartVote:      sv,
				StartVoteReply: svr,
			})
		}
	}

	return &www.ActiveVoteReply{
		Votes: votes,
	}, nil
}

func (p *politeiawww) processCastVotes(ctx context.Context, ballot *www.Ballot) (*www.BallotReply, error) {
	log.Tracef("processCastVotes")

	// Verify there is work to do
	if len(ballot.Votes) == 0 {
		return &www.BallotReply{
			Receipts: []www.CastVoteReply{},
		}, nil
	}

	// Prepare plugin command
	votes := make([]tkplugin.CastVote, 0, len(ballot.Votes))
	var token string
	for _, v := range ballot.Votes {
		token = v.Token
		votes = append(votes, tkplugin.CastVote{
			Token:     v.Token,
			Ticket:    v.Ticket,
			VoteBit:   v.VoteBit,
			Signature: v.Signature,
		})
	}
	cb := tkplugin.CastBallot{
		Ballot: votes,
	}

	// Send plugin command
	cbr, err := p.politeiad.TicketVoteCastBallot(ctx, token, cb)
	if err != nil {
		return nil, err
	}

	// Prepare reply
	receipts := make([]www.CastVoteReply, 0, len(cbr.Receipts))
	for k, v := range cbr.Receipts {
		receipts = append(receipts, www.CastVoteReply{
			ClientSignature: ballot.Votes[k].Signature,
			Signature:       v.Receipt,
			Error:           v.ErrorContext,
			ErrorStatus:     convertVoteErrorCodeToWWW(v.ErrorCode),
		})
	}

	return &www.BallotReply{
		Receipts: receipts,
	}, nil
}

func (p *politeiawww) processVoteResults(ctx context.Context, token string) (*www.VoteResultsReply, error) {
	log.Tracef("processVoteResults: %v", token)

	// Get vote details
	dr, err := p.politeiad.TicketVoteDetails(ctx, token)
	if err != nil {
		return nil, err
	}
	if dr.Vote == nil {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusWrongVoteStatus,
		}
	}
	sv, svr := convertVoteDetails(*dr.Vote)

	// Get cast votes
	rr, err := p.politeiad.TicketVoteResults(ctx, token)
	if err != nil {
		return nil, err
	}

	// Convert to www
	votes := make([]www.CastVote, 0, len(rr.Votes))
	for _, v := range rr.Votes {
		votes = append(votes, www.CastVote{
			Token:     v.Token,
			Ticket:    v.Ticket,
			VoteBit:   v.VoteBit,
			Signature: v.Signature,
		})
	}

	return &www.VoteResultsReply{
		StartVote:      sv,
		StartVoteReply: svr,
		CastVotes:      votes,
	}, nil
}

func (p *politeiawww) handleTokenInventory(w http.ResponseWriter, r *http.Request) {
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

func (p *politeiawww) handleAllVetted(w http.ResponseWriter, r *http.Request) {
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

	reply, err := p.processBatchVoteSummary(r.Context(), bvs)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleBatchVoteSummary: processBatchVoteSummary %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, reply)
}

func (p *politeiawww) handleActiveVote(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleActiveVote")

	avr, err := p.processActiveVote(r.Context())
	if err != nil {
		RespondWithError(w, r, 0,
			"handleActiveVote: processActiveVote %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, avr)
}

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

	avr, err := p.processCastVotes(r.Context(), &cv)
	if err != nil {
		RespondWithError(w, r, 0,
			"handleCastVotes: processCastVotes %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, avr)
}

func (p *politeiawww) handleVoteResults(w http.ResponseWriter, r *http.Request) {
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

// userMetadataDecode decodes and returns the UserMetadata from the provided
// metadata streams. If a UserMetadata is not found, nil is returned.
func userMetadataDecode(ms []v1.MetadataStream) (*umplugin.UserMetadata, error) {
	var userMD *umplugin.UserMetadata
	for _, v := range ms {
		if v.ID == umplugin.MDStreamIDUserMetadata {
			var um umplugin.UserMetadata
			err := json.Unmarshal([]byte(v.Payload), &um)
			if err != nil {
				return nil, err
			}
			userMD = &um
			break
		}
	}
	return userMD, nil
}

// userIDFromMetadataStreams searches for a UserMetadata and parses the user ID
// from it if found. An empty string is returned if no UserMetadata is found.
func userIDFromMetadataStreams(ms []pdv1.MetadataStream) string {
	um, err := userMetadataDecode(ms)
	if err != nil {
		return ""
	}
	if um == nil {
		return ""
	}
	return um.UserID
}

func convertStatusToWWW(status pdv1.RecordStatusT) www.PropStatusT {
	switch status {
	case pdv1.RecordStatusInvalid:
		return www.PropStatusInvalid
	case pdv1.RecordStatusPublic:
		return www.PropStatusPublic
	case pdv1.RecordStatusCensored:
		return www.PropStatusCensored
	case pdv1.RecordStatusArchived:
		return www.PropStatusAbandoned
	default:
		return www.PropStatusInvalid
	}
}

func convertRecordToProposal(r pdv1.Record) (*www.ProposalRecord, error) {
	// Decode metadata
	var (
		um       *umplugin.UserMetadata
		statuses = make([]umplugin.StatusChangeMetadata, 0, 16)
	)
	for _, v := range r.Metadata {
		if v.PluginID != umplugin.PluginID {
			continue
		}

		// This is a usermd plugin metadata stream
		switch v.ID {
		case umplugin.MDStreamIDUserMetadata:
			var m umplugin.UserMetadata
			err := json.Unmarshal([]byte(v.Payload), &m)
			if err != nil {
				return nil, err
			}
			um = &m
		case umplugin.MDStreamIDStatusChanges:
			d := json.NewDecoder(strings.NewReader(v.Payload))
			for {
				var sc umplugin.StatusChangeMetadata
				err := d.Decode(&sc)
				if errors.Is(err, io.EOF) {
					break
				} else if err != nil {
					return nil, err
				}
				statuses = append(statuses, sc)
			}
		}
	}

	// Convert files
	var (
		name, linkTo string
		linkBy       int64
		files        = make([]www.File, 0, len(r.Files))
	)
	for _, v := range r.Files {
		switch v.Name {
		case piplugin.FileNameProposalMetadata:
			b, err := base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				return nil, err
			}
			var pm piplugin.ProposalMetadata
			err = json.Unmarshal(b, &pm)
			if err != nil {
				return nil, err
			}
			name = pm.Name

		case tkplugin.FileNameVoteMetadata:
			b, err := base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				return nil, err
			}
			var vm tkplugin.VoteMetadata
			err = json.Unmarshal(b, &vm)
			if err != nil {
				return nil, err
			}
			linkTo = vm.LinkTo
			linkBy = vm.LinkBy

		default:
			files = append(files, www.File{
				Name:    v.Name,
				MIME:    v.MIME,
				Digest:  v.Digest,
				Payload: v.Payload,
			})
		}
	}

	// Setup user defined metadata
	pm := www.ProposalMetadata{
		Name:   name,
		LinkTo: linkTo,
		LinkBy: linkBy,
	}
	b, err := json.Marshal(pm)
	if err != nil {
		return nil, err
	}
	metadata := []www.Metadata{
		{
			Digest:  hex.EncodeToString(util.Digest(b)),
			Hint:    www.HintProposalMetadata,
			Payload: base64.StdEncoding.EncodeToString(b),
		},
	}

	var (
		publishedAt, censoredAt, abandonedAt int64
		changeMsg                            string
		changeMsgTimestamp                   int64
	)
	for _, v := range statuses {
		if v.Timestamp > changeMsgTimestamp {
			changeMsg = v.Reason
			changeMsgTimestamp = v.Timestamp
		}
		switch rcv1.RecordStatusT(v.Status) {
		case rcv1.RecordStatusPublic:
			publishedAt = v.Timestamp
		case rcv1.RecordStatusCensored:
			censoredAt = v.Timestamp
		case rcv1.RecordStatusArchived:
			abandonedAt = v.Timestamp
		}
	}

	return &www.ProposalRecord{
		Name:                pm.Name,
		State:               www.PropStateVetted,
		Status:              convertStatusToWWW(r.Status),
		Timestamp:           r.Timestamp,
		UserId:              um.UserID,
		Username:            "", // Intentionally omitted
		PublicKey:           um.PublicKey,
		Signature:           um.Signature,
		Version:             r.Version,
		StatusChangeMessage: changeMsg,
		PublishedAt:         publishedAt,
		CensoredAt:          censoredAt,
		AbandonedAt:         abandonedAt,
		LinkTo:              pm.LinkTo,
		LinkBy:              pm.LinkBy,
		LinkedFrom:          []string{},
		Files:               files,
		Metadata:            metadata,
		CensorshipRecord: www.CensorshipRecord{
			Token:     r.CensorshipRecord.Token,
			Merkle:    r.CensorshipRecord.Merkle,
			Signature: r.CensorshipRecord.Signature,
		},
	}, nil
}

func convertVoteStatusToWWW(status tkplugin.VoteStatusT) www.PropVoteStatusT {
	switch status {
	case tkplugin.VoteStatusInvalid:
		return www.PropVoteStatusInvalid
	case tkplugin.VoteStatusUnauthorized:
		return www.PropVoteStatusNotAuthorized
	case tkplugin.VoteStatusAuthorized:
		return www.PropVoteStatusAuthorized
	case tkplugin.VoteStatusStarted:
		return www.PropVoteStatusStarted
	case tkplugin.VoteStatusFinished:
		return www.PropVoteStatusFinished
	case tkplugin.VoteStatusApproved:
		return www.PropVoteStatusFinished
	case tkplugin.VoteStatusRejected:
		return www.PropVoteStatusFinished
	default:
		return www.PropVoteStatusInvalid
	}
}

func convertVoteTypeToWWW(t tkplugin.VoteT) www.VoteT {
	switch t {
	case tkplugin.VoteTypeInvalid:
		return www.VoteTypeInvalid
	case tkplugin.VoteTypeStandard:
		return www.VoteTypeStandard
	case tkplugin.VoteTypeRunoff:
		return www.VoteTypeRunoff
	default:
		return www.VoteTypeInvalid
	}
}

func convertVoteErrorCodeToWWW(e tkplugin.VoteErrorT) decredplugin.ErrorStatusT {
	switch e {
	case tkplugin.VoteErrorInvalid:
		return decredplugin.ErrorStatusInvalid
	case tkplugin.VoteErrorInternalError:
		return decredplugin.ErrorStatusInternalError
	case tkplugin.VoteErrorRecordNotFound:
		return decredplugin.ErrorStatusProposalNotFound
	case tkplugin.VoteErrorMultipleRecordVotes:
		// There is not decredplugin error code for this
	case tkplugin.VoteErrorVoteStatusInvalid:
		return decredplugin.ErrorStatusVoteHasEnded
	case tkplugin.VoteErrorVoteBitInvalid:
		return decredplugin.ErrorStatusInvalidVoteBit
	case tkplugin.VoteErrorSignatureInvalid:
		// There is not decredplugin error code for this
	case tkplugin.VoteErrorTicketNotEligible:
		return decredplugin.ErrorStatusIneligibleTicket
	case tkplugin.VoteErrorTicketAlreadyVoted:
		return decredplugin.ErrorStatusDuplicateVote
	default:
	}
	return decredplugin.ErrorStatusInternalError
}
