// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/decred/politeia/decredplugin"
	pd "github.com/decred/politeia/politeiad/api/v1"
	piplugin "github.com/decred/politeia/politeiad/plugins/pi"
	ticketvote "github.com/decred/politeia/politeiad/plugins/ticketvote"
	pi "github.com/decred/politeia/politeiawww/api/pi/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/sessions"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/decred/politeia/util"
	"github.com/gorilla/mux"
)

func convertStateToWWW(state pi.PropStateT) www.PropStateT {
	switch state {
	case pi.PropStateInvalid:
		return www.PropStateInvalid
	case pi.PropStateUnvetted:
		return www.PropStateUnvetted
	case pi.PropStateVetted:
		return www.PropStateVetted
	default:
		return www.PropStateInvalid
	}
}

func convertStatusToWWW(status pi.PropStatusT) www.PropStatusT {
	switch status {
	case pi.PropStatusInvalid:
		return www.PropStatusInvalid
	case pi.PropStatusPublic:
		return www.PropStatusPublic
	case pi.PropStatusCensored:
		return www.PropStatusCensored
	case pi.PropStatusAbandoned:
		return www.PropStatusAbandoned
	default:
		return www.PropStatusInvalid
	}
}

func convertProposalToWWW(pr *pi.ProposalRecord) (*www.ProposalRecord, error) {
	// Decode metadata
	var pm *piplugin.ProposalMetadata
	for _, v := range pr.Metadata {
		if v.Hint == pi.HintProposalMetadata {
			b, err := base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				return nil, err
			}
			var pm pi.ProposalMetadata
			err = json.Unmarshal(b, &pm)
			if err != nil {
				return nil, err
			}
		}
	}

	// Convert files
	files := make([]www.File, 0, len(pr.Files))
	for _, f := range pr.Files {
		files = append(files, www.File{
			Name:    f.Name,
			MIME:    f.MIME,
			Digest:  f.Digest,
			Payload: f.Payload,
		})
	}

	// Convert metadata
	metadata := make([]www.Metadata, 0, len(pr.Metadata))
	for _, md := range pr.Metadata {
		metadata = append(metadata, www.Metadata{
			Digest:  md.Digest,
			Hint:    md.Hint,
			Payload: md.Payload,
		})
	}

	var (
		publishedAt, censoredAt, abandonedAt int64
		changeMsg                            string
		changeMsgTimestamp                   int64
	)
	for _, v := range pr.Statuses {
		if v.Timestamp > changeMsgTimestamp {
			changeMsg = v.Reason
			changeMsgTimestamp = v.Timestamp
		}
		switch v.Status {
		case pi.PropStatusPublic:
			publishedAt = v.Timestamp
		case pi.PropStatusCensored:
			censoredAt = v.Timestamp
		case pi.PropStatusAbandoned:
			abandonedAt = v.Timestamp
		}
	}

	return &www.ProposalRecord{
		Name:                pm.Name,
		State:               convertStateToWWW(pr.State),
		Status:              convertStatusToWWW(pr.Status),
		Timestamp:           pr.Timestamp,
		UserId:              pr.UserID,
		Username:            pr.Username,
		PublicKey:           pr.PublicKey,
		Signature:           pr.Signature,
		Version:             pr.Version,
		StatusChangeMessage: changeMsg,
		PublishedAt:         publishedAt,
		CensoredAt:          censoredAt,
		AbandonedAt:         abandonedAt,
		Files:               files,
		Metadata:            metadata,
		CensorshipRecord: www.CensorshipRecord{
			Token:     pr.CensorshipRecord.Token,
			Merkle:    pr.CensorshipRecord.Merkle,
			Signature: pr.CensorshipRecord.Signature,
		},
	}, nil
}

func convertVoteStatusToWWW(status ticketvote.VoteStatusT) www.PropVoteStatusT {
	switch status {
	case ticketvote.VoteStatusInvalid:
		return www.PropVoteStatusInvalid
	case ticketvote.VoteStatusUnauthorized:
		return www.PropVoteStatusNotAuthorized
	case ticketvote.VoteStatusAuthorized:
		return www.PropVoteStatusAuthorized
	case ticketvote.VoteStatusStarted:
		return www.PropVoteStatusStarted
	case ticketvote.VoteStatusFinished:
		return www.PropVoteStatusFinished
	default:
		return www.PropVoteStatusInvalid
	}
}

func convertVoteTypeToWWW(t ticketvote.VoteT) www.VoteT {
	switch t {
	case ticketvote.VoteTypeInvalid:
		return www.VoteTypeInvalid
	case ticketvote.VoteTypeStandard:
		return www.VoteTypeStandard
	case ticketvote.VoteTypeRunoff:
		return www.VoteTypeRunoff
	default:
		return www.VoteTypeInvalid
	}
}

func convertVoteErrorCodeToWWW(errcode ticketvote.VoteErrorT) decredplugin.ErrorStatusT {
	switch errcode {
	case ticketvote.VoteErrorInvalid:
		return decredplugin.ErrorStatusInvalid
	case ticketvote.VoteErrorInternalError:
		return decredplugin.ErrorStatusInternalError
	case ticketvote.VoteErrorRecordNotFound:
		return decredplugin.ErrorStatusProposalNotFound
	case ticketvote.VoteErrorVoteBitInvalid:
		return decredplugin.ErrorStatusInvalidVoteBit
	case ticketvote.VoteErrorVoteStatusInvalid:
		return decredplugin.ErrorStatusVoteHasEnded
	case ticketvote.VoteErrorTicketAlreadyVoted:
		return decredplugin.ErrorStatusDuplicateVote
	case ticketvote.VoteErrorTicketNotEligible:
		return decredplugin.ErrorStatusIneligibleTicket
	default:
		return decredplugin.ErrorStatusInternalError
	}
}

func (p *politeiawww) processProposalDetails(ctx context.Context, pd www.ProposalsDetails, u *user.User) (*www.ProposalDetailsReply, error) {
	log.Tracef("processProposalDetails: %v", pd.Token)

	pr, err := p.proposalRecord(ctx, pi.PropStateVetted, pd.Token, pd.Version)
	if err != nil {
		return nil, err
	}
	pw, err := convertProposalToWWW(pr)
	if err != nil {
		return nil, err
	}

	return &www.ProposalDetailsReply{
		Proposal: *pw,
	}, nil
}

func (p *politeiawww) processAllVetted(ctx context.Context, gav www.GetAllVetted) (*www.GetAllVettedReply, error) {
	// TODO
	return nil, nil
}

func (p *politeiawww) processBatchProposals(ctx context.Context, bp www.BatchProposals, u *user.User) (*www.BatchProposalsReply, error) {
	log.Tracef("processBatchProposals: %v", bp.Tokens)

	// Setup requests
	prs := make([]pi.ProposalRequest, 0, len(bp.Tokens))
	for _, t := range bp.Tokens {
		prs = append(prs, pi.ProposalRequest{
			Token: t,
		})
	}

	// Get proposals
	props, err := p.proposalRecords(ctx, pi.PropStateVetted, prs, false)
	if err != nil {
		return nil, err
	}

	// Prepare reply
	propsw := make([]www.ProposalRecord, 0, len(bp.Tokens))
	for _, pr := range props {
		propw, err := convertProposalToWWW(&pr)
		if err != nil {
			return nil, err
		}
		propsw = append(propsw, *propw)
	}

	return &www.BatchProposalsReply{
		Proposals: propsw,
	}, nil
}

func (p *politeiawww) processVoteResults(ctx context.Context, token string) (*www.VoteResultsReply, error) {
	log.Tracef("processVoteResults: %v", token)

	// Get vote details
	vd, err := p.voteDetails(ctx, token)
	if err != nil {
		return nil, err
	}

	// Convert to www
	startHeight := strconv.FormatUint(uint64(vd.Vote.StartBlockHeight), 10)
	endHeight := strconv.FormatUint(uint64(vd.Vote.EndBlockHeight), 10)
	options := make([]www.VoteOption, 0, len(vd.Vote.Params.Options))
	for _, o := range vd.Vote.Params.Options {
		options = append(options, www.VoteOption{
			Id:          o.ID,
			Description: o.Description,
			Bits:        o.Bit,
		})
	}

	// Get cast votes
	rr, err := p.voteResults(ctx, token)
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
		StartVote: www.StartVote{
			PublicKey: vd.Vote.PublicKey,
			Signature: vd.Vote.Signature,
			Vote: www.Vote{
				Token:            vd.Vote.Params.Token,
				Mask:             vd.Vote.Params.Mask,
				Duration:         vd.Vote.Params.Duration,
				QuorumPercentage: vd.Vote.Params.QuorumPercentage,
				PassPercentage:   vd.Vote.Params.PassPercentage,
				Options:          options,
			},
		},
		StartVoteReply: www.StartVoteReply{
			StartBlockHeight: startHeight,
			StartBlockHash:   vd.Vote.StartBlockHash,
			EndHeight:        endHeight,
			EligibleTickets:  vd.Vote.EligibleTickets,
		},
		CastVotes: votes,
	}, nil
}

func (p *politeiawww) processBatchVoteSummary(ctx context.Context, bvs www.BatchVoteSummary) (*www.BatchVoteSummaryReply, error) {
	log.Tracef("processBatchVoteSummary: %v", bvs.Tokens)

	// TODO
	var bestBlock uint32
	var vs []ticketvote.VoteSummary

	// Prepare reply
	summaries := make(map[string]www.VoteSummary, len(vs))
	for _, v := range vs {
		results := make([]www.VoteOptionResult, 0, len(v.Results))
		for _, r := range v.Results {
			results = append(results, www.VoteOptionResult{
				VotesReceived: r.Votes,
				Option: www.VoteOption{
					Id:          r.ID,
					Description: r.Description,
					Bits:        r.VoteBit,
				},
			})
		}
		// TODO
		var token string
		summaries[token] = www.VoteSummary{
			Status:           convertVoteStatusToWWW(v.Status),
			Type:             convertVoteTypeToWWW(v.Type),
			Approved:         v.Approved,
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

func (p *politeiawww) processActiveVote(ctx context.Context) (*www.ActiveVoteReply, error) {
	// TODO
	return nil, nil
}

func (p *politeiawww) processCastVotes(ctx context.Context, ballot *www.Ballot) (*www.BallotReply, error) {
	log.Tracef("processCastVotes")

	// Prepare plugin command
	votes := make([]ticketvote.CastVote, 0, len(ballot.Votes))
	for _, vote := range ballot.Votes {
		votes = append(votes, ticketvote.CastVote{
			Token:     vote.Ticket,
			Ticket:    vote.Ticket,
			VoteBit:   vote.VoteBit,
			Signature: vote.Signature,
		})
	}
	cb := ticketvote.CastBallot{
		Ballot: votes,
	}
	cbr, err := p.castBallot(ctx, cb)
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

func (p *politeiawww) processTokenInventory(ctx context.Context, isAdmin bool) (*www.TokenInventoryReply, error) {
	log.Tracef("processTokenInventory")

	// Get record inventory
	ir, err := p.politeiad.InventoryByStatus(ctx)
	if err != nil {
		return nil, err
	}

	// Get vote inventory
	vir, err := p.piVoteInventory(ctx)
	if err != nil {
		return nil, err
	}

	// Unpack record inventory
	var (
		archived        = ir.Vetted[pd.RecordStatusArchived]
		unvetted        = ir.Unvetted[pd.RecordStatusNotReviewed]
		unvettedChanges = ir.Unvetted[pd.RecordStatusUnreviewedChanges]
		unreviewed      = append(unvetted, unvettedChanges...)
		censored        = ir.Unvetted[pd.RecordStatusCensored]
	)

	// Only return unvetted tokens to admins
	if isAdmin {
		unreviewed = nil
		censored = nil
	}

	return &www.TokenInventoryReply{
		Unreviewed: unreviewed,
		Censored:   censored,
		Pre:        append(vir.Unauthorized, vir.Authorized...),
		Active:     vir.Started,
		Approved:   vir.Approved,
		Rejected:   vir.Rejected,
		Abandoned:  archived,
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
