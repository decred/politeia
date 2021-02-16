// Copyright (c) 2017-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	pdv1 "github.com/decred/politeia/politeiad/api/v1"
	v1 "github.com/decred/politeia/politeiad/api/v1"
	piplugin "github.com/decred/politeia/politeiad/plugins/pi"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	tvplugin "github.com/decred/politeia/politeiad/plugins/ticketvote"
	umplugin "github.com/decred/politeia/politeiad/plugins/usermd"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/sessions"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/decred/politeia/util"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

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
		statusUnauth   = tvplugin.VoteStatuses[tvplugin.VoteStatusUnauthorized]
		statusAuth     = tvplugin.VoteStatuses[tvplugin.VoteStatusAuthorized]
		statusStarted  = tvplugin.VoteStatuses[tvplugin.VoteStatusStarted]
		statusApproved = tvplugin.VoteStatuses[tvplugin.VoteStatusApproved]
		statusRejected = tvplugin.VoteStatuses[tvplugin.VoteStatusRejected]

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
		unreviewed = nil
		censored = nil
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

func (p *politeiawww) processVoteResults(ctx context.Context, token string) (*www.VoteResultsReply, error) {
	log.Tracef("processVoteResults: %v", token)

	// TODO Get vote details
	var vd tvplugin.VoteDetails

	// Convert to www
	startHeight := strconv.FormatUint(uint64(vd.StartBlockHeight), 10)
	endHeight := strconv.FormatUint(uint64(vd.EndBlockHeight), 10)
	options := make([]www.VoteOption, 0, len(vd.Params.Options))
	for _, o := range vd.Params.Options {
		options = append(options, www.VoteOption{
			Id:          o.ID,
			Description: o.Description,
			Bits:        o.Bit,
		})
	}

	// TODO Get cast votes
	var rr tvplugin.ResultsReply

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
			PublicKey: vd.PublicKey,
			Signature: vd.Signature,
			Vote: www.Vote{
				Token:            vd.Params.Token,
				Mask:             vd.Params.Mask,
				Duration:         vd.Params.Duration,
				QuorumPercentage: vd.Params.QuorumPercentage,
				PassPercentage:   vd.Params.PassPercentage,
				Options:          options,
			},
		},
		StartVoteReply: www.StartVoteReply{
			StartBlockHeight: startHeight,
			StartBlockHash:   vd.StartBlockHash,
			EndHeight:        endHeight,
			EligibleTickets:  vd.EligibleTickets,
		},
		CastVotes: votes,
	}, nil
}

func (p *politeiawww) processBatchVoteSummary(ctx context.Context, bvs www.BatchVoteSummary) (*www.BatchVoteSummaryReply, error) {
	log.Tracef("processBatchVoteSummary: %v", bvs.Tokens)

	// TODO
	var bestBlock uint32
	var vs []tvplugin.SummaryReply

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
			// Status: convertVoteStatusToWWW(v.Status),
			// Type:   convertVoteTypeToWWW(v.Type),
			// Approved:         v.Approved,
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
	votes := make([]tvplugin.CastVote, 0, len(ballot.Votes))
	for _, vote := range ballot.Votes {
		votes = append(votes, tvplugin.CastVote{
			Token:     vote.Ticket,
			Ticket:    vote.Ticket,
			VoteBit:   vote.VoteBit,
			Signature: vote.Signature,
		})
	}
	cb := tvplugin.CastBallot{
		Ballot: votes,
	}
	// TODO
	_ = cb
	var cbr tvplugin.CastBallotReply

	// Prepare reply
	receipts := make([]www.CastVoteReply, 0, len(cbr.Receipts))
	for k, v := range cbr.Receipts {
		receipts = append(receipts, www.CastVoteReply{
			ClientSignature: ballot.Votes[k].Signature,
			Signature:       v.Receipt,
			Error:           v.ErrorContext,
			// ErrorStatus:     convertVoteErrorCodeToWWW(v.ErrorCode),
		})
	}

	return &www.BallotReply{
		Receipts: receipts,
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

// TODO convertRecordToProposal
func convertRecordToProposal(r pdv1.Record) (*www.ProposalRecord, error) {
	// Decode metadata
	var um *umplugin.UserMetadata
	for _, v := range r.Metadata {
		switch v.ID {
		case umplugin.MDStreamIDUserMetadata:
		}
	}

	// Convert files
	var (
		pm       *piplugin.ProposalMetadata
		vm       *tvplugin.VoteMetadata
		files    = make([]www.File, 0, len(r.Files))
		metadata = make([]www.Metadata, 0, len(r.Files))
	)
	for _, v := range r.Files {
		switch v.Name {
		case piplugin.FileNameProposalMetadata:
		case tvplugin.FileNameVoteMetadata:
		default:
			files = append(files, www.File{
				Name:    v.Name,
				MIME:    v.MIME,
				Digest:  v.Digest,
				Payload: v.Payload,
			})
		}
	}

	/*
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
			case piv1.PropStatusPublic:
				publishedAt = v.Timestamp
			case piv1.PropStatusCensored:
				censoredAt = v.Timestamp
			case piv1.PropStatusAbandoned:
				abandonedAt = v.Timestamp
			}
		}
	*/

	return &www.ProposalRecord{
		Name:      pm.Name,
		State:     www.PropStateVetted,
		Status:    convertStatusToWWW(r.Status),
		Timestamp: r.Timestamp,
		UserId:    um.UserID,
		Username:  "", // Intentionally omitted
		PublicKey: um.PublicKey,
		Signature: um.Signature,
		Version:   r.Version,
		// StatusChangeMessage: changeMsg,
		// PublishedAt:         publishedAt,
		// CensoredAt:          censoredAt,
		// AbandonedAt:         abandonedAt,
		LinkTo: vm.LinkTo,
		LinkBy: vm.LinkBy,
		// LinkedFrom: submissions,
		Files:    files,
		Metadata: metadata,
		CensorshipRecord: www.CensorshipRecord{
			Token:     r.CensorshipRecord.Token,
			Merkle:    r.CensorshipRecord.Merkle,
			Signature: r.CensorshipRecord.Signature,
		},
	}, nil
}

/*
func convertVoteStatusToWWW(status tvplugin.VoteStatusT) www.PropVoteStatusT {
	switch status {
	case tvplugin.VoteStatusInvalid:
		return www.PropVoteStatusInvalid
	case tvplugin.VoteStatusUnauthorized:
		return www.PropVoteStatusNotAuthorized
	case tvplugin.VoteStatusAuthorized:
		return www.PropVoteStatusAuthorized
	case tvplugin.VoteStatusStarted:
		return www.PropVoteStatusStarted
	case tvplugin.VoteStatusFinished:
		return www.PropVoteStatusFinished
	default:
		return www.PropVoteStatusInvalid
	}
}

func convertVoteTypeToWWW(t tvplugin.VoteT) www.VoteT {
	switch t {
	case tvplugin.VoteTypeInvalid:
		return www.VoteTypeInvalid
	case tvplugin.VoteTypeStandard:
		return www.VoteTypeStandard
	case tvplugin.VoteTypeRunoff:
		return www.VoteTypeRunoff
	default:
		return www.VoteTypeInvalid
	}
}

func convertVoteErrorCodeToWWW(errcode tvplugin.VoteErrorT) decredplugin.ErrorStatusT {
	switch errcode {
	case tvplugin.VoteErrorInvalid:
		return decredplugin.ErrorStatusInvalid
	case tvplugin.VoteErrorInternalError:
		return decredplugin.ErrorStatusInternalError
	case tvplugin.VoteErrorRecordNotFound:
		return decredplugin.ErrorStatusProposalNotFound
	case tvplugin.VoteErrorVoteBitInvalid:
		return decredplugin.ErrorStatusInvalidVoteBit
	case tvplugin.VoteErrorVoteStatusInvalid:
		return decredplugin.ErrorStatusVoteHasEnded
	case tvplugin.VoteErrorTicketAlreadyVoted:
		return decredplugin.ErrorStatusDuplicateVote
	case tvplugin.VoteErrorTicketNotEligible:
		return decredplugin.ErrorStatusIneligibleTicket
	default:
		return decredplugin.ErrorStatusInternalError
	}
}
*/
