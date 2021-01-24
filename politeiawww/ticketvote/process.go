// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import (
	"context"

	pdv1 "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	tkv1 "github.com/decred/politeia/politeiawww/api/ticketvote/v1"
	"github.com/decred/politeia/politeiawww/user"
)

func (t *TicketVote) processAuthorize(ctx context.Context, a tkv1.Authorize, u user.User) (*tkv1.AuthorizeReply, error) {
	log.Tracef("processAuthorize: %v", a.Token)

	// Verify user signed with their active identity
	if u.PublicKey() != a.PublicKey {
		return nil, tkv1.UserErrorReply{
			ErrorCode:    tkv1.ErrorCodePublicKeyInvalid,
			ErrorContext: "not active identity",
		}
	}

	// Verify user is the record author
	authorID, err := t.politeiad.Author(ctx, pdv1.RecordStateVetted, a.Token)
	if err != nil {
		return nil, err
	}
	if u.ID.String() != authorID {
		return nil, tkv1.UserErrorReply{
			ErrorCode:    tkv1.ErrorCodeUnauthorized,
			ErrorContext: "user is not record author",
		}
	}

	// Send plugin command
	ta := ticketvote.Authorize{
		Token:     a.Token,
		Version:   a.Version,
		Action:    ticketvote.AuthActionT(a.Action),
		PublicKey: a.PublicKey,
		Signature: a.Signature,
	}
	tar, err := t.politeiad.TicketVoteAuthorize(ctx, ta)
	if err != nil {
		return nil, err
	}

	// Emit event
	t.events.Emit(EventTypeAuthorize,
		EventAuthorize{
			Auth: a,
			User: u,
		})

	return &tkv1.AuthorizeReply{
		Timestamp: tar.Timestamp,
		Receipt:   tar.Receipt,
	}, nil
}

func (t *TicketVote) processStart(ctx context.Context, s tkv1.Start, u user.User) (*tkv1.StartReply, error) {
	log.Tracef("processStart: %v", len(s.Starts))

	// Verify user signed with their active identity
	for _, v := range s.Starts {
		if u.PublicKey() != v.PublicKey {
			return nil, tkv1.UserErrorReply{
				ErrorCode:    tkv1.ErrorCodePublicKeyInvalid,
				ErrorContext: "not active identity",
			}
		}
	}

	// Get token from start details
	var token string
	for _, v := range s.Starts {
		switch v.Params.Type {
		case tkv1.VoteTypeRunoff:
			// This is a runoff vote. Execute the plugin command on the
			// parent record.
			token = v.Params.Parent
		case tkv1.VoteTypeStandard:
			// This is a standard vote. Execute the plugin command on the
			// record specified in the vote params.
			token = v.Params.Token
		}
	}

	// Send plugin command
	ts := convertStartToPlugin(s)
	tsr, err := t.politeiad.TicketVoteStart(ctx, token, ts)
	if err != nil {
		return nil, err
	}

	// Emit notification for each start
	t.events.Emit(EventTypeStart,
		EventStart{
			Start: s,
			User:  u,
		})

	return &tkv1.StartReply{
		StartBlockHeight: tsr.StartBlockHeight,
		StartBlockHash:   tsr.StartBlockHash,
		EndBlockHeight:   tsr.EndBlockHeight,
		EligibleTickets:  tsr.EligibleTickets,
	}, nil
}

func (t *TicketVote) processCastBallot(ctx context.Context, cb tkv1.CastBallot) (*tkv1.CastBallotReply, error) {
	log.Tracef("processCastBallot")

	// Get token from one of the votes
	var token string
	for _, v := range cb.Votes {
		token = v.Token
		break
	}

	// Send plugin command
	tcb := ticketvote.CastBallot{
		Ballot: convertCastVotesToPlugin(cb.Votes),
	}
	tcbr, err := t.politeiad.TicketVoteCastBallot(ctx, token, tcb)
	if err != nil {
		return nil, err
	}

	return &tkv1.CastBallotReply{
		Receipts: convertCastVoteRepliesToV1(tcbr.Receipts),
	}, nil
}

func (t *TicketVote) processDetails(ctx context.Context, d tkv1.Details) (*tkv1.DetailsReply, error) {
	log.Tracef("processsDetails: %v", d.Token)

	tdr, err := t.politeiad.TicketVoteDetails(ctx, d.Token)
	if err != nil {
		return nil, err
	}
	var vote *tkv1.VoteDetails
	if tdr.Vote != nil {
		vd := convertVoteDetailsToV1(*tdr.Vote)
		vote = &vd
	}

	return &tkv1.DetailsReply{
		Auths: convertAuthDetailsToV1(tdr.Auths),
		Vote:  vote,
	}, nil
}

func (t *TicketVote) processResults(ctx context.Context, r tkv1.Results) (*tkv1.ResultsReply, error) {
	log.Tracef("processResults: %v", r.Token)

	return nil, nil
}

func (t *TicketVote) processSummaries(ctx context.Context, s tkv1.Summaries) (*tkv1.SummariesReply, error) {
	log.Tracef("processSummaries: %v", s.Tokens)

	return nil, nil
}

func (t *TicketVote) processLinkedFrom(ctx context.Context, lf tkv1.LinkedFrom) (*tkv1.LinkedFromReply, error) {
	log.Tracef("processLinkedFrom: %v", lf.Tokens)

	return nil, nil
}

func (t *TicketVote) processInventory(ctx context.Context) (*tkv1.InventoryReply, error) {
	log.Tracef("processInventory")

	return nil, nil
}

func (t *TicketVote) processTimestamps(ctx context.Context, ts tkv1.Timestamps) (*tkv1.TimestampsReply, error) {
	log.Tracef("processTimestamps: %v", ts.Token)

	// TODO Send plugin command
	var r ticketvote.TimestampsReply

	// Prepare reply
	var (
		auths = make([]tkv1.Timestamp, 0, len(r.Auths))
		votes = make(map[string]tkv1.Timestamp, len(r.Votes))

		details = convertTimestampToV1(r.Details)
	)
	for _, v := range r.Auths {
		auths = append(auths, convertTimestampToV1(v))
	}
	for k, v := range r.Votes {
		votes[k] = convertTimestampToV1(v)
	}

	return &tkv1.TimestampsReply{
		Auths:   auths,
		Details: details,
		Votes:   votes,
	}, nil
}

func convertVoteTypeToPlugin(t tkv1.VoteT) ticketvote.VoteT {
	switch t {
	case tkv1.VoteTypeStandard:
		return ticketvote.VoteTypeStandard
	case tkv1.VoteTypeRunoff:
		return ticketvote.VoteTypeRunoff
	}
	return ticketvote.VoteTypeInvalid
}

func convertVoteTypeToV1(t ticketvote.VoteT) tkv1.VoteT {
	switch t {
	case ticketvote.VoteTypeStandard:
		return tkv1.VoteTypeStandard
	case ticketvote.VoteTypeRunoff:
		return tkv1.VoteTypeRunoff
	}
	return tkv1.VoteTypeInvalid

}

func convertVoteParamsToPlugin(v tkv1.VoteParams) ticketvote.VoteParams {
	tv := ticketvote.VoteParams{
		Token:            v.Token,
		Version:          v.Version,
		Type:             convertVoteTypeToPlugin(v.Type),
		Mask:             v.Mask,
		Duration:         v.Duration,
		QuorumPercentage: v.QuorumPercentage,
		PassPercentage:   v.PassPercentage,
		Parent:           v.Parent,
	}
	// Convert vote options
	vo := make([]ticketvote.VoteOption, 0, len(v.Options))
	for _, vi := range v.Options {
		vo = append(vo, ticketvote.VoteOption{
			ID:          vi.ID,
			Description: vi.Description,
			Bit:         vi.Bit,
		})
	}
	tv.Options = vo

	return tv
}

func convertVoteParamsToV1(v ticketvote.VoteParams) tkv1.VoteParams {
	vp := tkv1.VoteParams{
		Token:            v.Token,
		Version:          v.Version,
		Type:             convertVoteTypeToV1(v.Type),
		Mask:             v.Mask,
		Duration:         v.Duration,
		QuorumPercentage: v.QuorumPercentage,
		PassPercentage:   v.PassPercentage,
	}
	vo := make([]tkv1.VoteOption, 0, len(v.Options))
	for _, o := range v.Options {
		vo = append(vo, tkv1.VoteOption{
			ID:          o.ID,
			Description: o.Description,
			Bit:         o.Bit,
		})
	}
	vp.Options = vo

	return vp
}

func convertStartDetailsToPlugin(sd tkv1.StartDetails) ticketvote.StartDetails {
	return ticketvote.StartDetails{
		Params:    convertVoteParamsToPlugin(sd.Params),
		PublicKey: sd.PublicKey,
		Signature: sd.Signature,
	}
}

func convertStartToPlugin(vs tkv1.Start) ticketvote.Start {
	starts := make([]ticketvote.StartDetails, 0, len(vs.Starts))
	for _, v := range vs.Starts {
		starts = append(starts, convertStartDetailsToPlugin(v))
	}
	return ticketvote.Start{
		Starts: starts,
	}
}

func convertCastVotesToPlugin(votes []tkv1.CastVote) []ticketvote.CastVote {
	cv := make([]ticketvote.CastVote, 0, len(votes))
	for _, v := range votes {
		cv = append(cv, ticketvote.CastVote{
			Token:     v.Token,
			Ticket:    v.Ticket,
			VoteBit:   v.VoteBit,
			Signature: v.Signature,
		})
	}
	return cv
}

func convertVoteErrorToV1(e ticketvote.VoteErrorT) tkv1.VoteErrorT {
	switch e {
	case ticketvote.VoteErrorInvalid:
		return tkv1.VoteErrorInvalid
	case ticketvote.VoteErrorInternalError:
		return tkv1.VoteErrorInternalError
	case ticketvote.VoteErrorRecordNotFound:
		return tkv1.VoteErrorRecordNotFound
	case ticketvote.VoteErrorVoteBitInvalid:
		return tkv1.VoteErrorVoteBitInvalid
	case ticketvote.VoteErrorVoteStatusInvalid:
		return tkv1.VoteErrorVoteStatusInvalid
	case ticketvote.VoteErrorTicketAlreadyVoted:
		return tkv1.VoteErrorTicketAlreadyVoted
	case ticketvote.VoteErrorTicketNotEligible:
		return tkv1.VoteErrorTicketNotEligible
	default:
		return tkv1.VoteErrorInternalError
	}
}

func convertCastVoteRepliesToV1(replies []ticketvote.CastVoteReply) []tkv1.CastVoteReply {
	r := make([]tkv1.CastVoteReply, 0, len(replies))
	for _, v := range replies {
		r = append(r, tkv1.CastVoteReply{
			Ticket:       v.Ticket,
			Receipt:      v.Receipt,
			ErrorCode:    convertVoteErrorToV1(v.ErrorCode),
			ErrorContext: v.ErrorContext,
		})
	}
	return r
}

func convertVoteDetailsToV1(vd ticketvote.VoteDetails) tkv1.VoteDetails {
	return tkv1.VoteDetails{
		Params:           convertVoteParamsToV1(vd.Params),
		PublicKey:        vd.PublicKey,
		Signature:        vd.Signature,
		StartBlockHeight: vd.StartBlockHeight,
		StartBlockHash:   vd.StartBlockHash,
		EndBlockHeight:   vd.EndBlockHeight,
		EligibleTickets:  vd.EligibleTickets,
	}
}

func convertAuthDetailsToV1(auths []ticketvote.AuthDetails) []tkv1.AuthDetails {
	a := make([]tkv1.AuthDetails, 0, len(auths))
	for _, v := range auths {
		a = append(a, tkv1.AuthDetails{
			Token:     v.Token,
			Version:   v.Version,
			Action:    v.Action,
			PublicKey: v.PublicKey,
			Signature: v.Signature,
			Timestamp: v.Timestamp,
			Receipt:   v.Receipt,
		})
	}
	return a
}

/*
func convertCastVoteDetails(votes []ticketvote.CastVoteDetails) []tkv1.CastVoteDetails {
	vs := make([]tkv1.CastVoteDetails, 0, len(votes))
	for _, v := range votes {
		vs = append(vs, tkv1.CastVoteDetails{
			Token:     v.Token,
			Ticket:    v.Ticket,
			VoteBit:   v.VoteBit,
			Signature: v.Signature,
			Receipt:   v.Receipt,
		})
	}
	return vs
}

func convertVoteStatus(s ticketvote.VoteStatusT) tkv1.VoteStatusT {
	switch s {
	case ticketvote.VoteStatusInvalid:
		return tkv1.VoteStatusInvalid
	case ticketvote.VoteStatusUnauthorized:
		return tkv1.VoteStatusUnauthorized
	case ticketvote.VoteStatusAuthorized:
		return tkv1.VoteStatusAuthorized
	case ticketvote.VoteStatusStarted:
		return tkv1.VoteStatusStarted
	case ticketvote.VoteStatusFinished:
		return tkv1.VoteStatusFinished
	default:
		return tkv1.VoteStatusInvalid
	}
}

func convertSummary(s ticketvote.VoteSummary) tkv1.Summary {
	results := make([]tkv1.VoteResult, 0, len(s.Results))
	for _, v := range s.Results {
		results = append(results, tkv1.VoteResult{
			ID:          v.ID,
			Description: v.Description,
			VoteBit:     v.VoteBit,
			Votes:       v.Votes,
		})
	}
	return tkv1.Summary{
		Type:             convertVoteType(s.Type),
		Status:           convertVoteStatus(s.Status),
		Duration:         s.Duration,
		StartBlockHeight: s.StartBlockHeight,
		StartBlockHash:   s.StartBlockHash,
		EndBlockHeight:   s.EndBlockHeight,
		EligibleTickets:  s.EligibleTickets,
		QuorumPercentage: s.QuorumPercentage,
		PassPercentage:   s.PassPercentage,
		Results:          results,
		Approved:         s.Approved,
	}
}
*/

func convertProofToV1(p ticketvote.Proof) tkv1.Proof {
	return tkv1.Proof{
		Type:       p.Type,
		Digest:     p.Digest,
		MerkleRoot: p.MerkleRoot,
		MerklePath: p.MerklePath,
		ExtraData:  p.ExtraData,
	}
}

func convertTimestampToV1(t ticketvote.Timestamp) tkv1.Timestamp {
	proofs := make([]tkv1.Proof, 0, len(t.Proofs))
	for _, v := range t.Proofs {
		proofs = append(proofs, convertProofToV1(v))
	}
	return tkv1.Timestamp{
		Data:       t.Data,
		Digest:     t.Digest,
		TxID:       t.TxID,
		MerkleRoot: t.MerkleRoot,
		Proofs:     proofs,
	}
}
