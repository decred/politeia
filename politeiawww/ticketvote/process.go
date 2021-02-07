// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import (
	"context"

	pdv1 "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	v1 "github.com/decred/politeia/politeiawww/api/ticketvote/v1"
	"github.com/decred/politeia/politeiawww/user"
)

func (t *TicketVote) processAuthorize(ctx context.Context, a v1.Authorize, u user.User) (*v1.AuthorizeReply, error) {
	log.Tracef("processAuthorize: %v", a.Token)

	// Verify user signed with their active identity
	if u.PublicKey() != a.PublicKey {
		return nil, v1.UserErrorReply{
			ErrorCode:    v1.ErrorCodePublicKeyInvalid,
			ErrorContext: "not active identity",
		}
	}

	// Verify user is the record author
	authorID, err := t.politeiad.Author(ctx, pdv1.RecordStateVetted, a.Token)
	if err != nil {
		return nil, err
	}
	if u.ID.String() != authorID {
		return nil, v1.UserErrorReply{
			ErrorCode:    v1.ErrorCodeUnauthorized,
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

	return &v1.AuthorizeReply{
		Timestamp: tar.Timestamp,
		Receipt:   tar.Receipt,
	}, nil
}

func (t *TicketVote) processStart(ctx context.Context, s v1.Start, u user.User) (*v1.StartReply, error) {
	log.Tracef("processStart: %v", len(s.Starts))

	// Verify user signed with their active identity
	for _, v := range s.Starts {
		if u.PublicKey() != v.PublicKey {
			return nil, v1.UserErrorReply{
				ErrorCode:    v1.ErrorCodePublicKeyInvalid,
				ErrorContext: "not active identity",
			}
		}
	}

	// Get token from start details
	var token string
	for _, v := range s.Starts {
		switch v.Params.Type {
		case v1.VoteTypeRunoff:
			// This is a runoff vote. Execute the plugin command on the
			// parent record.
			token = v.Params.Parent
		case v1.VoteTypeStandard:
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

	return &v1.StartReply{
		StartBlockHeight: tsr.StartBlockHeight,
		StartBlockHash:   tsr.StartBlockHash,
		EndBlockHeight:   tsr.EndBlockHeight,
		EligibleTickets:  tsr.EligibleTickets,
	}, nil
}

func (t *TicketVote) processCastBallot(ctx context.Context, cb v1.CastBallot) (*v1.CastBallotReply, error) {
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

	return &v1.CastBallotReply{
		Receipts: convertCastVoteRepliesToV1(tcbr.Receipts),
	}, nil
}

func (t *TicketVote) processDetails(ctx context.Context, d v1.Details) (*v1.DetailsReply, error) {
	log.Tracef("processsDetails: %v", d.Token)

	tdr, err := t.politeiad.TicketVoteDetails(ctx, d.Token)
	if err != nil {
		return nil, err
	}

	var vote *v1.VoteDetails
	if tdr.Vote != nil {
		vd := convertVoteDetailsToV1(*tdr.Vote)
		vote = &vd
	}

	return &v1.DetailsReply{
		Auths: convertAuthDetailsToV1(tdr.Auths),
		Vote:  vote,
	}, nil
}

func (t *TicketVote) processResults(ctx context.Context, r v1.Results) (*v1.ResultsReply, error) {
	log.Tracef("processResults: %v", r.Token)

	rr, err := t.politeiad.TicketVoteResults(ctx, r.Token)
	if err != nil {
		return nil, err
	}

	return &v1.ResultsReply{
		Votes: convertCastVoteDetailsToV1(rr.Votes),
	}, nil
}

func (t *TicketVote) processSummaries(ctx context.Context, s v1.Summaries) (*v1.SummariesReply, error) {
	log.Tracef("processSummaries: %v", s.Tokens)

	ts, err := t.politeiad.TicketVoteSummaries(ctx, s.Tokens)
	if err != nil {
		return nil, err
	}

	return &v1.SummariesReply{
		Summaries: convertSummariesToV1(ts),
	}, nil
}

func (t *TicketVote) processLinkedFrom(ctx context.Context, lf v1.LinkedFrom) (*v1.LinkedFromReply, error) {
	log.Tracef("processLinkedFrom: %v", lf.Tokens)

	tlf, err := t.politeiad.TicketVoteLinkedFrom(ctx, lf.Tokens)
	if err != nil {
		return nil, err
	}

	return &v1.LinkedFromReply{
		LinkedFrom: tlf,
	}, nil
}

func (t *TicketVote) processInventory(ctx context.Context) (*v1.InventoryReply, error) {
	log.Tracef("processInventory")

	// Send plugin command
	ir, err := t.politeiad.TicketVoteInventory(ctx)
	if err != nil {
		return nil, err
	}

	// Convert vote statuses to human readable equivalents
	records := make(map[string][]string, len(ir.Records))
	for k, v := range ir.Records {
		s := convertVoteStatusToV1(k)
		records[v1.VoteStatuses[s]] = v
	}

	return &v1.InventoryReply{
		Vetted:    records,
		BestBlock: ir.BestBlock,
	}, nil
}

func (t *TicketVote) processTimestamps(ctx context.Context, ts v1.Timestamps) (*v1.TimestampsReply, error) {
	log.Tracef("processTimestamps: %v", ts.Token)

	// Send plugin command
	tsr, err := t.politeiad.TicketVoteTimestamps(ctx, ts.Token)
	if err != nil {
		return nil, err
	}

	// Prepare reply
	var (
		auths = make([]v1.Timestamp, 0, len(tsr.Auths))
		votes = make(map[string]v1.Timestamp, len(tsr.Votes))

		details = convertTimestampToV1(tsr.Details)
	)
	for _, v := range tsr.Auths {
		auths = append(auths, convertTimestampToV1(v))
	}
	for k, v := range tsr.Votes {
		votes[k] = convertTimestampToV1(v)
	}

	return &v1.TimestampsReply{
		Auths:   auths,
		Details: details,
		Votes:   votes,
	}, nil
}

func convertVoteTypeToPlugin(t v1.VoteT) ticketvote.VoteT {
	switch t {
	case v1.VoteTypeStandard:
		return ticketvote.VoteTypeStandard
	case v1.VoteTypeRunoff:
		return ticketvote.VoteTypeRunoff
	}
	return ticketvote.VoteTypeInvalid
}

func convertVoteParamsToPlugin(v v1.VoteParams) ticketvote.VoteParams {
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

func convertStartDetailsToPlugin(sd v1.StartDetails) ticketvote.StartDetails {
	return ticketvote.StartDetails{
		Params:    convertVoteParamsToPlugin(sd.Params),
		PublicKey: sd.PublicKey,
		Signature: sd.Signature,
	}
}

func convertStartToPlugin(vs v1.Start) ticketvote.Start {
	starts := make([]ticketvote.StartDetails, 0, len(vs.Starts))
	for _, v := range vs.Starts {
		starts = append(starts, convertStartDetailsToPlugin(v))
	}
	return ticketvote.Start{
		Starts: starts,
	}
}

func convertCastVotesToPlugin(votes []v1.CastVote) []ticketvote.CastVote {
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

func convertVoteTypeToV1(t ticketvote.VoteT) v1.VoteT {
	switch t {
	case ticketvote.VoteTypeStandard:
		return v1.VoteTypeStandard
	case ticketvote.VoteTypeRunoff:
		return v1.VoteTypeRunoff
	}
	return v1.VoteTypeInvalid

}

func convertVoteParamsToV1(v ticketvote.VoteParams) v1.VoteParams {
	vp := v1.VoteParams{
		Token:            v.Token,
		Version:          v.Version,
		Type:             convertVoteTypeToV1(v.Type),
		Mask:             v.Mask,
		Duration:         v.Duration,
		QuorumPercentage: v.QuorumPercentage,
		PassPercentage:   v.PassPercentage,
	}
	vo := make([]v1.VoteOption, 0, len(v.Options))
	for _, o := range v.Options {
		vo = append(vo, v1.VoteOption{
			ID:          o.ID,
			Description: o.Description,
			Bit:         o.Bit,
		})
	}
	vp.Options = vo

	return vp
}

func convertVoteErrorToV1(e ticketvote.VoteErrorT) v1.VoteErrorT {
	switch e {
	case ticketvote.VoteErrorInvalid:
		return v1.VoteErrorInvalid
	case ticketvote.VoteErrorInternalError:
		return v1.VoteErrorInternalError
	case ticketvote.VoteErrorRecordNotFound:
		return v1.VoteErrorRecordNotFound
	case ticketvote.VoteErrorVoteBitInvalid:
		return v1.VoteErrorVoteBitInvalid
	case ticketvote.VoteErrorVoteStatusInvalid:
		return v1.VoteErrorVoteStatusInvalid
	case ticketvote.VoteErrorTicketAlreadyVoted:
		return v1.VoteErrorTicketAlreadyVoted
	case ticketvote.VoteErrorTicketNotEligible:
		return v1.VoteErrorTicketNotEligible
	default:
		return v1.VoteErrorInternalError
	}
}

func convertCastVoteRepliesToV1(replies []ticketvote.CastVoteReply) []v1.CastVoteReply {
	r := make([]v1.CastVoteReply, 0, len(replies))
	for _, v := range replies {
		r = append(r, v1.CastVoteReply{
			Ticket:       v.Ticket,
			Receipt:      v.Receipt,
			ErrorCode:    convertVoteErrorToV1(v.ErrorCode),
			ErrorContext: v.ErrorContext,
		})
	}
	return r
}

func convertVoteDetailsToV1(vd ticketvote.VoteDetails) v1.VoteDetails {
	return v1.VoteDetails{
		Params:           convertVoteParamsToV1(vd.Params),
		PublicKey:        vd.PublicKey,
		Signature:        vd.Signature,
		StartBlockHeight: vd.StartBlockHeight,
		StartBlockHash:   vd.StartBlockHash,
		EndBlockHeight:   vd.EndBlockHeight,
		EligibleTickets:  vd.EligibleTickets,
	}
}

func convertAuthDetailsToV1(auths []ticketvote.AuthDetails) []v1.AuthDetails {
	a := make([]v1.AuthDetails, 0, len(auths))
	for _, v := range auths {
		a = append(a, v1.AuthDetails{
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

func convertCastVoteDetailsToV1(votes []ticketvote.CastVoteDetails) []v1.CastVoteDetails {
	vs := make([]v1.CastVoteDetails, 0, len(votes))
	for _, v := range votes {
		vs = append(vs, v1.CastVoteDetails{
			Token:     v.Token,
			Ticket:    v.Ticket,
			VoteBit:   v.VoteBit,
			Signature: v.Signature,
			Receipt:   v.Receipt,
		})
	}
	return vs
}

func convertVoteStatusToV1(s ticketvote.VoteStatusT) v1.VoteStatusT {
	switch s {
	case ticketvote.VoteStatusInvalid:
		return v1.VoteStatusInvalid
	case ticketvote.VoteStatusUnauthorized:
		return v1.VoteStatusUnauthorized
	case ticketvote.VoteStatusAuthorized:
		return v1.VoteStatusAuthorized
	case ticketvote.VoteStatusStarted:
		return v1.VoteStatusStarted
	case ticketvote.VoteStatusFinished:
		return v1.VoteStatusFinished
	default:
		return v1.VoteStatusInvalid
	}
}

func convertSummaryToV1(s ticketvote.SummaryReply) v1.Summary {
	results := make([]v1.VoteResult, 0, len(s.Results))
	for _, v := range s.Results {
		results = append(results, v1.VoteResult{
			ID:          v.ID,
			Description: v.Description,
			VoteBit:     v.VoteBit,
			Votes:       v.Votes,
		})
	}
	return v1.Summary{
		Type:             convertVoteTypeToV1(s.Type),
		Status:           convertVoteStatusToV1(s.Status),
		Duration:         s.Duration,
		StartBlockHeight: s.StartBlockHeight,
		StartBlockHash:   s.StartBlockHash,
		EndBlockHeight:   s.EndBlockHeight,
		EligibleTickets:  s.EligibleTickets,
		QuorumPercentage: s.QuorumPercentage,
		PassPercentage:   s.PassPercentage,
		Results:          results,
		Approved:         s.Approved,
		BestBlock:        s.BestBlock,
	}
}

func convertSummariesToV1(s map[string]ticketvote.SummaryReply) map[string]v1.Summary {
	ts := make(map[string]v1.Summary, len(s))
	for k, v := range s {
		ts[k] = convertSummaryToV1(v)
	}
	return ts
}

func convertProofToV1(p ticketvote.Proof) v1.Proof {
	return v1.Proof{
		Type:       p.Type,
		Digest:     p.Digest,
		MerkleRoot: p.MerkleRoot,
		MerklePath: p.MerklePath,
		ExtraData:  p.ExtraData,
	}
}

func convertTimestampToV1(t ticketvote.Timestamp) v1.Timestamp {
	proofs := make([]v1.Proof, 0, len(t.Proofs))
	for _, v := range t.Proofs {
		proofs = append(proofs, convertProofToV1(v))
	}
	return v1.Timestamp{
		Data:       t.Data,
		Digest:     t.Digest,
		TxID:       t.TxID,
		MerkleRoot: t.MerkleRoot,
		Proofs:     proofs,
	}
}
