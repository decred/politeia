// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	ticketvote "github.com/decred/politeia/plugins/ticketvote"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
)

// voteDetails calls the ticketvote plugin command to get vote details.
func (p *politeiawww) voteDetails(token string) (*ticketvote.DetailsReply, error) {
	// Prep vote details payload
	vdp := ticketvote.Details{
		Token: token,
	}
	payload, err := ticketvote.EncodeDetails(vdp)
	if err != nil {
		return nil, err
	}

	r, err := p.pluginCommand(ticketvote.ID, ticketvote.CmdDetails, "",
		string(payload))
	vd, err := ticketvote.DecodeDetailsReply([]byte(r))
	if err != nil {
		return nil, err
	}

	return vd, nil
}

// castVotes calls the ticketvote plugin to retrieve cast votes.
func (p *politeiawww) castVotes(token string) (*ticketvote.CastVotesReply, error) {
	// Prep cast votes payload
	csp := ticketvote.CastVotes{
		Token: token,
	}
	payload, err := ticketvote.EncodeCastVotes(csp)
	if err != nil {
		return nil, err
	}

	r, err := p.pluginCommand(ticketvote.ID, ticketvote.CmdCastVotes, "",
		string(payload))
	if err != nil {
		return nil, err
	}
	cv, err := ticketvote.DecodeCastVotesReply([]byte(r))
	if err != nil {
		return nil, err
	}

	return cv, nil
}

// ballot calls the ticketvote plugin to cast a ballot of votes.
func (p *politeiawww) ballot(ballot *www.Ballot) (*ticketvote.BallotReply, error) {
	// Prep plugin command
	var bp ticketvote.Ballot

	// Transale votes
	votes := make([]ticketvote.Vote, 0, len(ballot.Votes))
	for _, vote := range ballot.Votes {
		votes = append(votes, ticketvote.Vote{
			Token:     vote.Ticket,
			Ticket:    vote.Ticket,
			VoteBit:   vote.VoteBit,
			Signature: vote.Signature,
		})
	}
	bp.Votes = votes
	payload, err := ticketvote.EncodeBallot(bp)
	if err != nil {
		return nil, err
	}

	r, err := p.pluginCommand(ticketvote.ID, ticketvote.CmdBallot, "",
		string(payload))
	if err != nil {
		return nil, err
	}
	b, err := ticketvote.DecodeBallotReply([]byte(r))
	if err != nil {
		return nil, err
	}

	return b, nil
}

// summaries calls the ticketvote plugin to get vote summary information.
func (p *politeiawww) voteSummaries(tokens []string) (*ticketvote.SummariesReply, error) {
	// Prep plugin command
	smp := ticketvote.Summaries{
		Tokens: tokens,
	}
	payload, err := ticketvote.EncodeSummaries(smp)
	if err != nil {
		return nil, err
	}

	r, err := p.pluginCommand(ticketvote.ID, ticketvote.CmdSummaries, "",
		string(payload))
	if err != nil {
		return nil, err
	}
	sm, err := ticketvote.DecodeSummariesReply([]byte(r))
	if err != nil {
		return nil, err
	}

	return sm, nil
}
