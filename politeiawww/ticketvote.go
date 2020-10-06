// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	ticketvote "github.com/decred/politeia/politeiad/plugins/ticketvote"
)

// voteAuthorize uses the ticketvote plugin to authorize a vote.
func (p *politeiawww) voteAuthorize(a ticketvote.Authorize) (*ticketvote.AuthorizeReply, error) {
	b, err := ticketvote.EncodeAuthorize(a)
	if err != nil {
		return nil, err
	}
	r, err := p.pluginCommand(ticketvote.ID, ticketvote.CmdAuthorize, string(b))
	if err != nil {
		return nil, err
	}
	va, err := ticketvote.DecodeAuthorizeReply([]byte(r))
	if err != nil {
		return nil, err
	}
	return va, nil
}

// voteStart uses the ticketvote plugin to start a vote.
func (p *politeiawww) voteStart(s ticketvote.Start) (*ticketvote.StartReply, error) {
	b, err := ticketvote.EncodeStart(s)
	if err != nil {
		return nil, err
	}
	r, err := p.pluginCommand(ticketvote.ID, ticketvote.CmdStart, string(b))
	if err != nil {
		return nil, err
	}
	sr, err := ticketvote.DecodeStartReply([]byte(r))
	if err != nil {
		return nil, err
	}
	return sr, nil
}

// voteStartRunoff uses the ticketvote plugin to start a runoff vote.
func (p *politeiawww) voteStartRunoff(sr ticketvote.StartRunoff) (*ticketvote.StartRunoffReply, error) {
	b, err := ticketvote.EncodeStartRunoff(sr)
	if err != nil {
		return nil, err
	}
	r, err := p.pluginCommand(ticketvote.ID, ticketvote.CmdStartRunoff,
		string(b))
	if err != nil {
		return nil, err
	}
	srr, err := ticketvote.DecodeStartRunoffReply([]byte(r))
	if err != nil {
		return nil, err
	}
	return srr, nil
}

// voteBallot uses the ticketvote plugin to cast a ballot of votes.
func (p *politeiawww) voteBallot(tb ticketvote.Ballot) (*ticketvote.BallotReply, error) {
	b, err := ticketvote.EncodeBallot(tb)
	if err != nil {
		return nil, err
	}
	r, err := p.pluginCommand(ticketvote.ID, ticketvote.CmdBallot, string(b))
	if err != nil {
		return nil, err
	}
	br, err := ticketvote.DecodeBallotReply([]byte(r))
	if err != nil {
		return nil, err
	}
	return br, nil
}

// voteDetails uses the ticketvote plugin to fetch the details of a vote.
func (p *politeiawww) voteDetails(tokens []string) (*ticketvote.DetailsReply, error) {
	d := ticketvote.Details{
		Tokens: tokens,
	}
	b, err := ticketvote.EncodeDetails(d)
	if err != nil {
		return nil, err
	}
	r, err := p.pluginCommand(ticketvote.ID, ticketvote.CmdDetails, string(b))
	if err != nil {
		return nil, err
	}
	dr, err := ticketvote.DecodeDetailsReply([]byte(r))
	if err != nil {
		return nil, err
	}
	return dr, nil
}

// castVotes uses the ticketvote plugin to fetch cast votes for a record.
func (p *politeiawww) castVotes(token string) (*ticketvote.CastVotesReply, error) {
	cv := ticketvote.CastVotes{
		Token: token,
	}
	b, err := ticketvote.EncodeCastVotes(cv)
	if err != nil {
		return nil, err
	}
	r, err := p.pluginCommand(ticketvote.ID, ticketvote.CmdCastVotes, string(b))
	if err != nil {
		return nil, err
	}
	cvr, err := ticketvote.DecodeCastVotesReply([]byte(r))
	if err != nil {
		return nil, err
	}
	return cvr, nil
}

// voteSummaries uses the ticketvote plugin to fetch vote summaries.
func (p *politeiawww) voteSummaries(tokens []string) (*ticketvote.SummariesReply, error) {
	s := ticketvote.Summaries{
		Tokens: tokens,
	}
	b, err := ticketvote.EncodeSummaries(s)
	if err != nil {
		return nil, err
	}
	r, err := p.pluginCommand(ticketvote.ID, ticketvote.CmdSummaries, string(b))
	if err != nil {
		return nil, err
	}
	sr, err := ticketvote.DecodeSummariesReply([]byte(r))
	if err != nil {
		return nil, err
	}
	return sr, nil
}
