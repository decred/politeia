// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"context"

	ticketvote "github.com/decred/politeia/politeiad/plugins/ticketvote"
)

// voteAuthorize uses the ticketvote plugin to authorize a vote.
func (p *politeiawww) voteAuthorize(ctx context.Context, a ticketvote.Authorize) (*ticketvote.AuthorizeReply, error) {
	b, err := ticketvote.EncodeAuthorize(a)
	if err != nil {
		return nil, err
	}
	r, err := p.pluginCommand(ctx, ticketvote.ID,
		ticketvote.CmdAuthorize, string(b))
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
func (p *politeiawww) voteStart(ctx context.Context, s ticketvote.Start) (*ticketvote.StartReply, error) {
	b, err := ticketvote.EncodeStart(s)
	if err != nil {
		return nil, err
	}
	r, err := p.pluginCommand(ctx, ticketvote.ID,
		ticketvote.CmdStart, string(b))
	if err != nil {
		return nil, err
	}
	sr, err := ticketvote.DecodeStartReply([]byte(r))
	if err != nil {
		return nil, err
	}
	return sr, nil
}

// castBallot uses the ticketvote plugin to cast a ballot of votes.
func (p *politeiawww) castBallot(ctx context.Context, tb ticketvote.CastBallot) (*ticketvote.CastBallotReply, error) {
	b, err := ticketvote.EncodeCastBallot(tb)
	if err != nil {
		return nil, err
	}
	r, err := p.pluginCommand(ctx, ticketvote.ID,
		ticketvote.CmdCastBallot, string(b))
	if err != nil {
		return nil, err
	}
	br, err := ticketvote.DecodeCastBallotReply([]byte(r))
	if err != nil {
		return nil, err
	}
	return br, nil
}

// voteDetails uses the ticketvote plugin to fetch the details of a vote.
func (p *politeiawww) voteDetails(ctx context.Context, tokens []string) (*ticketvote.DetailsReply, error) {
	d := ticketvote.Details{
		Tokens: tokens,
	}
	b, err := ticketvote.EncodeDetails(d)
	if err != nil {
		return nil, err
	}
	r, err := p.pluginCommand(ctx, ticketvote.ID,
		ticketvote.CmdDetails, string(b))
	if err != nil {
		return nil, err
	}
	dr, err := ticketvote.DecodeDetailsReply([]byte(r))
	if err != nil {
		return nil, err
	}
	return dr, nil
}

// voteResults uses the ticketvote plugin to fetch cast votes for a record.
func (p *politeiawww) voteResults(ctx context.Context, token string) (*ticketvote.ResultsReply, error) {
	cv := ticketvote.Results{
		Token: token,
	}
	b, err := ticketvote.EncodeResults(cv)
	if err != nil {
		return nil, err
	}
	r, err := p.pluginCommand(ctx, ticketvote.ID,
		ticketvote.CmdResults, string(b))
	if err != nil {
		return nil, err
	}
	cvr, err := ticketvote.DecodeResultsReply([]byte(r))
	if err != nil {
		return nil, err
	}
	return cvr, nil
}

// voteSummaries uses the ticketvote plugin to fetch vote summaries.
func (p *politeiawww) voteSummaries(ctx context.Context, tokens []string) (*ticketvote.SummariesReply, error) {
	s := ticketvote.Summaries{
		Tokens: tokens,
	}
	b, err := ticketvote.EncodeSummaries(s)
	if err != nil {
		return nil, err
	}
	r, err := p.pluginCommand(ctx, ticketvote.ID,
		ticketvote.CmdSummaries, string(b))
	if err != nil {
		return nil, err
	}
	sr, err := ticketvote.DecodeSummariesReply([]byte(r))
	if err != nil {
		return nil, err
	}
	return sr, nil
}
