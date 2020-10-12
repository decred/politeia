// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"github.com/decred/politeia/politeiad/plugins/comments"
)

// commentsAll returns all comments for the provided record.
func (p *politeiawww) commentsAll(cp comments.GetAll) (*comments.GetAllReply, error) {
	b, err := comments.EncodeGetAll(cp)
	if err != nil {
		return nil, err
	}
	r, err := p.pluginCommand(comments.ID, comments.CmdGetAll, string(b))
	if err != nil {
		return nil, err
	}
	cr, err := comments.DecodeGetAllReply([]byte(r))
	if err != nil {
		return nil, err
	}
	return cr, nil
}

// commentsGet returns the set of comments specified in the comment's id slice.
func (p *politeiawww) commentsGet(cg comments.Get) (*comments.GetReply, error) {
	b, err := comments.EncodeGet(cg)
	if err != nil {
		return nil, err
	}
	r, err := p.pluginCommand(comments.ID, comments.CmdGet, string(b))
	if err != nil {
		return nil, err
	}
	cgr, err := comments.DecodeGetReply([]byte(r))
	if err != nil {
		return nil, err
	}
	return cgr, nil
}

// commentVotes returns the comment votes that meet the provided criteria.
func (p *politeiawww) commentVotes(vs comments.Votes) (*comments.VotesReply, error) {
	b, err := comments.EncodeVotes(vs)
	if err != nil {
		return nil, err
	}
	r, err := p.pluginCommand(comments.ID, comments.CmdVotes, string(b))
	if err != nil {
		return nil, err
	}
	vsr, err := comments.DecodeVotesReply([]byte(r))
	if err != nil {
		return nil, err
	}
	return vsr, nil
}
