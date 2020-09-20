// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"github.com/decred/politeia/decredplugin"
)

// decredGetComment sends the decred plugin getcomment command to the cache and
// returns the specified comment.
func (p *politeiawww) decredGetComment(gc decredplugin.GetComment) (*decredplugin.Comment, error) {
	// Setup plugin command
	payload, err := decredplugin.EncodeGetComment(gc)
	if err != nil {
		return nil, err
	}

	// TODO this needs to use the politeiad plugin command
	_ = payload
	var reply string

	gcr, err := decredplugin.DecodeGetCommentReply([]byte(reply))
	if err != nil {
		return nil, err
	}

	return &gcr.Comment, nil
}

// decredCommentGetByID retrieves the specified decred plugin comment from the
// cache.
func (p *politeiawww) decredCommentGetByID(token, commentID string) (*decredplugin.Comment, error) {
	gc := decredplugin.GetComment{
		Token:     token,
		CommentID: commentID,
	}
	return p.decredGetComment(gc)
}

// decredCommentGetBySignature retrieves the specified decred plugin comment
// decredGetComments sends the decred plugin getcomments command to the cache
// and returns all of the comments for the passed in proposal token.
func (p *politeiawww) decredGetComments(token string) ([]decredplugin.Comment, error) {
	// Setup plugin command
	gc := decredplugin.GetComments{
		Token: token,
	}
	payload, err := decredplugin.EncodeGetComments(gc)
	if err != nil {
		return nil, err
	}

	// TODO this needs to use the politeiad plugin command
	_ = payload
	var reply string

	gcr, err := decredplugin.DecodeGetCommentsReply([]byte(reply))
	if err != nil {
		return nil, err
	}

	return gcr.Comments, nil
}

func (p *politeiawww) decredBestBlock() (*decredplugin.BestBlockReply, error) {
	// Setup plugin command
	payload, err := decredplugin.EncodeBestBlock(decredplugin.BestBlock{})
	if err != nil {
		return nil, err
	}

	// Execute plugin command
	reply, err := p.pluginCommand(decredplugin.ID, decredplugin.CmdBestBlock,
		decredplugin.CmdBestBlock, string(payload))

	// Receive plugin command reply
	bbr, err := decredplugin.DecodeBestBlockReply([]byte(reply))
	if err != nil {
		return nil, err
	}

	return bbr, nil
}
