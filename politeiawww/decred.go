// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"

	"github.com/decred/politeia/decredplugin"
)

// decredGetComments sends the decred plugin getcomments command to the cache
// and returns all of the comments for the passed in proposal token.
func (p *politeiawww) decredGetComments(ctx context.Context, token string) ([]decredplugin.Comment, error) {
	// Setup plugin command
	gc := decredplugin.GetComments{
		Token: token,
	}
	payload, err := decredplugin.EncodeGetComments(gc)
	if err != nil {
		return nil, err
	}

	// Execute plugin command
	reply, err := p.pluginCommand(ctx, decredplugin.ID, decredplugin.CmdGetComments,
		string(payload))
	if err != nil {
		return nil, fmt.Errorf("pluginCommand %v %v: %v",
			decredplugin.ID, decredplugin.CmdGetComments, err)
	}

	// Receive plugin command reply
	gcr, err := decredplugin.DecodeGetCommentsReply([]byte(reply))
	if err != nil {
		return nil, err
	}

	return gcr.Comments, nil
}

func (p *politeiawww) decredBestBlock(ctx context.Context) (uint32, error) {
	// Setup plugin command
	payload, err := decredplugin.EncodeBestBlock(decredplugin.BestBlock{})
	if err != nil {
		return 0, err
	}

	// Execute plugin command
	reply, err := p.pluginCommand(ctx, decredplugin.ID, decredplugin.CmdBestBlock,
		string(payload))
	if err != nil {
		return 0, fmt.Errorf("pluginCommand %v %v: %v",
			decredplugin.ID, decredplugin.CmdBestBlock, err)
	}

	// Receive plugin command reply
	bbr, err := decredplugin.DecodeBestBlockReply([]byte(reply))
	if err != nil {
		return 0, err
	}

	return bbr.Height, nil
}
