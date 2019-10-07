// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package testcache

import (
	"github.com/decred/politeia/decredplugin"
	decred "github.com/decred/politeia/decredplugin"
	"github.com/decred/politeia/politeiad/cache"
)

func (c *testcache) getComments(payload string) (string, error) {
	gc, err := decred.DecodeGetComments([]byte(payload))
	if err != nil {
		return "", err
	}

	c.RLock()
	defer c.RUnlock()

	gcrb, err := decred.EncodeGetCommentsReply(
		decred.GetCommentsReply{
			Comments: c.comments[gc.Token],
		})
	if err != nil {
		return "", err
	}

	return string(gcrb), nil
}

func (c *testcache) authorizeVote(cmdPayload, replyPayload string) (string, error) {
	av, err := decred.DecodeAuthorizeVote([]byte(cmdPayload))
	if err != nil {
		return "", err
	}

	avr, err := decred.DecodeAuthorizeVoteReply([]byte(replyPayload))
	if err != nil {
		return "", err
	}

	av.Receipt = avr.Receipt
	av.Timestamp = avr.Timestamp

	c.Lock()
	defer c.Unlock()

	_, ok := c.authorizeVotes[av.Token]
	if !ok {
		c.authorizeVotes[av.Token] = make(map[string]decred.AuthorizeVote)
	}

	c.authorizeVotes[av.Token][avr.RecordVersion] = *av

	return replyPayload, nil
}

func (c *testcache) startVote(cmdPayload, replyPayload string) (string, error) {
	sv, err := decred.DecodeStartVote([]byte(cmdPayload))
	if err != nil {
		return "", err
	}

	svr, err := decred.DecodeStartVoteReply([]byte(replyPayload))
	if err != nil {
		return "", err
	}

	c.Lock()
	defer c.Unlock()

	// Store start vote data
	c.startVotes[sv.Vote.Token] = *sv
	c.startVoteReplies[sv.Vote.Token] = *svr

	return replyPayload, nil
}

func (c *testcache) voteDetails(payload string) (string, error) {
	vd, err := decred.DecodeVoteDetails([]byte(payload))
	if err != nil {
		return "", err
	}

	c.Lock()
	defer c.Unlock()

	// Lookup the latest record version
	r, err := c.record(vd.Token)
	if err != nil {
		return "", err
	}

	// Prepare reply
	_, ok := c.authorizeVotes[vd.Token]
	if !ok {
		c.authorizeVotes[vd.Token] = make(map[string]decred.AuthorizeVote)
	}

	vdb, err := decred.EncodeVoteDetailsReply(
		decred.VoteDetailsReply{
			AuthorizeVote:  c.authorizeVotes[vd.Token][r.Version],
			StartVote:      c.startVotes[vd.Token],
			StartVoteReply: c.startVoteReplies[vd.Token],
		})
	if err != nil {
		return "", err
	}

	return string(vdb), nil
}

// This is left as a stub for now. The results of this are not used in any
// tests.
func (c *testcache) batchVoteSummary(payload string) (string, error) {
	summaries := make(map[string]decredplugin.VoteSummaryReply)

	bvr, _ := decred.EncodeBatchVoteSummaryReply(
		decred.BatchVoteSummaryReply{
			Summaries: summaries,
		})

	return string(bvr), nil
}

func (c *testcache) decredExec(cmd, cmdPayload, replyPayload string) (string, error) {
	switch cmd {
	case decred.CmdGetComments:
		return c.getComments(cmdPayload)
	case decred.CmdAuthorizeVote:
		return c.authorizeVote(cmdPayload, replyPayload)
	case decred.CmdStartVote:
		return c.startVote(cmdPayload, replyPayload)
	case decred.CmdVoteDetails:
		return c.voteDetails(cmdPayload)
	case decred.CmdBatchVoteSummary:
		return c.batchVoteSummary(cmdPayload)
	}

	return "", cache.ErrInvalidPluginCmd
}
