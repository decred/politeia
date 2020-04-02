// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package testcache

import (
	"fmt"
	"strconv"

	"github.com/thi4go/politeia/decredplugin"
	decred "github.com/thi4go/politeia/decredplugin"
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
	sv, err := decred.DecodeStartVoteV2([]byte(cmdPayload))
	if err != nil {
		return "", err
	}

	svr, err := decred.DecodeStartVoteReply([]byte(replyPayload))
	if err != nil {
		return "", err
	}

	// Version must be added to the StartVote. This is done by
	// politeiad but the updated StartVote does not travel to the
	// cache.
	sv.Version = decred.VersionStartVote

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

	sv := c.startVotes[vd.Token]
	svb, err := decredplugin.EncodeStartVoteV2(sv)
	if err != nil {
		return "", err
	}

	vdb, err := decred.EncodeVoteDetailsReply(
		decred.VoteDetailsReply{
			AuthorizeVote: c.authorizeVotes[vd.Token][r.Version],
			StartVote: decredplugin.StartVote{
				Version: sv.Version,
				Payload: string(svb),
			},
			StartVoteReply: c.startVoteReplies[vd.Token],
		})
	if err != nil {
		return "", err
	}

	return string(vdb), nil
}

func (c *testcache) voteSummary(cmdPayload string) (string, error) {
	vs, err := decred.DecodeVoteSummary([]byte(cmdPayload))
	if err != nil {
		return "", err
	}

	c.RLock()
	defer c.RUnlock()

	// Lookup vote info
	r, err := c.record(vs.Token)
	if err != nil {
		return "", err
	}

	av := c.authorizeVotes[vs.Token][r.Version]
	sv := c.startVotes[vs.Token]

	var duration uint32
	svr, ok := c.startVoteReplies[vs.Token]
	if ok {
		start, err := strconv.ParseUint(svr.StartBlockHeight, 10, 32)
		if err != nil {
			return "", err
		}
		end, err := strconv.ParseUint(svr.EndHeight, 10, 32)
		if err != nil {
			return "", err
		}
		duration = uint32(end - start)
	}

	// Prepare reply
	vsr := decred.VoteSummaryReply{
		Authorized:          av.Action == decred.AuthVoteActionAuthorize,
		Duration:            duration,
		EndHeight:           svr.EndHeight,
		EligibleTicketCount: 0,
		QuorumPercentage:    sv.Vote.QuorumPercentage,
		PassPercentage:      sv.Vote.PassPercentage,
		Results:             []decred.VoteOptionResult{},
	}
	reply, err := decred.EncodeVoteSummaryReply(vsr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
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
	case decred.CmdVoteSummary:
		return c.voteSummary(cmdPayload)
	}

	return "", fmt.Errorf("invalid cache plugin command")
}
