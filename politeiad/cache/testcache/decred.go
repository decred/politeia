// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package testcache

import (
	"fmt"
	"strconv"

	"github.com/decred/politeia/decredplugin"
	decred "github.com/decred/politeia/decredplugin"
	"github.com/decred/politeia/mdstream"
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

// findLinkedFrom returns the tokens of any proposals that have linked to
// the given proposal token.
func (c *testcache) findLinkedFrom(token string) ([]string, error) {
	linkedFrom := make([]string, 0, len(c.records))

	for _, allVersions := range c.records {
		// Get the latest version of the proposal
		r := allVersions[string(len(allVersions))]

		// Check the LinkTo field of the ProposalGeneral mdstream
		for _, md := range r.Metadata {
			if md.ID == mdstream.IDProposalGeneral {
				pg, err := mdstream.DecodeProposalGeneral([]byte(md.Payload))
				if err != nil {
					return nil, err
				}
				if pg.LinkTo == token {
					linkedFrom = append(linkedFrom, r.CensorshipRecord.Token)
				}
			}
		}
	}

	return linkedFrom, nil
}

func (c *testcache) linkedFrom(cmdPayload string) (string, error) {
	lf, err := decredplugin.DecodeLinkedFrom([]byte(cmdPayload))
	if err != nil {
		return "", err
	}

	c.RLock()
	defer c.RUnlock()

	linkedFromBatch := make(map[string][]string, len(lf.Tokens)) // [token]linkedFrom
	for _, token := range lf.Tokens {
		linkedFrom, err := c.findLinkedFrom(token)
		if err != nil {
			return "", err
		}
		linkedFromBatch[token] = linkedFrom
	}

	lfr := decredplugin.LinkedFromReply{
		LinkedFrom: linkedFromBatch,
	}
	reply, err := decredplugin.EncodeLinkedFromReply(lfr)
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
	case decred.CmdLinkedFrom:
		return c.linkedFrom(cmdPayload)
	}

	return "", fmt.Errorf("invalid cache plugin command")
}
