// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package testcache

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/decred/politeia/decredplugin"
	decred "github.com/decred/politeia/decredplugin"
	"github.com/decred/politeia/mdstream"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
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

func (c *testcache) voteSummaryReply(token string) (*decred.VoteSummaryReply, error) {
	c.RLock()
	defer c.RUnlock()

	r, err := c.record(token)
	if err != nil {
		return nil, err
	}

	av := c.authorizeVotes[token][r.Version]
	sv := c.startVotes[token]

	var duration uint32
	svr, ok := c.startVoteReplies[token]
	if ok {
		start, err := strconv.ParseUint(svr.StartBlockHeight, 10, 32)
		if err != nil {
			return nil, err
		}
		end, err := strconv.ParseUint(svr.EndHeight, 10, 32)
		if err != nil {
			return nil, err
		}
		duration = uint32(end - start)
	}

	vsr := decred.VoteSummaryReply{
		Authorized:          av.Action == decred.AuthVoteActionAuthorize,
		Type:                sv.Vote.Type,
		Duration:            duration,
		EndHeight:           svr.EndHeight,
		EligibleTicketCount: 0,
		QuorumPercentage:    sv.Vote.QuorumPercentage,
		PassPercentage:      sv.Vote.PassPercentage,
		Results:             []decred.VoteOptionResult{},
	}

	return &vsr, nil
}

func (c *testcache) voteSummary(cmdPayload string) (string, error) {
	vs, err := decred.DecodeVoteSummary([]byte(cmdPayload))
	if err != nil {
		return "", err
	}
	vsr, err := c.voteSummaryReply(vs.Token)
	if err != nil {
		return "", err
	}
	reply, err := decred.EncodeVoteSummaryReply(*vsr)
	if err != nil {
		return "", err
	}
	return string(reply), nil
}

func (c *testcache) voteSummaries(cmdPayload string) (string, error) {
	bvs, err := decred.DecodeBatchVoteSummary([]byte(cmdPayload))
	if err != nil {
		return "", err
	}

	s := make(map[string]decred.VoteSummaryReply, len(bvs.Tokens))
	for _, token := range bvs.Tokens {
		vsr, err := c.voteSummaryReply(token)
		if err != nil {
			return "", err
		}
		s[token] = *vsr
	}

	reply, err := decred.EncodeBatchVoteSummaryReply(
		decred.BatchVoteSummaryReply{
			Summaries: s,
		})
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// findLinkedFrom returns the tokens of any proposals that have linked to
// the given proposal token.
func (c *testcache) findLinkedFrom(token string) ([]string, error) {
	linkedFrom := make([]string, 0, len(c.records))

	// Check all records in the cache to see if they're linked to the
	// provided token.
	for _, allVersions := range c.records {
		// Get the latest version of the proposal
		r := allVersions[strconv.Itoa(len(allVersions))]

		// Extract LinkTo from the ProposalMetadata file
		for _, f := range r.Files {
			if f.Name == mdstream.FilenameProposalMetadata {
				b, err := base64.StdEncoding.DecodeString(f.Payload)
				if err != nil {
					return nil, err
				}
				var pm www.ProposalMetadata
				err = json.Unmarshal(b, &pm)
				if err != nil {
					return nil, err
				}
				if pm.LinkTo == token {
					// This proposal links to the provided token
					linkedFrom = append(linkedFrom, r.CensorshipRecord.Token)
				}

				// No need to continue
				break
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

func (c *testcache) getNumComments(payload string) (string, error) {
	gnc, err := decred.DecodeGetNumComments([]byte(payload))
	if err != nil {
		return "", err
	}

	numComments := make(map[string]int)
	for _, token := range gnc.Tokens {
		numComments[token] = len(c.comments[token])
	}

	gncr, err := decred.EncodeGetNumCommentsReply(
		decred.GetNumCommentsReply{
			NumComments: numComments,
		})

	if err != nil {
		return "", err
	}

	return string(gncr), nil
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
	case decred.CmdGetNumComments:
		return c.getNumComments(cmdPayload)
	case decred.CmdVoteSummary:
		return c.voteSummary(cmdPayload)
	case decred.CmdBatchVoteSummary:
		return c.voteSummaries(cmdPayload)
	case decred.CmdLinkedFrom:
		return c.linkedFrom(cmdPayload)
	}

	return "", fmt.Errorf("invalid cache plugin command")
}
