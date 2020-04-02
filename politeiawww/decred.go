// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/davecgh/go-spew/spew"
	"github.com/thi4go/politeia/decredplugin"
	pd "github.com/thi4go/politeia/politeiad/api/v1"
	"github.com/thi4go/politeia/politeiad/cache"
	"github.com/thi4go/politeia/util"
)

// decredGetComment sends the decred plugin getcomment command to the cache and
// returns the specified comment.
func (p *politeiawww) decredGetComment(gc decredplugin.GetComment) (*decredplugin.Comment, error) {
	// Setup plugin command
	payload, err := decredplugin.EncodeGetComment(gc)
	if err != nil {
		return nil, err
	}

	pc := cache.PluginCommand{
		ID:             decredplugin.ID,
		Command:        decredplugin.CmdGetComment,
		CommandPayload: string(payload),
	}

	// Get comment from the cache
	reply, err := p.cache.PluginExec(pc)
	if err != nil {
		return nil, err
	}

	gcr, err := decredplugin.DecodeGetCommentReply([]byte(reply.Payload))
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
// from the cache.
func (p *politeiawww) decredCommentGetBySignature(token, sig string) (*decredplugin.Comment, error) {
	gc := decredplugin.GetComment{
		Token:     token,
		Signature: sig,
	}
	return p.decredGetComment(gc)
}

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

	pc := cache.PluginCommand{
		ID:             decredplugin.ID,
		Command:        decredplugin.CmdGetComments,
		CommandPayload: string(payload),
	}

	// Get comments from the cache
	reply, err := p.cache.PluginExec(pc)
	if err != nil {
		return nil, fmt.Errorf("PluginExec: %v", err)
	}

	gcr, err := decredplugin.DecodeGetCommentsReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}

	return gcr.Comments, nil
}

// decredGetNumComments sends the decred plugin command GetNumComments to the
// cache and returns the number of comments for each of the specified
// proposals. If a provided token does not correspond to an actual proposal
// then it will not be included in the returned map. It is the responability
// of the caller to ensure results are returned for all of the provided tokens.
func (p *politeiawww) decredGetNumComments(tokens []string) (map[string]int, error) {
	// Setup plugin command
	gnc := decredplugin.GetNumComments{
		Tokens: tokens,
	}

	payload, err := decredplugin.EncodeGetNumComments(gnc)
	if err != nil {
		return nil, err
	}

	pc := cache.PluginCommand{
		ID:             decredplugin.ID,
		Command:        decredplugin.CmdGetNumComments,
		CommandPayload: string(payload),
	}

	// Send plugin comand
	reply, err := p.cache.PluginExec(pc)
	if err != nil {
		return nil, fmt.Errorf("PluginExec: %v", err)
	}

	gncr, err := decredplugin.DecodeGetNumCommentsReply(
		[]byte(reply.Payload))
	if err != nil {
		return nil, err
	}

	return gncr.NumComments, nil
}

// decredCommentLikes sends the decred plugin commentlikes command to the cache
// and returns all of the comment likes for the passed in comment.
func (p *politeiawww) decredCommentLikes(token, commentID string) ([]decredplugin.LikeComment, error) {
	// Setup plugin command
	cl := decredplugin.CommentLikes{
		Token:     token,
		CommentID: commentID,
	}

	payload, err := decredplugin.EncodeCommentLikes(cl)
	if err != nil {
		return nil, err
	}

	pc := cache.PluginCommand{
		ID:             decredplugin.ID,
		Command:        decredplugin.CmdCommentLikes,
		CommandPayload: string(payload),
	}

	// Get comment likes from cache
	reply, err := p.cache.PluginExec(pc)
	if err != nil {
		return nil, err
	}

	clr, err := decredplugin.DecodeCommentLikesReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}

	return clr.CommentLikes, nil
}

// decredPropCommentLikes sends the decred plugin proposalcommentslikes command
// to the cache and returns all of the comment likes for the passed in proposal
// token.
func (p *politeiawww) decredPropCommentLikes(token string) ([]decredplugin.LikeComment, error) {
	// Setup plugin command
	pcl := decredplugin.GetProposalCommentsLikes{
		Token: token,
	}

	payload, err := decredplugin.EncodeGetProposalCommentsLikes(pcl)
	if err != nil {
		return nil, err
	}

	pc := cache.PluginCommand{
		ID:             decredplugin.ID,
		Command:        decredplugin.CmdProposalCommentsLikes,
		CommandPayload: string(payload),
	}

	// Get proposal comment likes from cache
	reply, err := p.cache.PluginExec(pc)
	if err != nil {
		return nil, err
	}

	rp := []byte(reply.Payload)
	pclr, err := decredplugin.DecodeGetProposalCommentsLikesReply(rp)
	if err != nil {
		return nil, err
	}

	return pclr.CommentsLikes, nil
}

// decredVoteDetails sends the decred plugin votedetails command to the cache
// and returns the vote details for the passed in proposal.
func (p *politeiawww) decredVoteDetails(token string) (*decredplugin.VoteDetailsReply, error) {
	// Setup plugin command
	vd := decredplugin.VoteDetails{
		Token: token,
	}

	payload, err := decredplugin.EncodeVoteDetails(vd)
	if err != nil {
		return nil, err
	}

	pc := cache.PluginCommand{
		ID:             decredplugin.ID,
		Command:        decredplugin.CmdVoteDetails,
		CommandPayload: string(payload),
	}

	// Get vote details from cache
	reply, err := p.cache.PluginExec(pc)
	if err != nil {
		return nil, err
	}

	vdr, err := decredplugin.DecodeVoteDetailsReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}

	return vdr, nil
}

// decredProposalVotes sends the decred plugin proposalvotes command to the
// cache and returns the vote results for the passed in proposal.
func (p *politeiawww) decredProposalVotes(token string) (*decredplugin.VoteResultsReply, error) {
	// Setup plugin command
	vr := decredplugin.VoteResults{
		Token: token,
	}

	payload, err := decredplugin.EncodeVoteResults(vr)
	if err != nil {
		return nil, err
	}

	pc := cache.PluginCommand{
		ID:             decredplugin.ID,
		Command:        decredplugin.CmdProposalVotes,
		CommandPayload: string(payload),
	}

	// Get proposal votes from cache
	reply, err := p.cache.PluginExec(pc)
	if err != nil {
		return nil, err
	}

	vrr, err := decredplugin.DecodeVoteResultsReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}

	return vrr, nil
}

// decredInventory sends the decred plugin inventory command to the cache and
// returns the decred plugin inventory.
func (p *politeiawww) decredInventory() (*decredplugin.InventoryReply, error) {
	// Setup plugin command
	i := decredplugin.Inventory{}
	payload, err := decredplugin.EncodeInventory(i)
	if err != nil {
		return nil, err
	}

	pc := cache.PluginCommand{
		ID:             decredplugin.ID,
		Command:        decredplugin.CmdInventory,
		CommandPayload: string(payload),
	}

	// Get cache inventory
	reply, err := p.cache.PluginExec(pc)
	if err != nil {
		return nil, err
	}

	ir, err := decredplugin.DecodeInventoryReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}

	return ir, nil
}

// decredTokenInventory sends the decred plugin tokeninventory command to the
// cache.
func (p *politeiawww) decredTokenInventory(bestBlock uint64, includeUnvetted bool) (*decredplugin.TokenInventoryReply, error) {
	payload, err := decredplugin.EncodeTokenInventory(
		decredplugin.TokenInventory{
			BestBlock: bestBlock,
			Unvetted:  includeUnvetted,
		})
	if err != nil {
		return nil, err
	}

	pc := cache.PluginCommand{
		ID:             decredplugin.ID,
		Command:        decredplugin.CmdTokenInventory,
		CommandPayload: string(payload),
	}

	reply, err := p.cache.PluginExec(pc)
	if err != nil {
		return nil, err
	}

	tir, err := decredplugin.DecodeTokenInventoryReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}

	return tir, nil
}

// decredLoadVoteResults sends the loadvotesummaries command to politeiad.
func (p *politeiawww) decredLoadVoteResults(bestBlock uint64) (*decredplugin.LoadVoteResultsReply, error) {
	// Setup plugin command
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	lvr := decredplugin.LoadVoteResults{
		BestBlock: bestBlock,
	}
	payload, err := decredplugin.EncodeLoadVoteResults(lvr)
	if err != nil {
		return nil, err
	}

	pc := pd.PluginCommand{
		Challenge: hex.EncodeToString(challenge),
		ID:        decredplugin.ID,
		Command:   decredplugin.CmdLoadVoteResults,
		CommandID: decredplugin.CmdLoadVoteResults,
		Payload:   string(payload),
	}

	// Send plugin command to politeiad
	respBody, err := p.makeRequest(http.MethodPost,
		pd.PluginCommandRoute, pc)
	if err != nil {
		return nil, err
	}

	// Handle response
	var pcr pd.PluginCommandReply
	err = json.Unmarshal(respBody, &pcr)
	if err != nil {
		return nil, err
	}

	err = util.VerifyChallenge(p.cfg.Identity, challenge, pcr.Response)
	if err != nil {
		return nil, err
	}

	b := []byte(pcr.Payload)
	reply, err := decredplugin.DecodeLoadVoteResultsReply(b)
	if err != nil {
		spew.Dump("here")
		return nil, err
	}

	return reply, nil
}

// decredBatchVoteSummary uses the decred plugin batch vote summary command to
// request a vote summary for a set of proposals from the cache.
func (p *politeiawww) decredBatchVoteSummary(tokens []string) (*decredplugin.BatchVoteSummaryReply, error) {
	bvs := decredplugin.BatchVoteSummary{
		Tokens: tokens,
	}
	payload, err := decredplugin.EncodeBatchVoteSummary(bvs)
	if err != nil {
		return nil, err
	}

	pc := cache.PluginCommand{
		ID:             decredplugin.ID,
		Command:        decredplugin.CmdBatchVoteSummary,
		CommandPayload: string(payload),
	}

	res, err := p.cache.PluginExec(pc)
	if err != nil {
		return nil, err
	}

	reply, err := decredplugin.DecodeBatchVoteSummaryReply([]byte(res.Payload))
	if err != nil {
		return nil, err
	}

	return reply, nil
}

// decredVoteSummary uses the decred plugin vote summary command to request a
// vote summary for a specific proposal from the cache.
func (p *politeiawww) decredVoteSummary(token string) (*decredplugin.VoteSummaryReply, error) {
	v := decredplugin.VoteSummary{
		Token: token,
	}
	payload, err := decredplugin.EncodeVoteSummary(v)
	if err != nil {
		return nil, err
	}

	pc := cache.PluginCommand{
		ID:             decredplugin.ID,
		Command:        decredplugin.CmdVoteSummary,
		CommandPayload: string(payload),
	}

	resp, err := p.cache.PluginExec(pc)
	if err != nil {
		return nil, err
	}

	reply, err := decredplugin.DecodeVoteSummaryReply([]byte(resp.Payload))
	if err != nil {
		return nil, err
	}

	return reply, nil
}
