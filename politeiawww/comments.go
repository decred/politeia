// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"

	"github.com/decred/politeia/decredplugin"
	pd "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/cache"
	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/decred/politeia/util"
)

// initCommentScores populates the comment scores cache.
func (p *politeiawww) initCommentScores() error {
	log.Tracef("initCommentScores")

	// Fetch decred plugin inventory from cache
	ir, err := p.decredInventory()
	if err != nil {
		return fmt.Errorf("decredInventory: %v", err)
	}

	// XXX this could be done much more efficiently since we
	// already have all of the like comments in the inventory
	// response, but re-using the updateCommentScore function is
	// simpler. This only gets run on startup so I'm not that
	// worried about performance for right now.
	for _, v := range ir.Comments {
		_, err := p.updateCommentScore(v.Token, v.CommentID)
		if err != nil {
			return fmt.Errorf("updateCommentScore: %v", err)
		}
	}

	return nil
}

// getComment retreives the specified comment from the cache then fills in
// politeiawww specific data for the comment.
func (p *politeiawww) getComment(token, commentID string) (*www.Comment, error) {
	// Fetch comment from the cache
	dc, err := p.decredGetComment(token, commentID)
	if err != nil {
		return nil, fmt.Errorf("decredGetComment: %v", err)
	}
	c := convertCommentFromDecred(*dc)

	p.RLock()
	defer p.RUnlock()

	// Lookup comment vote score
	score, ok := p.commentScores[token+commentID]
	if !ok {
		log.Errorf("getComment: comment score lookup failed for "+
			"token:%v commentID:%v", token, commentID)
	}
	c.ResultVotes = score

	// Lookup author info
	userID, ok := p.userPubkeys[c.PublicKey]
	if !ok {
		log.Errorf("getComment: userID lookup failed for pubkey:%v "+
			"token:%v commentID:%v", c.PublicKey, token, commentID)
	}
	c.UserID = userID
	c.Username = p.getUsernameById(userID)

	return &c, nil
}

// updateCommentScore calculates the comment score for the specified comment
// then updates the in-memory comment score cache.
func (p *politeiawww) updateCommentScore(token, commentID string) (int64, error) {
	log.Tracef("updateCommentScore: %v %v", token, commentID)

	// Fetch all comment likes for the specified comment
	likes, err := p.decredCommentLikes(token, commentID)
	if err != nil {
		return 0, fmt.Errorf("decredLikeComments: %v", err)
	}

	// Sanity check. Like comments should already be sorted in
	// chronological order.
	sort.SliceStable(likes, func(i, j int) bool {
		return likes[i].Timestamp < likes[j].Timestamp
	})

	p.Lock()
	defer p.Unlock()

	// Compute the comment score. We have to keep track of each
	// user's most recent like action because the net effect of an
	// upvote/downvote on the comment score is dependent on the
	// user's previous action. Example: a user upvoting a comment
	// twice results in a net score of 0 because the second upvote
	// is actually the user taking away their original upvote.
	var score int64
	userActions := make(map[string]int64) // [userID]action
	for _, v := range likes {
		action, err := strconv.ParseInt(v.Action, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("parse action '%v' failed on "+
				"commentID %v: %v", v.Action, v.CommentID, err)
		}

		// Lookup the userID of the comment author
		userID, ok := p.userPubkeys[v.PublicKey]
		if !ok {
			return 0, fmt.Errorf("userID lookup failed for pubkey %v",
				v.PublicKey)
		}

		// Lookup the previous like comment action that the author
		// made on this comment
		prevAction := userActions[userID]

		switch {
		case prevAction == 0:
			// No previous action so we add the new action to the
			// vote score
			score += action
			userActions[userID] = action

		case prevAction == action:
			// New action is the same as the previous action so we
			// remove the previous action from the vote score
			score -= prevAction
			userActions[userID] = 0

		case prevAction != action:
			// New action is different than the previous action so
			// we remove the previous action from the vote score
			// and then add the new action to the vote score
			score -= prevAction
			score += action
			userActions[userID] = action
		}
	}

	// Set final comment likes score
	p.commentScores[token+commentID] = score

	return score, nil
}

func validateComment(c www.NewComment) error {
	// max length
	if len(c.Comment) > www.PolicyMaxCommentLength {
		return www.UserError{
			ErrorCode: www.ErrorStatusCommentLengthExceededPolicy,
		}
	}
	// validate token
	_, err := util.ConvertStringToken(c.Token)
	if err != nil && err.Error() == "invalid censorship token size" {
		err = www.UserError{
			ErrorCode: www.ErrorStatusInvalidCensorshipToken,
		}
	}
	return err
}

// processNewComment sends a new comment decred plugin command to politeaid
// then fetches the new comment from the cache and returns it.
func (p *politeiawww) processNewComment(nc www.NewComment, u *user.User) (*www.NewCommentReply, error) {
	log.Tracef("processNewComment: %v %v", nc.Token, u.ID)

	// Pay up sucker!
	if !p.HasUserPaid(u) {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusUserNotPaid,
		}
	}

	// Verify authenticity
	err := checkPublicKeyAndSignature(u, nc.PublicKey, nc.Signature,
		nc.Token, nc.ParentID, nc.Comment)
	if err != nil {
		return nil, err
	}

	// Validate comment
	err = validateComment(nc)
	if err != nil {
		return nil, err
	}

	// Ensure proposal exists and is public
	pr, err := p.getProp(nc.Token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: www.ErrorStatusProposalNotFound,
			}
		}
		return nil, err
	}

	if pr.Status != www.PropStatusPublic {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusCannotCommentOnProp,
		}
	}

	// Ensure proposal voting has not ended
	vdr, err := p.decredVoteDetails(nc.Token)
	if err != nil {
		return nil, fmt.Errorf("decredVoteDetails: %v", err)
	}
	_, avr := convertAuthVoteFromDecred(vdr.AuthorizeVote)
	svr := convertStartVoteReplyFromDecred(vdr.StartVoteReply)

	bb, err := p.getBestBlock()
	if err != nil {
		return nil, fmt.Errorf("getBestBlock: %v", err)
	}

	if getVoteStatus(avr, svr, bb) == www.PropVoteStatusFinished {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusWrongVoteStatus,
		}
	}

	// Setup plugin command
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	dnc := convertNewCommentToDecredPlugin(nc)
	payload, err := decredplugin.EncodeNewComment(dnc)
	if err != nil {
		return nil, err
	}

	pc := pd.PluginCommand{
		Challenge: hex.EncodeToString(challenge),
		ID:        decredplugin.ID,
		Command:   decredplugin.CmdNewComment,
		CommandID: decredplugin.CmdNewComment,
		Payload:   string(payload),
	}

	// Send polieiad request
	responseBody, err := p.makeRequest(http.MethodPost,
		pd.PluginCommandRoute, pc)
	if err != nil {
		return nil, err
	}

	// Handle response
	var reply pd.PluginCommandReply
	err = json.Unmarshal(responseBody, &reply)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal "+
			"PluginCommandReply: %v", err)
	}

	err = util.VerifyChallenge(p.cfg.Identity, challenge, reply.Response)
	if err != nil {
		return nil, err
	}

	ncr, err := decredplugin.DecodeNewCommentReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}

	// Add comment to commentScores in-memory cache
	p.Lock()
	p.commentScores[nc.Token+ncr.CommentID] = 0
	p.Unlock()

	// Get comment from cache
	c, err := p.getComment(nc.Token, ncr.CommentID)
	if err != nil {
		return nil, fmt.Errorf("getComment: %v", err)
	}

	// Fire off new comment event
	p.fireEvent(EventTypeComment, EventDataComment{
		Comment: c,
	})

	return &www.NewCommentReply{
		Comment: *c,
	}, nil
}

// processNewCommentInvoice sends a new comment decred plugin command to politeaid
// then fetches the new comment from the cache and returns it.
func (p *politeiawww) processNewCommentInvoice(nc www.NewComment, u *user.User) (*www.NewCommentReply, error) {
	log.Tracef("processNewComment: %v %v", nc.Token, u.ID)

	ir, err := p.getInvoice(nc.Token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: www.ErrorStatusInvoiceNotFound,
			}
		}
		return nil, err
	}

	_, ok := p.userPubkeys[ir.PublicKey]

	// Check to make sure the user is either an admin or the creator of the invoice
	if !u.Admin && !ok {
		err := www.UserError{
			ErrorCode: www.ErrorStatusUserActionNotAllowed,
		}
		return nil, err
	}

	// Verify authenticity
	err = checkPublicKeyAndSignature(u, nc.PublicKey, nc.Signature,
		nc.Token, nc.ParentID, nc.Comment)
	if err != nil {
		return nil, err
	}

	// Validate comment
	err = validateComment(nc)
	if err != nil {
		return nil, err
	}

	// Check to make sure that invoice isn't already approved or paid.
	if ir.Status == cms.InvoiceStatusApproved || ir.Status == cms.InvoiceStatusPaid {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusCannotCommentOnProp,
		}
	}

	// Setup plugin command
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	dnc := convertNewCommentToDecredPlugin(nc)
	payload, err := decredplugin.EncodeNewComment(dnc)
	if err != nil {
		return nil, err
	}

	pc := pd.PluginCommand{
		Challenge: hex.EncodeToString(challenge),
		ID:        decredplugin.ID,
		Command:   decredplugin.CmdNewComment,
		CommandID: decredplugin.CmdNewComment,
		Payload:   string(payload),
	}

	// Send polieiad request
	responseBody, err := p.makeRequest(http.MethodPost,
		pd.PluginCommandRoute, pc)
	if err != nil {
		return nil, err
	}

	// Handle response
	var reply pd.PluginCommandReply
	err = json.Unmarshal(responseBody, &reply)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal "+
			"PluginCommandReply: %v", err)
	}

	err = util.VerifyChallenge(p.cfg.Identity, challenge, reply.Response)
	if err != nil {
		return nil, err
	}

	ncr, err := decredplugin.DecodeNewCommentReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}

	// Add comment to commentScores in-memory cache
	p.Lock()
	p.commentScores[nc.Token+ncr.CommentID] = 0
	p.Unlock()

	// Get comment from cache
	c, err := p.getComment(nc.Token, ncr.CommentID)
	if err != nil {
		return nil, fmt.Errorf("getComment: %v", err)
	}

	// Fire off new comment event
	/*
		// XXX This is implemented only for proposal comments.  If we want email
		// notifications for cms here is where to add the updated impls.
		p.fireEvent(EventTypeComment, EventDataComment{
			Comment: c,
		})
	*/
	return &www.NewCommentReply{
		Comment: *c,
	}, nil
}

// processLikeComment processes an upvote/downvote on a comment.
func (p *politeiawww) processLikeComment(lc www.LikeComment, u *user.User) (*www.LikeCommentReply, error) {
	log.Debugf("processLikeComment: %v %v %v", lc.Token, lc.CommentID, u.ID)

	// Pay up sucker!
	if !p.HasUserPaid(u) {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusUserNotPaid,
		}
	}

	// Verify authenticity
	err := checkPublicKeyAndSignature(u, lc.PublicKey, lc.Signature,
		lc.Token, lc.CommentID, lc.Action)
	if err != nil {
		return nil, err
	}

	// Ensure proposal exists and is public
	pr, err := p.getProp(lc.Token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: www.ErrorStatusProposalNotFound,
			}
		}
		return nil, err
	}

	if pr.Status != www.PropStatusPublic {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusWrongStatus,
		}
	}

	// Ensure proposal voting has not ended
	vdr, err := p.decredVoteDetails(lc.Token)
	if err != nil {
		return nil, fmt.Errorf("decredVoteDetails: %v", err)
	}
	vd := convertVoteDetailsReplyFromDecred(*vdr)

	bb, err := p.getBestBlock()
	if err != nil {
		return nil, fmt.Errorf("getBestBlock: %v", err)
	}

	s := getVoteStatus(vd.AuthorizeVoteReply, vd.StartVoteReply, bb)
	if s == www.PropVoteStatusFinished {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusWrongVoteStatus,
		}
	}

	// Ensure comment exists
	_, err = p.decredGetComment(lc.Token, lc.CommentID)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: www.ErrorStatusCommentNotFound,
			}
		}
		return nil, err
	}

	// Validate action
	action := lc.Action
	if len(lc.Action) > 10 {
		// Clip action to not fill up logs and prevent DOS of sorts
		action = lc.Action[0:9] + "..."
	}
	if action != "1" && action != "-1" {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidLikeCommentAction,
		}
	}

	// Setup plugin command
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	dlc := convertLikeCommentToDecred(lc)
	payload, err := decredplugin.EncodeLikeComment(dlc)
	if err != nil {
		return nil, err
	}

	pc := pd.PluginCommand{
		Challenge: hex.EncodeToString(challenge),
		ID:        decredplugin.ID,
		Command:   decredplugin.CmdLikeComment,
		CommandID: decredplugin.CmdLikeComment,
		Payload:   string(payload),
	}

	// Send plugin command to politeiad
	responseBody, err := p.makeRequest(http.MethodPost,
		pd.PluginCommandRoute, pc)
	if err != nil {
		return nil, err
	}

	// Handle response
	var reply pd.PluginCommandReply
	err = json.Unmarshal(responseBody, &reply)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal "+
			"PluginCommandReply: %v", err)
	}

	err = util.VerifyChallenge(p.cfg.Identity, challenge, reply.Response)
	if err != nil {
		return nil, err
	}

	lcr, err := decredplugin.DecodeLikeCommentReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}

	// Update comment score in the in-memory cache
	result, err := p.updateCommentScore(lc.Token, lc.CommentID)
	if err != nil {
		log.Criticalf("processLikeComment: update comment score "+
			"failed token:%v commentID:%v error:%v", lc.Token,
			lc.CommentID, err)
	}

	return &www.LikeCommentReply{
		Result:  result,
		Receipt: lcr.Receipt,
		Error:   lcr.Error,
	}, nil
}

// processCensorComment sends a censor comment decred plugin command to
// politeiad then returns the censor comment receipt.
func (p *politeiawww) processCensorComment(cc www.CensorComment, u *user.User) (*www.CensorCommentReply, error) {
	log.Tracef("processCensorComment: %v: %v", cc.Token, cc.CommentID)

	// Verify authenticity
	err := checkPublicKeyAndSignature(u, cc.PublicKey, cc.Signature,
		cc.Token, cc.CommentID, cc.Reason)
	if err != nil {
		return nil, err
	}

	// Ensure censor reason is present
	if cc.Reason == "" {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusCensorReasonCannotBeBlank,
		}
	}

	// Ensure comment exists and has not already been censored
	c, err := p.decredGetComment(cc.Token, cc.CommentID)
	if err != nil {
		return nil, fmt.Errorf("decredGetComment: %v", err)
	}
	if c.Censored {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusCommentNotFound,
		}
	}

	// Ensure proposal voting has not ended
	vdr, err := p.decredVoteDetails(cc.Token)
	if err != nil {
		return nil, fmt.Errorf("decredVoteDetails: %v", err)
	}
	vd := convertVoteDetailsReplyFromDecred(*vdr)

	bb, err := p.getBestBlock()
	if err != nil {
		return nil, fmt.Errorf("getBestBlock: %v", err)
	}

	s := getVoteStatus(vd.AuthorizeVoteReply, vd.StartVoteReply, bb)
	if s == www.PropVoteStatusFinished {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusWrongVoteStatus,
		}
	}

	// Setup plugin command
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	dcc := convertCensorCommentToDecred(cc)
	payload, err := decredplugin.EncodeCensorComment(dcc)
	if err != nil {
		return nil, err
	}

	pc := pd.PluginCommand{
		Challenge: hex.EncodeToString(challenge),
		ID:        decredplugin.ID,
		Command:   decredplugin.CmdCensorComment,
		CommandID: decredplugin.CmdCensorComment,
		Payload:   string(payload),
	}

	// Send plugin request
	responseBody, err := p.makeRequest(http.MethodPost,
		pd.PluginCommandRoute, pc)
	if err != nil {
		return nil, err
	}

	// Handle response
	var reply pd.PluginCommandReply
	err = json.Unmarshal(responseBody, &reply)
	if err != nil {
		return nil, err
	}

	err = util.VerifyChallenge(p.cfg.Identity, challenge, reply.Response)
	if err != nil {
		return nil, err
	}

	ccr, err := decredplugin.DecodeCensorCommentReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}

	return &www.CensorCommentReply{
		Receipt: ccr.Receipt,
	}, nil
}
