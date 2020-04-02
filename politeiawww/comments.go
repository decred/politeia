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

	"github.com/thi4go/politeia/decredplugin"
	pd "github.com/thi4go/politeia/politeiad/api/v1"
	"github.com/thi4go/politeia/politeiad/cache"
	cms "github.com/thi4go/politeia/politeiawww/api/cms/v1"
	www "github.com/thi4go/politeia/politeiawww/api/www/v1"
	"github.com/thi4go/politeia/politeiawww/user"
	"github.com/thi4go/politeia/util"
)

// counters is a struct that helps us keep track of up/down votes.
type counters struct {
	up   uint64
	down uint64
}

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
	// response, but re-using the updateCommentVotes function is
	// simpler. This only gets run on startup so I'm not that
	// worried about performance for right now.
	for _, v := range ir.Comments {
		_, err := p.updateCommentVotes(v.Token, v.CommentID)
		if err != nil {
			return fmt.Errorf("updateCommentVotes: %v", err)
		}
	}

	return nil
}

// getComment retreives the specified comment from the cache then fills in
// politeiawww specific data for the comment.
func (p *politeiawww) getComment(token, commentID string) (*www.Comment, error) {
	// Fetch comment from the cache
	dc, err := p.decredCommentGetByID(token, commentID)
	if err != nil {
		return nil, fmt.Errorf("decredGetComment: %v", err)
	}
	c := convertCommentFromDecred(*dc)

	// Lookup author info
	u, err := p.db.UserGetByPubKey(c.PublicKey)
	if err != nil {
		log.Errorf("getComment: UserGetByPubKey: token:%v commentID:%v "+
			"pubKey:%v err:%v", token, commentID, c.PublicKey, err)
	} else {
		c.UserID = u.ID.String()
		c.Username = u.Username
	}

	// Lookup comment votes
	p.RLock()
	defer p.RUnlock()

	votes, ok := p.commentVotes[token+commentID]
	if !ok {
		log.Errorf("getComment: comment votes lookup failed for "+
			"token:%v commentID:%v", token, commentID)
	}
	c.ResultVotes = int64(votes.up - votes.down)
	c.Upvotes = votes.up
	c.Downvotes = votes.down

	return &c, nil
}

// updateCommentVotes calculates the up/down votes for the specified comment,
// updates the in-memory comment votes cache with these and returns them.
func (p *politeiawww) updateCommentVotes(token, commentID string) (*counters, error) {
	log.Tracef("updateCommentVotes: %v %v", token, commentID)

	// Fetch all comment likes for the specified comment
	likes, err := p.decredCommentLikes(token, commentID)
	if err != nil {
		return nil, fmt.Errorf("decredLikeComments: %v", err)
	}

	// Sanity check. Like comments should already be sorted in
	// chronological order.
	sort.SliceStable(likes, func(i, j int) bool {
		return likes[i].Timestamp < likes[j].Timestamp
	})

	p.Lock()
	defer p.Unlock()

	// Compute the comment votes. We have to keep track of each user's most
	// recent like action because the net effect of an upvote/downvote is
	// dependent on the user's previous action.
	// Example: a user upvoting a comment twice results in a net score of 0
	// because the second upvote is actually the user taking away their original
	// upvote.
	var votes counters
	userActions := make(map[string]string) // [userID]action
	for _, v := range likes {
		// Lookup the userID of the comment author
		u, err := p.db.UserGetByPubKey(v.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("user lookup failed for pubkey %v",
				v.PublicKey)
		}
		userID := u.ID.String()

		// Lookup the previous like comment action that the author
		// made on this comment
		prevAction := userActions[userID]

		switch {
		case prevAction == "":
			// No previous action so we add the new action to the
			// vote score
			switch v.Action {
			case www.VoteActionDown:
				votes.down += 1
			case www.VoteActionUp:
				votes.up += 1
			}
			userActions[userID] = v.Action

		case prevAction == v.Action:
			// New action is the same as the previous action so we
			// remove the previous action from the vote score
			switch prevAction {
			case www.VoteActionDown:
				votes.down -= 1
			case www.VoteActionUp:
				votes.up -= 1
			}
			delete(userActions, userID)

		case prevAction != v.Action:
			// New action is different than the previous action so
			// we remove the previous action from the vote score..
			switch prevAction {
			case www.VoteActionDown:
				votes.down -= 1
			case www.VoteActionUp:
				votes.up -= 1
			}

			// ..and then add the new action to the vote score
			switch v.Action {
			case www.VoteActionDown:
				votes.down += 1
			case www.VoteActionUp:
				votes.up += 1
			}
			userActions[userID] = v.Action
		}
	}

	// Update in-memory cache
	p.commentVotes[token+commentID] = votes

	return &votes, nil
}

func validateComment(c www.NewComment) error {
	// max length
	if len(c.Comment) > www.PolicyMaxCommentLength {
		return www.UserError{
			ErrorCode: www.ErrorStatusCommentLengthExceededPolicy,
		}
	}
	// validate token
	if !tokenIsValid(c.Token) {
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidCensorshipToken,
		}
	}
	return nil
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

	// Ensure the public key is the user's active key
	if nc.PublicKey != u.PublicKey() {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidSigningKey,
		}
	}

	// Validate signature
	msg := nc.Token + nc.ParentID + nc.Comment
	err := validateSignature(nc.PublicKey, nc.Signature, msg)
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
			ErrorCode:    www.ErrorStatusWrongStatus,
			ErrorContext: []string{"proposal is not public"},
		}
	}

	// Ensure proposal voting has not ended
	vsr, err := p.decredVoteSummary(nc.Token)
	if err != nil {
		return nil, fmt.Errorf("decredVoteSummary: %v", err)
	}
	bb, err := p.getBestBlock()
	if err != nil {
		return nil, fmt.Errorf("getBestBlock: %v", err)
	}
	s := voteStatusFromVoteSummary(*vsr, bb)
	if s == www.PropVoteStatusFinished {
		return nil, www.UserError{
			ErrorCode:    www.ErrorStatusWrongVoteStatus,
			ErrorContext: []string{"vote is finished"},
		}
	}

	// Ensure the comment is not a duplicate
	_, err = p.decredCommentGetBySignature(nc.Token, nc.Signature)
	switch err {
	case nil:
		// Duplicate comment was found
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusDuplicateComment,
		}
	case cache.ErrRecordNotFound:
		// No duplicate comment; continue
	default:
		// Some other error
		return nil, fmt.Errorf("decredCommentBySignature: %v", err)
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

	// Add comment to commentVotes in-memory cache
	p.Lock()
	p.commentVotes[nc.Token+ncr.CommentID] = counters{}
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
				ErrorCode: cms.ErrorStatusInvoiceNotFound,
			}
		}
		return nil, err
	}

	// Check to make sure the user is either an admin or the
	// author of the invoice.
	if !u.Admin && (ir.Username != u.Username) {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusUserActionNotAllowed,
		}
	}

	// Ensure the public key is the user's active key
	if nc.PublicKey != u.PublicKey() {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidSigningKey,
		}
	}

	// Validate signature
	msg := nc.Token + nc.ParentID + nc.Comment
	err = validateSignature(nc.PublicKey, nc.Signature, msg)
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
			ErrorCode: cms.ErrorStatusWrongInvoiceStatus,
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

	// Add comment to commentVotes in-memory cache
	p.Lock()
	p.commentVotes[nc.Token+ncr.CommentID] = counters{}
	p.Unlock()

	// Get comment from cache
	c, err := p.getComment(nc.Token, ncr.CommentID)
	if err != nil {
		return nil, fmt.Errorf("getComment: %v", err)
	}

	if u.Admin {
		invoiceUser, err := p.db.UserGetByUsername(ir.Username)
		if err != nil {
			return nil, fmt.Errorf("failed to get user by username %v %v",
				ir.Username, err)
		}
		// Fire off new invoice comment event
		p.fireEvent(EventTypeInvoiceComment,
			EventDataInvoiceComment{
				Token: nc.Token,
				User:  invoiceUser,
			},
		)
	}
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

	// Ensure the public key is the user's active key
	if lc.PublicKey != u.PublicKey() {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidSigningKey,
		}
	}

	// Validate signature
	msg := lc.Token + lc.CommentID + lc.Action
	err := validateSignature(lc.PublicKey, lc.Signature, msg)
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
	vsr, err := p.decredVoteSummary(pr.CensorshipRecord.Token)
	if err != nil {
		return nil, err
	}
	bb, err := p.getBestBlock()
	if err != nil {
		return nil, fmt.Errorf("getBestBlock: %v", err)
	}
	s := voteStatusFromVoteSummary(*vsr, bb)
	if s == www.PropVoteStatusFinished {
		return nil, www.UserError{
			ErrorCode:    www.ErrorStatusWrongVoteStatus,
			ErrorContext: []string{"vote has ended"},
		}
	}

	// Ensure comment exists and has not been censored.
	c, err := p.decredCommentGetByID(lc.Token, lc.CommentID)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: www.ErrorStatusCommentNotFound,
			}
		}
		return nil, err
	}
	if c.Censored {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusCommentIsCensored,
		}
	}

	// Validate action
	action := lc.Action
	if len(lc.Action) > 10 {
		// Clip action to not fill up logs and prevent DOS of sorts
		action = lc.Action[0:9] + "..."
	}
	if action != www.VoteActionUp && action != www.VoteActionDown {
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
	votes, err := p.updateCommentVotes(lc.Token, lc.CommentID)
	if err != nil {
		log.Criticalf("processLikeComment: update comment score "+
			"failed token:%v commentID:%v error:%v", lc.Token,
			lc.CommentID, err)
	}

	return &www.LikeCommentReply{
		Result:    int64(votes.up - votes.down),
		Upvotes:   votes.up,
		Downvotes: votes.down,
		Receipt:   lcr.Receipt,
		Error:     lcr.Error,
	}, nil
}

// processCensorComment sends a censor comment decred plugin command to
// politeiad then returns the censor comment receipt.
func (p *politeiawww) processCensorComment(cc www.CensorComment, u *user.User) (*www.CensorCommentReply, error) {
	log.Tracef("processCensorComment: %v: %v", cc.Token, cc.CommentID)

	// Ensure the public key is the user's active key
	if cc.PublicKey != u.PublicKey() {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidSigningKey,
		}
	}

	// Validate signature
	msg := cc.Token + cc.CommentID + cc.Reason
	err := validateSignature(cc.PublicKey, cc.Signature, msg)
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
	c, err := p.decredCommentGetByID(cc.Token, cc.CommentID)
	if err != nil {
		return nil, fmt.Errorf("decredGetComment: %v", err)
	}
	if c.Censored {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusCommentNotFound,
		}
	}

	// Ensure proposal voting has not ended
	vsr, err := p.decredVoteSummary(cc.Token)
	if err != nil {
		return nil, err
	}
	bb, err := p.getBestBlock()
	if err != nil {
		return nil, fmt.Errorf("getBestBlock: %v", err)
	}
	s := voteStatusFromVoteSummary(*vsr, bb)
	if s == www.PropVoteStatusFinished {
		return nil, www.UserError{
			ErrorCode:    www.ErrorStatusWrongVoteStatus,
			ErrorContext: []string{"vote has ended"},
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
