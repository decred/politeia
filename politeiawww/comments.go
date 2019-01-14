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
	www "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/politeiawww/database"
	"github.com/decred/politeia/util"
)

// This function must be called WITHOUT the mutex held.
func (b *backend) getComment(token, commentID string) (*www.Comment, error) {
	// Fetch comment from the cache
	dc, err := b.decredGetComment(token, commentID)
	if err != nil {
		return nil, fmt.Errorf("decredGetComment: %v", err)
	}
	c := convertCommentFromDecred(*dc)

	b.RLock()
	defer b.RUnlock()

	// Lookup comment vote score
	score, ok := b.commentScores[token+commentID]
	if !ok {
		log.Errorf("getComment: comment score lookup failed for "+
			"token:%v commentID:%v", token, commentID)
	}
	c.ResultVotes = score

	// Lookup author info
	userID, ok := b.userPubkeys[c.PublicKey]
	if !ok {
		log.Errorf("getComment: userID lookup failed for pubkey:%v "+
			"token:%v commentID:%v", c.PublicKey, token, commentID)
	}
	c.UserID = userID
	c.Username = b.getUsernameById(userID)

	return &c, nil
}

// This function must be called WITHOUT the mutex held.
func (b *backend) updateCommentScore(token, commentID string) (int64, error) {
	log.Tracef("updateCommentScore: %v %v", token, commentID)

	// Fetch all comment likes for the specified comment
	likes, err := b.decredLikeComments(token, commentID)
	if err != nil {
		return 0, fmt.Errorf("decredLikeComments: %v")
	}

	// Sanity check. Like comments should already be sorted in
	// chronological order.
	sort.SliceStable(likes, func(i, j int) bool {
		return likes[i].Timestamp < likes[j].Timestamp
	})

	b.Lock()
	defer b.Unlock()

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
		userID, ok := b.userPubkeys[v.PublicKey]
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
	b.commentScores[token+commentID] = score

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

// ProcessNewComment sends a new comment decred plugin command to politeaid
// then fetches the new comment from the cache and returns it.
func (b *backend) ProcessNewComment(nc www.NewComment, user *database.User) (*www.NewCommentReply, error) {
	log.Tracef("ProcessNewComment: %v %v", nc.Token, user.ID)

	// Pay up sucker!
	if !b.HasUserPaid(user) {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusUserNotPaid,
		}
	}

	// Verify authenticity
	err := checkPublicKeyAndSignature(user, nc.PublicKey, nc.Signature,
		nc.Token, nc.ParentID, nc.Comment)
	if err != nil {
		return nil, err
	}

	// Validate comment
	err = validateComment(nc)
	if err != nil {
		return nil, err
	}

	// Get proposal from the cache
	pr, err := b.getProp(nc.Token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: www.ErrorStatusProposalNotFound,
			}
		}
		return nil, err
	}

	// Make sure the proposal is public
	if pr.Status != www.PropStatusPublic {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusCannotCommentOnProp,
		}
	}

	ir, err := b.getInventoryRecord(nc.Token)
	if err != nil {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusProposalNotFound,
		}
	}

	// Make sure the proposal voting has not ended
	bb, err := b.getBestBlock()
	if err != nil {
		return nil, fmt.Errorf("getBestBlock: %v", err)
	}

	if getVoteStatus(ir, bb) == www.PropVoteStatusFinished {
		// vote is finished
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
	responseBody, err := b.makeRequest(http.MethodPost,
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

	err = util.VerifyChallenge(b.cfg.Identity, challenge, reply.Response)
	if err != nil {
		return nil, err
	}

	ncr, err := decredplugin.DecodeNewCommentReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}

	// Add comment to commentScores in-memory cache
	b.Lock()
	b.commentScores[nc.Token+ncr.CommentID] = 0
	b.Unlock()

	// Get comment from cache
	c, err := b.getComment(nc.Token, ncr.CommentID)
	if err != nil {
		return nil, fmt.Errorf("getComment: %v", err)
	}

	// Fire off new comment event
	b.fireEvent(EventTypeComment, EventDataComment{
		Comment: c,
	})

	return &www.NewCommentReply{
		Comment: *c,
	}, nil
}

// ProcessLikeComment processes an upvote/downvote on a comment.
func (b *backend) ProcessLikeComment(lc www.LikeComment, user *database.User) (*www.LikeCommentReply, error) {
	log.Debugf("ProcessLikeComment: %v %v %v", lc.Token, lc.CommentID, user.ID)

	// Pay up sucker!
	if !b.HasUserPaid(user) {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusUserNotPaid,
		}
	}

	// Verify authenticity
	err := checkPublicKeyAndSignature(user, lc.PublicKey, lc.Signature,
		lc.Token, lc.CommentID, lc.Action)
	if err != nil {
		return nil, err
	}

	// Get proposal from cache
	pr, err := b.getProp(lc.Token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: www.ErrorStatusProposalNotFound,
			}
		}
		return nil, err
	}

	// Ensure proposal is public
	if pr.Status != www.PropStatusPublic {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusWrongStatus,
		}
	}

	// Make sure the proposal voting has not ended
	ir, err := b.getInventoryRecord(lc.Token)
	if err != nil {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusProposalNotFound,
		}
	}

	bb, err := b.getBestBlock()
	if err != nil {
		return nil, fmt.Errorf("getBestBlock: %v", err)
	}

	if getVoteStatus(ir, bb) == www.PropVoteStatusFinished {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusWrongVoteStatus,
		}
	}

	// Ensure comment exists
	_, err = b.decredGetComment(lc.Token, lc.CommentID)
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
	responseBody, err := b.makeRequest(http.MethodPost,
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

	err = util.VerifyChallenge(b.cfg.Identity, challenge, reply.Response)
	if err != nil {
		return nil, err
	}

	lcr, err := decredplugin.DecodeLikeCommentReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}

	// Update comment score in the in-memory cache
	result, err := b.updateCommentScore(lc.Token, lc.CommentID)
	if err != nil {
		log.Criticalf("ProcessLikeComment: update comment score failed "+
			"token:%v commentID:%v error:%v", lc.Token, lc.CommentID, err)
	}

	return &www.LikeCommentReply{
		Result:  result,
		Receipt: lcr.Receipt,
		Error:   lcr.Error,
	}, nil
}

// ProcessCensorComment sends a censor comment decred plugin command to
// politeiad then returns the censor comment receipt.
func (b *backend) ProcessCensorComment(cc www.CensorComment, user *database.User) (*www.CensorCommentReply, error) {
	log.Tracef("ProcessCensorComment: %v: %v", cc.Token, cc.CommentID)

	// Verify authenticity
	err := checkPublicKeyAndSignature(user, cc.PublicKey, cc.Signature,
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
	c, err := b.decredGetComment(cc.Token, cc.CommentID)
	if err != nil {
		return nil, fmt.Errorf("decredGetComment: %v", err)
	}
	if c.Censored {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusCommentNotFound,
		}
	}

	// get the proposal record from inventory
	b.RLock()
	ir, err := b._getInventoryRecord(cc.Token)
	b.RUnlock()
	if err != nil {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusProposalNotFound,
		}
	}

	// Ensure proposal voting has not ended
	bb, err := b.getBestBlock()
	if err != nil {
		return nil, fmt.Errorf("getBestBlock: %v", err)
	}

	if getVoteStatus(ir, bb) == www.PropVoteStatusFinished {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusCannotCensorComment,
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
	responseBody, err := b.makeRequest(http.MethodPost,
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

	err = util.VerifyChallenge(b.cfg.Identity, challenge, reply.Response)
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
