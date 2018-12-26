package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/decred/politeia/decredplugin"
	pd "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/cache"
	www "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/politeiawww/database"
	"github.com/decred/politeia/util"
)

func convertWWWLikeCommentToDecredLikeComment(lc www.LikeComment) decredplugin.LikeComment {
	return decredplugin.LikeComment{
		Token:     lc.Token,
		CommentID: lc.CommentID,
		Action:    lc.Action,
		Signature: lc.Signature,
		PublicKey: lc.PublicKey,
	}
}

func convertDecredLikeCommentToWWWLikeComment(lc decredplugin.LikeComment) www.LikeComment {
	return www.LikeComment{
		Token:     lc.Token,
		CommentID: lc.CommentID,
		Action:    lc.Action,
		Signature: lc.Signature,
		PublicKey: lc.PublicKey,
	}
}

func convertDecredLikeCommentReplyToWWWLikeCommentReply(lcr decredplugin.LikeCommentReply) www.LikeCommentReply {
	return www.LikeCommentReply{
		Total:   lcr.Total,
		Result:  lcr.Result,
		Receipt: lcr.Receipt,
		Error:   lcr.Error,
	}
}

// getComments returns all comments for given proposal token.  Note that the
// comments are not sorted.
// This call must be called WITHOUT the lock held.
func (b *backend) getComments(token string) (*www.GetCommentsReply, error) {
	b.RLock()
	defer b.RUnlock()

	c, ok := b.inventory[token]
	if !ok {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusProposalNotFound,
		}
	}

	gcr := &www.GetCommentsReply{
		Comments: make([]www.Comment, 0, len(c.comments)),
	}

	// create a map to cache found usernames so it doesn't query
	// the database for every comment
	usernameByID := map[string]string{}

	for _, v := range c.comments {

		if username, ok := usernameByID[v.UserID]; ok && username != "" {
			v.Username = username
		} else {
			v.Username = b.getUsernameById(v.UserID)
			usernameByID[v.UserID] = username
		}

		gcr.Comments = append(gcr.Comments, v)
	}

	return gcr, nil
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
	return err
}

// updateResultsForCommentLike updates the comment total votes, the votes
// results and the vote resultant action for the user
//
// This function must be called WITHOUT the mutex held
func (b *backend) updateResultsForCommentLike(like www.LikeComment) (*www.Comment, error) {
	b.Lock()
	defer b.Unlock()
	return b._updateResultsForCommentLike(like)
}

// _updateResultsForCommentLike updates the comment total votes, the votes
// results and the vote resultant action for the user
//
// This function must be called WITH the mutex held
func (b *backend) _updateResultsForCommentLike(like www.LikeComment) (*www.Comment, error) {
	userID := b.userPubkeys[like.PublicKey]
	token := like.Token
	commentID := like.CommentID

	// get comment from inventory cache
	comment, err := b._getInventoryRecordComment(token, commentID)
	if err != nil {
		return nil, fmt.Errorf("Comment not found %v: %v", token, commentID)
	}

	newUserVoteAction, err := strconv.ParseInt(like.Action, 10, 64)
	if err != nil {
		// sanity check
		return nil, fmt.Errorf(
			"updateResutsForCommentLike for %s, %s: action conversion failed: %v",
			token, commentID, err)
	}

	if _, ok := b.userLikeActionByCommentID[token]; !ok {
		b.userLikeActionByCommentID[token] = make(map[string]map[string]int64)
	}

	if _, ok := b.userLikeActionByCommentID[token][userID]; !ok {
		b.userLikeActionByCommentID[token][userID] = make(map[string]int64)
	}
	// Simply add the like to the totals if the user has not
	// previously voted on this comment
	lastUserVoteAction, hasVoted := b.userLikeActionByCommentID[token][userID][commentID]
	if !hasVoted {
		b.userLikeActionByCommentID[token][userID][commentID] = newUserVoteAction
		comment.ResultVotes += newUserVoteAction
		comment.TotalVotes++
	} else if lastUserVoteAction == newUserVoteAction {
		// new action is equals the previous one, so we
		// revert last user action
		b.userLikeActionByCommentID[token][userID][commentID] = 0
		comment.ResultVotes -= newUserVoteAction
		comment.TotalVotes--
	} else {
		// new action is different from the previous one
		// so the new action is set as the current one
		b.userLikeActionByCommentID[token][userID][commentID] = newUserVoteAction
		comment.ResultVotes += newUserVoteAction - lastUserVoteAction
		// only update the total if last user action was 0
		if lastUserVoteAction == 0 {
			comment.TotalVotes++
		}
	}

	err = b._setRecordComment(*comment)
	if err != nil {
		return nil, err
	}

	return comment, nil
}

// TODO: get rid of setRecordComment
// _setRecordComment sets a comment alongside the record's comments (if any)
// this can be used for adding or updating a comment
//
// This function must be called WITH the mutex held
func (b *backend) _setRecordComment(comment www.Comment) error {
	// Sanity check
	_, ok := b.inventory[comment.Token]
	if !ok {
		return fmt.Errorf("inventory record not found: %v", comment.Token)
	}

	// set record comment
	b.inventory[comment.Token].comments[comment.CommentID] = comment

	return nil
}

// setRecordComment sets a comment alongside the record's comments (if any)
// this can be used for adding or updating a comment
//
// This function must be called WITHOUT the mutex held
func (b *backend) setRecordComment(comment www.Comment) error {
	b.Lock()
	defer b.Unlock()
	return b._setRecordComment(comment)
}

func (b *backend) getCommentFromCache(token, commentID string) (*www.Comment, error) {
	// Setup plugin command
	cgb, err := decredplugin.EncodeGetComment(decredplugin.GetComment{
		Token:     token,
		CommentID: commentID,
	})
	if err != nil {
		return nil, fmt.Errorf("EncodeCommentGet: %v", err)
	}

	// Send cache request
	payload, err := b.cache.Plugin(decredplugin.CmdGetComment,
		string(cgb), "")
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: www.ErrorStatusCommentNotFound,
			}
		}
		return nil, err
	}

	// Handle response
	gcr, err := decredplugin.DecodeGetCommentReply([]byte(payload))
	if err != nil {
		return nil, fmt.Errorf("DecodeGetComment: %v", err)
	}
	c := convertCommentFromDecredPlugin(gcr.Comment)

	// Fill in author info
	userID, ok := b.getUserIDByPubKey(c.PublicKey)
	if !ok {
		return nil, fmt.Errorf("userID not found for pubkey %v",
			c.PublicKey)
	}
	c.UserID = userID
	c.Username = b.getUsernameById(userID)

	return &c, nil
}

// ProcessNewComment processes a submitted comment.  It ensures the proposal
// and the parent exists.  A parent ID of 0 indicates that it is a comment on
// the proposal whereas non-zero indicates that it is a reply to a comment.
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

	// Get proposal from cache
	r, err := b.cache.RecordGetLatest(nc.Token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: www.ErrorStatusProposalNotFound,
			}
		}
		return nil, err
	}
	pr := convertPropFromCache(*r)

	// Ensure proposal is public
	if pr.Status != www.PropStatusPublic {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusWrongStatus,
		}
	}

	// TODO: remove this once vote data has been added to cache
	ir, err := b.getInventoryRecord(nc.Token)
	if err != nil {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusProposalNotFound,
		}
	}

	// Ensure proposal vote has not ended
	bb, err := b.getBestBlock()
	if err != nil {
		return nil, fmt.Errorf("getBestBlock: %v", err)
	}

	if getVoteStatus(ir, bb) == www.PropVoteStatusFinished {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusWrongVoteStatus,
		}
	}

	// Validate comment
	if err := validateComment(nc); err != nil {
		return nil, err
	}

	// Setup decred plugin command
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

	// Send politeiad request
	responseBody, err := b.makeRequest(http.MethodPost,
		pd.PluginCommandRoute, pc)
	if err != nil {
		return nil, err
	}

	// Handle response
	var reply pd.PluginCommandReply
	err = json.Unmarshal(responseBody, &reply)
	if err != nil {
		return nil, fmt.Errorf("Unmarshal PluginCommandReply: %v", err)
	}

	err = util.VerifyChallenge(b.cfg.Identity, challenge, reply.Response)
	if err != nil {
		return nil, fmt.Errorf("VerifyChallenge: %v")
	}

	dncr, err := decredplugin.DecodeNewCommentReply([]byte(reply.Payload))
	if err != nil {
		return nil, fmt.Errorf("DecodeNewCommentReply: %v", err)
	}
	ncr := convertNewCommentReplyFromDecredPlugin(*dncr)

	// Fill in author info
	userID, ok := b.getUserIDByPubKey(ncr.Comment.PublicKey)
	if !ok {
		log.Errorf("ProcessNewComment: userID not found for pubkey %v",
			ncr.Comment.PublicKey)
	}
	ncr.Comment.UserID = userID
	ncr.Comment.Username = b.getUsernameById(userID)

	// Fire of new comment event
	b.fireEvent(EventTypeComment, EventDataComment{
		Comment: &ncr.Comment,
	})

	return &ncr, nil
}

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

	// Get proposal from cache
	r, err := b.cache.RecordGetLatest(cc.Token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: www.ErrorStatusProposalNotFound,
			}
		}
		return nil, err
	}
	pr := convertPropFromCache(*r)

	// Ensure proposal is public
	if pr.Status != www.PropStatusPublic {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusWrongStatus,
		}
	}

	// Ensure comment exists and has not been censored
	c, err := b.getCommentFromCache(cc.Token, cc.CommentID)
	if err != nil {
		return nil, err
	}
	if c.Censored {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusCensoredComment,
		}
	}

	// TODO: remove this once vote data has been added to cache
	ir, err := b.getInventoryRecord(cc.Token)
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
			ErrorCode: www.ErrorStatusWrongVoteStatus,
		}
	}

	// Setup plugin command
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	dcc := convertCensorCommentToDecredPlugin(cc)
	payload, err := decredplugin.EncodeCensorComment(dcc)
	if err != nil {
		return nil, fmt.Errorf("EncodeCensorComment: %v", err)
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
		return nil, fmt.Errorf("Unmarshal PluginCommandReply: %v", err)
	}

	err = util.VerifyChallenge(b.cfg.Identity, challenge, reply.Response)
	if err != nil {
		return nil, fmt.Errorf("VerifyChallenge: %v", err)
	}

	ccr, err := decredplugin.DecodeCensorCommentReply([]byte(reply.Payload))
	if err != nil {
		return nil, fmt.Errorf("DecodeCensorCommentReply: %v", err)
	}
	ccrWWW := convertCensorCommentReplyFromDecredPlugin(*ccr)

	return &ccrWWW, nil
}
