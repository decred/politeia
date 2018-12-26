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

func convertNewCommentReplyFromDecredPlugin(ncr decredplugin.NewCommentReply) www.NewCommentReply {
	return www.NewCommentReply{
		Comment: www.Comment{
			Token:       ncr.Comment.Token,
			ParentID:    ncr.Comment.ParentID,
			Comment:     ncr.Comment.Comment,
			Signature:   ncr.Comment.Signature,
			PublicKey:   ncr.Comment.PublicKey,
			CommentID:   ncr.Comment.CommentID,
			Receipt:     ncr.Comment.Receipt,
			Timestamp:   ncr.Comment.Timestamp,
			TotalVotes:  ncr.Comment.TotalVotes,
			ResultVotes: ncr.Comment.ResultVotes,
			Censored:    ncr.Comment.Censored,
			UserID:      "",
			Username:    "",
		},
	}
}

func convertWWWNewCommentToDecredNewComment(nc www.NewComment) decredplugin.NewComment {
	return decredplugin.NewComment{
		Token:     nc.Token,
		ParentID:  nc.ParentID,
		Comment:   nc.Comment,
		Signature: nc.Signature,
		PublicKey: nc.PublicKey,
	}
}

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

func convertWWWCensorCommentToDecredCensorComment(cc www.CensorComment) decredplugin.CensorComment {
	return decredplugin.CensorComment{
		Token:     cc.Token,
		CommentID: cc.CommentID,
		Reason:    cc.Reason,
		Signature: cc.Signature,
		PublicKey: cc.PublicKey,
	}
}

func convertDecredCensorCommentReplyToWWWCensorCommentReply(ccr decredplugin.CensorCommentReply) www.CensorCommentReply {
	return www.CensorCommentReply{
		Receipt: ccr.Receipt,
	}
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

	// XXX keep this until vote data has been added to the cache.
	// Note that we are not racing ir because it is a copy.
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

	// Setup plugin command
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	dnc := convertWWWNewCommentToDecredNewComment(nc)
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
		return nil, fmt.Errorf("Could not unmarshal "+
			"PluginCommandReply: %v", err)
	}

	err = util.VerifyChallenge(b.cfg.Identity, challenge, reply.Response)
	if err != nil {
		return nil, err
	}

	dncr, err := decredplugin.DecodeNewCommentReply([]byte(reply.Payload))
	if err != nil {
		return nil, err
	}
	ncr := convertNewCommentReplyFromDecredPlugin(*dncr)

	// Fill in author info
	userID, ok := b.getUserIDByPubkey(ncr.Comment.PublicKey)
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
