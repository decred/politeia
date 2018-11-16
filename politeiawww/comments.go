package main

import (
	"fmt"
	"strconv"

	"github.com/decred/politeia/decredplugin"
	www "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/util"
)

// _convertDecredCommentToWWWComment converts decred plugin comment to www comment.
//
// Must be called WITH the lock held.
func (b *backend) _convertDecredCommentToWWWComment(c decredplugin.Comment) www.Comment {
	return www.Comment{
		Token:       c.Token,
		ParentID:    c.ParentID,
		Comment:     c.Comment,
		Signature:   c.Signature,
		PublicKey:   c.PublicKey,
		CommentID:   c.CommentID,
		Receipt:     c.Receipt,
		Timestamp:   c.Timestamp,
		TotalVotes:  c.TotalVotes,
		ResultVotes: c.ResultVotes,
		UserID:      b.userPubkeys[c.PublicKey],
		Censored:    c.Censored,
	}
}

func convertWWWCommentToDecredComment(c www.Comment) decredplugin.Comment {
	return decredplugin.Comment{
		Token:       c.Token,
		ParentID:    c.ParentID,
		Comment:     c.Comment,
		Signature:   c.Signature,
		PublicKey:   c.PublicKey,
		CommentID:   c.CommentID,
		Receipt:     c.Receipt,
		Timestamp:   c.Timestamp,
		TotalVotes:  c.TotalVotes,
		ResultVotes: c.ResultVotes,
		Censored:    c.Censored,
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

// convertDecredNewCommentReplyToWWWNewCommentReply converts decred plugin new
// comment to www new comment.
//
// Must be called WITHOUT the lock held.
func (b *backend) convertDecredNewCommentReplyToWWWNewCommentReply(cr decredplugin.NewCommentReply) www.NewCommentReply {
	b.RLock()
	defer b.RUnlock()
	return www.NewCommentReply{
		Comment: b._convertDecredCommentToWWWComment(cr.Comment),
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
