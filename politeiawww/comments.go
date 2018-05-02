package main

import (
	"github.com/decred/politeia/decredplugin"
	www "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/util"
)

func (b *backend) convertDecredCommentToWWWComment(c decredplugin.Comment) www.Comment {
	return www.Comment{
		Token:     c.Token,
		ParentID:  c.ParentID,
		Comment:   c.Comment,
		Signature: c.Signature,
		PublicKey: c.PublicKey,
		CommentID: c.CommentID,
		Receipt:   c.Receipt,
		Timestamp: c.Timestamp,
		UserID:    b.userPubkeys[c.PublicKey],
	}
}

func convertWWWCommentToDecredComment(c www.Comment) decredplugin.Comment {
	return decredplugin.Comment{
		Token:     c.Token,
		ParentID:  c.ParentID,
		Comment:   c.Comment,
		Signature: c.Signature,
		PublicKey: c.PublicKey,
		CommentID: c.CommentID,
		Receipt:   c.Receipt,
		Timestamp: c.Timestamp,
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

func (b *backend) convertDecredNewCommentReplyToWWWNewCommentReply(cr decredplugin.NewCommentReply) www.NewCommentReply {
	return www.NewCommentReply{
		Comment: b.convertDecredCommentToWWWComment(cr.Comment),
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
	for _, v := range c.comments {
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
