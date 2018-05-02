package main

import (
	"github.com/decred/politeia/decredplugin"
	www "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/util"
)

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
		Comments: make([]decredplugin.Comment, 0, len(c.comments)),
	}
	for _, v := range c.comments {
		gcr.Comments = append(gcr.Comments, v)
	}

	return gcr, nil
}

func validateComment(c decredplugin.NewComment) error {
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
