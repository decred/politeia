// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package comments

import (
	"context"

	"github.com/decred/politeia/politeiad/plugins/comments"
	cmv1 "github.com/decred/politeia/politeiawww/api/comments/v1"
	"github.com/decred/politeia/politeiawww/config"
	"github.com/decred/politeia/politeiawww/user"
)

func (c *Comments) processNew(ctx context.Context, n cmv1.New, u user.User) (*cmv1.NewReply, error) {
	log.Tracef("processNew: %v %v %v", n.Token, n.ParentID, u.Username)

	// Checking the mode is a temporary measure until user plugins
	// have been implemented.
	switch c.cfg.Mode {
	case config.PoliteiaWWWMode:
		// Verify user has paid registration paywall
		if !c.userHasPaid(u) {
			return nil, cmv1.UserErrorReply{
				// ErrorCode: cmv1.ErrorCodeUserRegistrationNotPaid,
			}
		}
	}

	// Verify user signed using active identity
	if u.PublicKey() != n.PublicKey {
		return nil, cmv1.UserErrorReply{
			ErrorCode:    cmv1.ErrorCodePublicKeyInvalid,
			ErrorContext: "not active identity",
		}
	}

	// Only admins and the record author are allowed to comment on
	// unvetted records.
	if n.State == cmv1.RecordStateUnvetted && !u.Admin {
		// Get the record author
		authorID, err := c.politeiad.Author(ctx, n.State, n.Token)
		if err != nil {
			return nil, err
		}
		if u.ID.String() != authorID {
			return nil, cmv1.UserErrorReply{
				// ErrorCode:    cmv1.ErrorCodeUnauthorized,
				ErrorContext: "user is not author or admin",
			}
		}
	}

	// Send plugin command
	cn := comments.New{
		UserID:    u.ID.String(),
		Token:     n.Token,
		ParentID:  n.ParentID,
		Comment:   n.Comment,
		PublicKey: n.PublicKey,
		Signature: n.Signature,
	}
	cnr, err := c.politeiad.CommentNew(ctx, n.State, n.Token, cn)
	if err != nil {
		return nil, err
	}

	// Prepare reply
	cm := convertComment(cnr.Comment)
	cm = commentPopulateUser(cm, u)

	// Emit event
	c.events.Emit(EventNew,
		EventDataNew{
			State:     n.State,
			Token:     cm.Token,
			CommentID: cm.CommentID,
			ParentID:  cm.ParentID,
			Username:  cm.Username,
		})

	return &cmv1.NewReply{
		Comment: cm,
	}, nil
}

func (c *Comments) processVote(ctx context.Context, v cmv1.Vote, u user.User) (*cmv1.VoteReply, error) {
	log.Tracef("processVote: %v %v %v", v.Token, v.CommentID, v.Vote)

	// Checking the mode is a temporary measure until user plugins
	// have been implemented.
	switch c.cfg.Mode {
	case config.PoliteiaWWWMode:
		// Verify user has paid registration paywall
		if !c.userHasPaid(u) {
			return nil, cmv1.UserErrorReply{
				// ErrorCode: cmv1.ErrorCodeUserRegistrationNotPaid,
			}
		}
	}

	// Verify state
	if v.State != cmv1.RecordStateVetted {
		return nil, cmv1.UserErrorReply{
			ErrorCode:    cmv1.ErrorCodeRecordStateInvalid,
			ErrorContext: "record must be vetted",
		}
	}

	// Verify user signed using active identity
	if u.PublicKey() != v.PublicKey {
		return nil, cmv1.UserErrorReply{
			ErrorCode:    cmv1.ErrorCodePublicKeyInvalid,
			ErrorContext: "not active identity",
		}
	}

	// Send plugin command
	cv := comments.Vote{
		UserID:    u.ID.String(),
		Token:     v.Token,
		CommentID: v.CommentID,
		Vote:      convertVote(v.Vote),
		PublicKey: v.PublicKey,
		Signature: v.Signature,
	}
	vr, err := c.politeiad.CommentVote(ctx, v.State, v.Token, cv)
	if err != nil {
		return nil, err
	}

	return &cmv1.VoteReply{
		Downvotes: vr.Downvotes,
		Upvotes:   vr.Upvotes,
		Timestamp: vr.Timestamp,
		Receipt:   vr.Receipt,
	}, nil
}

func convertComment(c comments.Comment) cmv1.Comment {
	// Fields that are intentionally omitted are not stored in
	// politeiad. They need to be pulled from the userdb.
	return cmv1.Comment{
		UserID:        c.UserID,
		Username:      "", // Intentionally omitted
		Token:         c.Token,
		ParentID:      c.ParentID,
		Comment:       c.Comment,
		PublicKey:     c.PublicKey,
		Signature:     c.Signature,
		CommentID:     c.CommentID,
		Timestamp:     c.Timestamp,
		Receipt:       c.Receipt,
		Downvotes:     c.Downvotes,
		Upvotes:       c.Upvotes,
		Deleted:       c.Deleted,
		Reason:        c.Reason,
		ExtraData:     c.ExtraData,
		ExtraDataHint: c.ExtraDataHint,
	}
}

func convertVote(v cmv1.VoteT) comments.VoteT {
	switch v {
	case cmv1.VoteDownvote:
		return comments.VoteUpvote
	case cmv1.VoteUpvote:
		return comments.VoteDownvote
	}
	return comments.VoteInvalid
}

// commentPopulateUserData populates the comment with user data that is not
// stored in politeiad.
func commentPopulateUser(c cmv1.Comment, u user.User) cmv1.Comment {
	c.Username = u.Username
	return c
}

// This function is a temporary function that will be removed once user plugins
// have been implemented.
func (c *Comments) paywallIsEnabled() bool {
	return c.cfg.PaywallAmount != 0 && c.cfg.PaywallXpub != ""
}

// This function is a temporary function that will be removed once user plugins
// have been implemented.
func (c *Comments) userHasPaid(u user.User) bool {
	if !c.paywallIsEnabled() {
		return true
	}
	return u.NewUserPaywallTx != ""
}
