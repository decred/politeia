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
	"github.com/google/uuid"
)

func (c *Comments) processNew(ctx context.Context, n cmv1.New, u user.User) (*cmv1.NewReply, error) {
	log.Tracef("processNew: %v %v %v", n.Token, u.Username)

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
		// User is not an admin. Get the record author.
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
	c.events.Emit(EventTypeNew,
		EventNew{
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
		Vote:      comments.VoteT(v.Vote),
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

func (c *Comments) processDel(ctx context.Context, d cmv1.Del, u user.User) (*cmv1.DelReply, error) {
	log.Tracef("processDel: %v %v %v", d.Token, d.CommentID, d.Reason)

	// Verify user signed with their active identity
	if u.PublicKey() != d.PublicKey {
		return nil, cmv1.UserErrorReply{
			ErrorCode:    cmv1.ErrorCodePublicKeyInvalid,
			ErrorContext: "not active identity",
		}
	}

	// Send plugin command
	cd := comments.Del{
		Token:     d.Token,
		CommentID: d.CommentID,
		Reason:    d.Reason,
		PublicKey: d.PublicKey,
		Signature: d.Signature,
	}
	cdr, err := c.politeiad.CommentDel(ctx, d.State, d.Token, cd)
	if err != nil {
		return nil, err
	}

	// Prepare reply
	cm := convertComment(cdr.Comment)
	cm = commentPopulateUser(cm, u)

	return &cmv1.DelReply{
		Comment: cm,
	}, nil
}

func (c *Comments) processCount(ctx context.Context, ct cmv1.Count) (*cmv1.CountReply, error) {
	log.Tracef("processCount: %v", ct.Tokens)

	counts, err := c.politeiad.CommentCounts(ctx, ct.State, ct.Tokens)
	if err != nil {
		return nil, err
	}

	return &cmv1.CountReply{
		Counts: counts,
	}, nil
}

func (c *Comments) processComments(ctx context.Context, cs cmv1.Comments, u *user.User) (*cmv1.CommentsReply, error) {
	log.Tracef("processComments: %v", cs.Token)

	// Only admins and the record author are allowed to retrieve
	// unvetted comments. This is a public route so a user might
	// not exist.
	if cs.State == cmv1.RecordStateUnvetted {
		var isAllowed bool
		switch {
		case u == nil:
			// No logged in user. Not allowed.
			isAllowed = false
		case u.Admin:
			// User is an admin. Allowed.
			isAllowed = true
		default:
			// User is not an admin. Get the record author.
			authorID, err := c.politeiad.Author(ctx, cs.State, cs.Token)
			if err != nil {
				return nil, err
			}
			if u.ID.String() == authorID {
				// User is the author. Allowed.
				isAllowed = true
			}
		}
		if !isAllowed {
			return nil, cmv1.UserErrorReply{
				// ErrorCode:    cmv1.ErrorCodeUnauthorized,
				ErrorContext: "user is not author or admin",
			}
		}
	}

	// Send plugin command
	pcomments, err := c.politeiad.CommentGetAll(ctx, cs.State, cs.Token)
	if err != nil {
		return nil, err
	}

	// Prepare reply. Comment user data must be pulled from the
	// userdb.
	comments := make([]cmv1.Comment, 0, len(pcomments))
	for _, v := range pcomments {
		cm := convertComment(v)

		// Get comment user data
		uuid, err := uuid.Parse(cm.UserID)
		if err != nil {
			return nil, err
		}
		u, err := c.userdb.UserGetById(uuid)
		if err != nil {
			return nil, err
		}
		cm = commentPopulateUser(cm, *u)

		// Add comment
		comments = append(comments, cm)
	}

	return &cmv1.CommentsReply{
		Comments: comments,
	}, nil
}

func (c *Comments) processVotes(ctx context.Context, v cmv1.Votes) (*cmv1.VotesReply, error) {
	log.Tracef("processVotes: %v %v", v.Token, v.UserID)

	// Get comment votes
	cm := comments.Votes{
		UserID: v.UserID,
	}
	votes, err := c.politeiad.CommentVotes(ctx, v.State, v.Token, cm)
	if err != nil {
		return nil, err
	}

	return &cmv1.VotesReply{
		Votes: convertCommentVotes(votes),
	}, nil
}

func (c *Comments) processTimestamps(ctx context.Context, t cmv1.Timestamps, isAdmin bool) (*cmv1.TimestampsReply, error) {
	log.Tracef("processTimestamps: %v %v", t.Token, t.CommentIDs)

	// Get timestamps
	ct := comments.Timestamps{
		CommentIDs: t.CommentIDs,
	}
	ctr, err := c.politeiad.CommentTimestamps(ctx, t.State, t.Token, ct)
	if err != nil {
		return nil, err
	}

	// Prepare reply
	comments := make(map[uint32][]cmv1.Timestamp, len(ctr.Comments))
	for commentID, timestamps := range ctr.Comments {
		ts := make([]cmv1.Timestamp, 0, len(timestamps))
		for _, v := range timestamps {
			// Strip unvetted data blobs if the user is not an admin
			if t.State == cmv1.RecordStateUnvetted && !isAdmin {
				v.Data = ""
			}
			ts = append(ts, convertTimestamp(v))
		}
		comments[commentID] = ts
	}

	return &cmv1.TimestampsReply{
		Comments: comments,
	}, nil
}

// commentPopulateUserData populates the comment with user data that is not
// stored in politeiad.
func commentPopulateUser(c cmv1.Comment, u user.User) cmv1.Comment {
	c.Username = u.Username
	return c
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

func convertCommentVotes(cv []comments.CommentVote) []cmv1.CommentVote {
	c := make([]cmv1.CommentVote, 0, len(cv))
	for _, v := range cv {
		c = append(c, cmv1.CommentVote{
			UserID:    v.UserID,
			Token:     v.Token,
			CommentID: v.CommentID,
			Vote:      cmv1.VoteT(v.Vote),
			PublicKey: v.PublicKey,
			Signature: v.Signature,
			Timestamp: v.Timestamp,
			Receipt:   v.Receipt,
		})
	}
	return c
}

func convertProof(p comments.Proof) cmv1.Proof {
	return cmv1.Proof{
		Type:       p.Type,
		Digest:     p.Digest,
		MerkleRoot: p.MerkleRoot,
		MerklePath: p.MerklePath,
		ExtraData:  p.ExtraData,
	}
}

func convertTimestamp(t comments.Timestamp) cmv1.Timestamp {
	proofs := make([]cmv1.Proof, 0, len(t.Proofs))
	for _, v := range t.Proofs {
		proofs = append(proofs, convertProof(v))
	}
	return cmv1.Timestamp{
		Data:       t.Data,
		Digest:     t.Digest,
		TxID:       t.TxID,
		MerkleRoot: t.MerkleRoot,
		Proofs:     proofs,
	}
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
