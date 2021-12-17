// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package comments

import (
	"context"
	"errors"
	"fmt"

	pdv2 "github.com/decred/politeia/politeiad/api/v2"
	"github.com/decred/politeia/politeiad/plugins/comments"
	v1 "github.com/decred/politeia/politeiawww/api/comments/v1"
	"github.com/decred/politeia/politeiawww/config"
	"github.com/decred/politeia/politeiawww/legacy/user"
	"github.com/google/uuid"
)

func (c *Comments) processNew(ctx context.Context, n v1.New, u user.User) (*v1.NewReply, error) {
	log.Tracef("processNew: %v %v %v", n.Token, u.Username)

	// Verify state
	state := convertStateToPlugin(n.State)
	if state == comments.RecordStateInvalid {
		return nil, v1.UserErrorReply{
			ErrorCode: v1.ErrorCodeRecordStateInvalid,
		}
	}

	// Verify user signed using active identity
	if u.PublicKey() != n.PublicKey {
		return nil, v1.UserErrorReply{
			ErrorCode:    v1.ErrorCodePublicKeyInvalid,
			ErrorContext: "not active identity",
		}
	}

	// Execute pre plugin hooks. Checking the mode is a temporary
	// measure until user plugins have been properly implemented.
	switch c.cfg.Mode {
	case config.PiWWWMode:
		err := c.piHookNewPre(u)
		if err != nil {
			return nil, err
		}
	}

	// Only admins and the record author are allowed to comment on
	// unvetted records.
	if n.State == v1.RecordStateUnvetted && !u.Admin {
		// User is not an admin. Check if the user is the author.
		authorID, err := c.politeiad.Author(ctx, n.Token)
		if err != nil {
			return nil, err
		}
		if u.ID.String() != authorID {
			return nil, v1.UserErrorReply{
				ErrorCode:    v1.ErrorCodeUnauthorized,
				ErrorContext: "user is not author or admin",
			}
		}
	}

	// Send plugin command
	cn := comments.New{
		UserID:        u.ID.String(),
		State:         state,
		Token:         n.Token,
		ParentID:      n.ParentID,
		Comment:       n.Comment,
		PublicKey:     n.PublicKey,
		Signature:     n.Signature,
		ExtraData:     n.ExtraData,
		ExtraDataHint: n.ExtraDataHint,
	}
	pdc, err := c.politeiad.CommentNew(ctx, cn)
	if err != nil {
		return nil, err
	}

	// Prepare reply
	cm := convertComment(*pdc)
	commentPopulateUserData(&cm, u)

	// Emit event
	c.events.Emit(EventTypeNew,
		EventNew{
			State:   n.State,
			Comment: cm,
		})

	return &v1.NewReply{
		Comment: cm,
	}, nil
}

func (c *Comments) processVote(ctx context.Context, v v1.Vote, u user.User) (*v1.VoteReply, error) {
	log.Tracef("processVote: %v %v %v", v.Token, v.CommentID, v.Vote)

	// Verify state
	state := convertStateToPlugin(v.State)
	if state == comments.RecordStateInvalid {
		return nil, v1.UserErrorReply{
			ErrorCode: v1.ErrorCodeRecordStateInvalid,
		}
	}

	// Verify user signed using active identity
	if u.PublicKey() != v.PublicKey {
		return nil, v1.UserErrorReply{
			ErrorCode:    v1.ErrorCodePublicKeyInvalid,
			ErrorContext: "not active identity",
		}
	}

	// Execute pre plugin hooks. Checking the mode is a temporary
	// measure until user plugins have been properly implemented.
	switch c.cfg.Mode {
	case config.PiWWWMode:
		err := c.piHookVotePre(u)
		if err != nil {
			return nil, err
		}
	}

	// Votes are only allowed on vetted records
	if v.State != v1.RecordStateVetted {
		return nil, v1.UserErrorReply{
			ErrorCode:    v1.ErrorCodeRecordStateInvalid,
			ErrorContext: "comment voting is only allowed on vetted records",
		}
	}

	// Send plugin command
	cv := comments.Vote{
		UserID:    u.ID.String(),
		State:     state,
		Token:     v.Token,
		CommentID: v.CommentID,
		Vote:      comments.VoteT(v.Vote),
		PublicKey: v.PublicKey,
		Signature: v.Signature,
	}
	vr, err := c.politeiad.CommentVote(ctx, cv)
	if err != nil {
		return nil, err
	}

	return &v1.VoteReply{
		Downvotes: vr.Downvotes,
		Upvotes:   vr.Upvotes,
		Timestamp: vr.Timestamp,
		Receipt:   vr.Receipt,
	}, nil
}

func (c *Comments) processDel(ctx context.Context, d v1.Del, u user.User) (*v1.DelReply, error) {
	log.Tracef("processDel: %v %v %v", d.Token, d.CommentID, d.Reason)

	// Verify state
	state := convertStateToPlugin(d.State)
	if state == comments.RecordStateInvalid {
		return nil, v1.UserErrorReply{
			ErrorCode: v1.ErrorCodeRecordStateInvalid,
		}
	}

	// Verify user signed with their active identity
	if u.PublicKey() != d.PublicKey {
		return nil, v1.UserErrorReply{
			ErrorCode:    v1.ErrorCodePublicKeyInvalid,
			ErrorContext: "not active identity",
		}
	}

	// Send plugin command
	cd := comments.Del{
		State:     state,
		Token:     d.Token,
		CommentID: d.CommentID,
		Reason:    d.Reason,
		PublicKey: d.PublicKey,
		Signature: d.Signature,
	}
	cdr, err := c.politeiad.CommentDel(ctx, cd)
	if err != nil {
		return nil, err
	}

	// Prepare reply
	cm := convertComment(cdr.Comment)
	commentPopulateUserData(&cm, u)

	return &v1.DelReply{
		Comment: cm,
	}, nil
}

func (c *Comments) processCount(ctx context.Context, ct v1.Count) (*v1.CountReply, error) {
	log.Tracef("processCount: %v", ct.Tokens)

	// Verify size of request
	switch {
	case len(ct.Tokens) == 0:
		// Nothing to do
		return &v1.CountReply{
			Counts: map[string]uint32{},
		}, nil

	case len(ct.Tokens) > int(v1.CountPageSize):
		return nil, v1.UserErrorReply{
			ErrorCode:    v1.ErrorCodePageSizeExceeded,
			ErrorContext: fmt.Sprintf("max page size is %v", v1.CountPageSize),
		}
	}

	// Get comment counts
	counts, err := c.politeiad.CommentCount(ctx, ct.Tokens)
	if err != nil {
		return nil, err
	}

	return &v1.CountReply{
		Counts: counts,
	}, nil
}

func (c *Comments) processComments(ctx context.Context, cs v1.Comments, u *user.User) (*v1.CommentsReply, error) {
	log.Tracef("processComments: %v", cs.Token)

	// Send plugin command
	pcomments, err := c.politeiad.CommentsGetAll(ctx, cs.Token)
	if err != nil {
		return nil, err
	}
	if len(pcomments) == 0 {
		return &v1.CommentsReply{
			Comments: []v1.Comment{},
		}, nil
	}

	// Only admins and the record author are allowed to retrieve
	// unvetted comments. This is a public route so a user might
	// not exist.
	if pcomments[0].State == comments.RecordStateUnvetted {
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
			authorID, err := c.politeiad.Author(ctx, cs.Token)
			if err != nil {
				return nil, err
			}
			if u.ID.String() == authorID {
				// User is the author. Allowed.
				isAllowed = true
			}
		}
		if !isAllowed {
			return nil, v1.UserErrorReply{
				ErrorCode:    v1.ErrorCodeUnauthorized,
				ErrorContext: "user is not author or admin",
			}
		}
	}

	// Prepare reply. Comment user data must be pulled from the
	// userdb.
	comments := make([]v1.Comment, 0, len(pcomments))
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
		commentPopulateUserData(&cm, *u)

		// Add comment
		comments = append(comments, cm)
	}

	return &v1.CommentsReply{
		Comments: comments,
	}, nil
}

func (c *Comments) processVotes(ctx context.Context, v v1.Votes) (*v1.VotesReply, error) {
	log.Tracef("processVotes: %v %v", v.Token, v.UserID)

	// Get comment votes. Votes are only allowed on vetted comments so
	// there is no need to check the user permissions since all vetted
	// comments are public.
	cm := comments.Votes{
		UserID: v.UserID,
		Page:   v.Page,
	}
	votes, err := c.politeiad.CommentVotes(ctx, v.Token, cm)
	if err != nil {
		return nil, err
	}
	cv := convertCommentVotes(votes)

	// Populate comment votes with user data
	err = c.commentVotesPopulateUserData(cv, v.UserID)
	if err != nil {
		return nil, err
	}

	return &v1.VotesReply{
		Votes: cv,
	}, nil
}

// usersBatchSize is the maximum number of users which can be fetched from
// politeiawww and stored in memory while populating the comment votes structs
// with the missing users data.
var usersBatchSize = 10

// commentVotePopulateUserData populates the comment votes with user data that
// is not stored in politeiad. If all votes are associated with one user it
// expects to get the user's ID as a parameter.
func (c *Comments) commentVotesPopulateUserData(votes []v1.CommentVote, userID string) error {
	// If given votes slice is emptry, nothing to do
	if len(votes) == 0 {
		return nil
	}

	// Collect the users public keys in a map to prevent duplicates and to
	// retrieve the users in a batched db call.
	var mPubkeys map[string]bool // map[pubkey]bool
	if userID != "" {
		// If user ID filter is applied, we have only one user
		// to fetch.
		mPubkeys = make(map[string]bool, 1)
		mPubkeys[votes[0].PublicKey] = true
	} else {
		// If user ID filter is not applied, we need to collect all
		// the user public keys from comment votes.
		mPubkeys = make(map[string]bool, len(votes))
		for _, vote := range votes {
			if ok := mPubkeys[vote.UserID]; ok {
				// If user uuid already known, skip
				continue
			}
			mPubkeys[vote.PublicKey] = true
		}
	}

	// Store public keys in a slice
	pubkeys := make([]string, 0, len(mPubkeys))
	for pubkey := range mPubkeys {
		pubkeys = append(pubkeys, pubkey)
	}

	// Get users from db in batchs to avoid reading too many
	// users into memory.
	var batchStartIdx int
	usernames := make(map[string]string, len(pubkeys))
	for batchStartIdx < len(pubkeys) {
		batchEndIdx := batchStartIdx + usersBatchSize
		if batchEndIdx > len(pubkeys) {
			// We've reached the end of the slice
			batchEndIdx = len(pubkeys)
		}

		// batchStartIdx is included. batchEndIdx is excluded.
		batch := pubkeys[batchStartIdx:batchEndIdx]

		// Get batch of users
		users, err := c.userdb.UsersGetByPubKey(batch)
		if err != nil {
			return err
		}

		// Map user IDs to usernames
		for _, u := range users {
			usernames[u.ID.String()] = u.Username
		}

		log.Debugf("Fetched a batch of %v users out of %v required users",
			len(batch), len(pubkeys))

		// Next batch start index
		batchStartIdx = batchEndIdx
	}

	// Populate comment votes with usernames
	for k := range votes {
		username := usernames[votes[k].UserID]
		votes[k].Username = username
	}

	return nil
}

func (c *Comments) processTimestamps(ctx context.Context, t v1.Timestamps, isAdmin bool) (*v1.TimestampsReply, error) {
	log.Tracef("processTimestamps: %v %v", t.Token, t.CommentIDs)

	// Verify size of request
	switch {
	case len(t.CommentIDs) == 0:
		// Nothing to do
		return &v1.TimestampsReply{
			Comments: map[uint32]v1.CommentTimestamp{},
		}, nil

	case len(t.CommentIDs) > int(v1.TimestampsPageSize):
		return nil, v1.UserErrorReply{
			ErrorCode: v1.ErrorCodePageSizeExceeded,
			ErrorContext: fmt.Sprintf("max page size is %v",
				v1.TimestampsPageSize),
		}
	}

	// Get record state
	r, err := c.recordNoFiles(ctx, t.Token)
	if err != nil {
		if err == errRecordNotFound {
			return nil, v1.UserErrorReply{
				ErrorCode: v1.ErrorCodeRecordNotFound,
			}
		}
		return nil, err
	}

	// Get timestamps
	ct := comments.Timestamps{
		CommentIDs: t.CommentIDs,
	}
	ctr, err := c.politeiad.CommentTimestamps(ctx, t.Token, ct)
	if err != nil {
		return nil, err
	}

	// Prepare reply
	var (
		comments = make(map[uint32]v1.CommentTimestamp, len(ctr.Comments))

		// Unvetted data payloads are removed from the timestamp if the
		// user is not an admin.
		rmPayloads = (r.State == pdv2.RecordStateUnvetted) && !isAdmin
	)
	for commentID, ct := range ctr.Comments {
		adds := make([]v1.Timestamp, 0, len(ct.Adds))
		for _, ts := range ct.Adds {
			if rmPayloads {
				ts.Data = ""
			}
			adds = append(adds, convertTimestamp(ts))
		}

		var del *v1.Timestamp
		if ct.Del != nil {
			if rmPayloads {
				ct.Del.Data = ""
			}
			d := convertTimestamp(*ct.Del)
			del = &d
		}

		comments[commentID] = v1.CommentTimestamp{
			Adds: adds,
			Del:  del,
		}
	}

	return &v1.TimestampsReply{
		Comments: comments,
	}, nil
}

var (
	errRecordNotFound = errors.New("record not found")
)

// recordNoFiles returns a politeiad record without any of its files. This
// allows the call to be light weight but still return metadata about the
// record such as state and status.
func (c *Comments) recordNoFiles(ctx context.Context, token string) (*pdv2.Record, error) {
	req := []pdv2.RecordRequest{
		{
			Token:        token,
			OmitAllFiles: true,
		},
	}
	records, err := c.politeiad.Records(ctx, req)
	if err != nil {
		return nil, err
	}
	r, ok := records[token]
	if !ok {
		return nil, errRecordNotFound
	}

	return &r, nil
}

// commentPopulateUserData populates the comment with user data that is not
// stored in politeiad.
func commentPopulateUserData(c *v1.Comment, u user.User) {
	c.Username = u.Username
}

func convertStateToPlugin(s v1.RecordStateT) comments.RecordStateT {
	switch s {
	case v1.RecordStateUnvetted:
		return comments.RecordStateUnvetted
	case v1.RecordStateVetted:
		return comments.RecordStateVetted
	}
	return comments.RecordStateInvalid
}

func convertStateToV1(s comments.RecordStateT) v1.RecordStateT {
	switch s {
	case comments.RecordStateUnvetted:
		return v1.RecordStateUnvetted
	case comments.RecordStateVetted:
		return v1.RecordStateVetted
	}
	return v1.RecordStateInvalid
}

func convertComment(c comments.Comment) v1.Comment {
	// Fields that are intentionally omitted are not stored in
	// politeiad. They need to be pulled from the userdb.
	return v1.Comment{
		UserID:        c.UserID,
		Username:      "", // Intentionally omitted
		State:         convertStateToV1(c.State),
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

func convertCommentVotes(cv []comments.CommentVote) []v1.CommentVote {
	c := make([]v1.CommentVote, 0, len(cv))
	for _, v := range cv {
		c = append(c, v1.CommentVote{
			UserID:    v.UserID,
			Token:     v.Token,
			State:     convertStateToV1(v.State),
			CommentID: v.CommentID,
			Vote:      v1.VoteT(v.Vote),
			PublicKey: v.PublicKey,
			Signature: v.Signature,
			Timestamp: v.Timestamp,
			Receipt:   v.Receipt,
		})
	}
	return c
}

func convertProof(p comments.Proof) v1.Proof {
	return v1.Proof{
		Type:       p.Type,
		Digest:     p.Digest,
		MerkleRoot: p.MerkleRoot,
		MerklePath: p.MerklePath,
		ExtraData:  p.ExtraData,
	}
}

func convertTimestamp(t comments.Timestamp) v1.Timestamp {
	proofs := make([]v1.Proof, 0, len(t.Proofs))
	for _, v := range t.Proofs {
		proofs = append(proofs, convertProof(v))
	}
	return v1.Timestamp{
		Data:       t.Data,
		Digest:     t.Digest,
		TxID:       t.TxID,
		MerkleRoot: t.MerkleRoot,
		Proofs:     proofs,
	}
}
