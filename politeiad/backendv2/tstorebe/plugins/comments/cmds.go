// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package comments

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"time"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
	"github.com/decred/politeia/politeiad/plugins/comments"
	"github.com/decred/politeia/util"
	errors "github.com/pkg/errors"
)

const (
	pluginID = comments.PluginID

	// Blob entry data descriptors
	dataDescriptorCommentAdd  = pluginID + "-add-v1"
	dataDescriptorCommentDel  = pluginID + "-del-v1"
	dataDescriptorCommentVote = pluginID + "-vote-v1"
)

// cmdNew creates a new comment.
func (p *commentsPlugin) cmdNew(tstore plugins.TstoreClient, token []byte, payload string) (string, error) {
	// Decode payload
	var n comments.New
	err := json.Unmarshal([]byte(payload), &n)
	if err != nil {
		return "", err
	}

	// Verify token
	err = tokenMatches(token, n.Token)
	if err != nil {
		return "", err
	}

	// Verify signature
	msg := strconv.FormatUint(uint64(n.State), 10) + n.Token +
		strconv.FormatUint(uint64(n.ParentID), 10) + n.Comment
	err = verifySignature(n.Signature, n.PublicKey, msg)
	if err != nil {
		return "", err
	}

	// Verify comment length
	if len(n.Comment) > int(p.commentLengthMax) {
		return "", backend.PluginError{
			PluginID:  comments.PluginID,
			ErrorCode: uint32(comments.ErrorCodeMaxLengthExceeded),
			ErrorContext: fmt.Sprintf("max length is %v characters",
				p.commentLengthMax),
		}
	}

	// Verify record state
	state, err := tstore.RecordState(token)
	if err != nil {
		return "", err
	}
	if uint32(n.State) != uint32(state) {
		return "", backend.PluginError{
			PluginID:     comments.PluginID,
			ErrorCode:    uint32(comments.ErrorCodeRecordStateInvalid),
			ErrorContext: fmt.Sprintf("got %v, want %v", n.State, state),
		}
	}

	// Get the cached record index
	ridx, err := getRecordIndex(tstore, token, state)
	if err != nil {
		return "", err
	}

	// Verify that the parent comment exists. A parent ID of 0
	// means that this is a base level comment, not a reply to
	// another comment.
	if n.ParentID > 0 && !ridx.commentExists(n.ParentID) {
		return "", backend.PluginError{
			PluginID:     comments.PluginID,
			ErrorCode:    uint32(comments.ErrorCodeParentIDInvalid),
			ErrorContext: "parent ID comment not found",
		}
	}

	// Setup comment
	receipt := p.identity.SignMessage([]byte(n.Signature))
	ca := comments.CommentAdd{
		UserID:        n.UserID,
		State:         n.State,
		Token:         n.Token,
		ParentID:      n.ParentID,
		Comment:       n.Comment,
		PublicKey:     n.PublicKey,
		Signature:     n.Signature,
		CommentID:     ridx.commentIDLatest() + 1,
		Version:       1,
		Timestamp:     time.Now().Unix(),
		Receipt:       hex.EncodeToString(receipt[:]),
		ExtraData:     n.ExtraData,
		ExtraDataHint: n.ExtraDataHint,
	}

	// Save comment
	digest, err := commentAddSave(tstore, token, ca)
	if err != nil {
		return "", err
	}

	// Update index
	ridx.Comments[ca.CommentID] = newCommentIndex(digest)

	// Save updated index
	err = ridx.save(tstore, state)
	if err != nil {
		return "", err
	}

	log.Debugf("Comment saved to record %v comment ID %v",
		ca.Token, ca.CommentID)

	// Get the newly created comment so that it can be returned.
	c, err := ridx.comment(tstore, ca.CommentID)
	if err != nil {
		return "", err
	}

	// Prepare reply
	nr := comments.NewReply{
		Comment: *c,
	}
	reply, err := json.Marshal(nr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// cmdEdit edits an existing comment. Editing a comment creates a new version
// of the comment.
func (p *commentsPlugin) cmdEdit(tstore plugins.TstoreClient, token []byte, payload string) (string, error) {
	// Decode payload
	var e comments.Edit
	err := json.Unmarshal([]byte(payload), &e)
	if err != nil {
		return "", err
	}

	// Verify token
	err = tokenMatches(token, e.Token)
	if err != nil {
		return "", err
	}

	// Verify signature
	msg := strconv.FormatUint(uint64(e.State), 10) + e.Token +
		strconv.FormatUint(uint64(e.ParentID), 10) + e.Comment
	err = verifySignature(e.Signature, e.PublicKey, msg)
	if err != nil {
		return "", err
	}

	// Verify comment
	if len(e.Comment) > int(p.commentLengthMax) {
		return "", backend.PluginError{
			PluginID:  comments.PluginID,
			ErrorCode: uint32(comments.ErrorCodeMaxLengthExceeded),
			ErrorContext: fmt.Sprintf("max length is %v characters",
				p.commentLengthMax),
		}
	}

	// Verify record state
	state, err := tstore.RecordState(token)
	if err != nil {
		return "", err
	}
	if uint32(e.State) != uint32(state) {
		return "", backend.PluginError{
			PluginID:     comments.PluginID,
			ErrorCode:    uint32(comments.ErrorCodeRecordStateInvalid),
			ErrorContext: fmt.Sprintf("got %v, want %v", e.State, state),
		}
	}

	// Get the cached record index
	ridx, err := getRecordIndex(tstore, token, state)
	if err != nil {
		return "", err
	}

	// Get the existing comment
	cs, err := ridx.comments(tstore, []uint32{e.CommentID})
	if err != nil {
		return "", err
	}
	existing, ok := cs[e.CommentID]
	if !ok {
		return "", backend.PluginError{
			PluginID:  comments.PluginID,
			ErrorCode: uint32(comments.ErrorCodeCommentNotFound),
		}
	}

	// Verify the user ID
	if e.UserID != existing.UserID {
		return "", backend.PluginError{
			PluginID:  comments.PluginID,
			ErrorCode: uint32(comments.ErrorCodeUserUnauthorized),
		}
	}

	// Verify the parent ID
	if e.ParentID != existing.ParentID {
		return "", backend.PluginError{
			PluginID:  comments.PluginID,
			ErrorCode: uint32(comments.ErrorCodeParentIDInvalid),
			ErrorContext: fmt.Sprintf("parent id cannot change; got %v, want %v",
				e.ParentID, existing.ParentID),
		}
	}

	// Verify comment changes
	if e.Comment == existing.Comment {
		return "", backend.PluginError{
			PluginID:  comments.PluginID,
			ErrorCode: uint32(comments.ErrorCodeNoChanges),
		}
	}

	// Create a new comment version
	receipt := p.identity.SignMessage([]byte(e.Signature))
	ca := comments.CommentAdd{
		UserID:        e.UserID,
		State:         e.State,
		Token:         e.Token,
		ParentID:      e.ParentID,
		Comment:       e.Comment,
		PublicKey:     e.PublicKey,
		Signature:     e.Signature,
		CommentID:     e.CommentID,
		Version:       existing.Version + 1,
		Timestamp:     time.Now().Unix(),
		Receipt:       hex.EncodeToString(receipt[:]),
		ExtraData:     e.ExtraData,
		ExtraDataHint: e.ExtraDataHint,
	}

	// Save comment
	digest, err := commentAddSave(tstore, token, ca)
	if err != nil {
		return "", err
	}

	// Update the index
	ridx.Comments[ca.CommentID].Adds[ca.Version] = digest

	// Save the updated index
	err = ridx.save(tstore, state)
	if err != nil {
		return "", err
	}

	log.Debugf("Comment edited on record %v comment ID %v",
		ca.Token, ca.CommentID)

	// Return updated comment
	c, err := ridx.comment(tstore, e.CommentID)
	if err != nil {
		return "", err
	}

	// Prepare reply
	er := comments.EditReply{
		Comment: *c,
	}
	reply, err := json.Marshal(er)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// cmdDel deletes a comment. This function permanently deletes the comment
// blobs from tstore.
func (p *commentsPlugin) cmdDel(tstore plugins.TstoreClient, token []byte, payload string) (string, error) {
	// Decode payload
	var d comments.Del
	err := json.Unmarshal([]byte(payload), &d)
	if err != nil {
		return "", err
	}

	// Verify token
	err = tokenMatches(token, d.Token)
	if err != nil {
		return "", err
	}

	// Verify signature
	msg := strconv.FormatUint(uint64(d.State), 10) + d.Token +
		strconv.FormatUint(uint64(d.CommentID), 10) + d.Reason
	err = verifySignature(d.Signature, d.PublicKey, msg)
	if err != nil {
		return "", err
	}

	// Verify record state
	state, err := tstore.RecordState(token)
	if err != nil {
		return "", err
	}
	if uint32(d.State) != uint32(state) {
		return "", backend.PluginError{
			PluginID:     comments.PluginID,
			ErrorCode:    uint32(comments.ErrorCodeRecordStateInvalid),
			ErrorContext: fmt.Sprintf("got %v, want %v", d.State, state),
		}
	}

	// Get the cached record index
	ridx, err := getRecordIndex(tstore, token, state)
	if err != nil {
		return "", err
	}

	// Get the existing comment
	cs, err := ridx.comments(tstore, []uint32{d.CommentID})
	if err != nil {
		return "", err
	}
	existing, ok := cs[d.CommentID]
	if !ok {
		return "", backend.PluginError{
			PluginID:  comments.PluginID,
			ErrorCode: uint32(comments.ErrorCodeCommentNotFound),
		}
	}

	// Prepare comment delete
	receipt := p.identity.SignMessage([]byte(d.Signature))
	cd := comments.CommentDel{
		Token:     d.Token,
		State:     d.State,
		CommentID: d.CommentID,
		Reason:    d.Reason,
		PublicKey: d.PublicKey,
		Signature: d.Signature,
		ParentID:  existing.ParentID,
		UserID:    existing.UserID,
		Timestamp: time.Now().Unix(),
		Receipt:   hex.EncodeToString(receipt[:]),
	}

	// Save comment del
	digest, err := commentDelSave(tstore, token, cd)
	if err != nil {
		return "", err
	}

	// Update the index
	cidx, ok := ridx.Comments[d.CommentID]
	if !ok {
		// Should not be possible. The cache is not coherent.
		panic(fmt.Sprintf("comment not found in index: %v", d.CommentID))
	}
	cidx.Del = digest
	ridx.Comments[d.CommentID] = cidx

	// Svae the updated index
	err = ridx.save(tstore, state)
	if err != nil {
		return "", err
	}

	// Delete all comment versions. A comment is considered deleted
	// once the CommenDel record has been saved. If attempts to
	// actually delete the blobs fails, simply log the error and
	// continue command execution. The period fsck will clean this up
	// next time it is run.
	digests := make([][]byte, 0, len(cidx.Adds))
	for _, v := range cidx.Adds {
		digests = append(digests, v)
	}
	err = tstore.BlobsDel(token, digests)
	if err != nil {
		log.Errorf("comments cmdDel %x: BlobsDel %x: %v ",
			token, digests, err)
	}

	// Return updated comment
	c, err := ridx.comment(tstore, d.CommentID)
	if err != nil {
		return "", err
	}

	// Prepare reply
	dr := comments.DelReply{
		Comment: *c,
	}
	reply, err := json.Marshal(dr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// cmdVote casts an upvote/downvote on a comment.
func (p *commentsPlugin) cmdVote(tstore plugins.TstoreClient, token []byte, payload string) (string, error) {
	// Decode payload
	var v comments.Vote
	err := json.Unmarshal([]byte(payload), &v)
	if err != nil {
		return "", err
	}

	// Verify token
	err = tokenMatches(token, v.Token)
	if err != nil {
		return "", err
	}

	// Verify vote
	switch v.Vote {
	case comments.VoteDownvote, comments.VoteUpvote:
		// These are allowed
	default:
		return "", backend.PluginError{
			PluginID:  comments.PluginID,
			ErrorCode: uint32(comments.ErrorCodeVoteInvalid),
		}
	}

	// Verify signature
	msg := strconv.FormatUint(uint64(v.State), 10) + v.Token +
		strconv.FormatUint(uint64(v.CommentID), 10) +
		strconv.FormatInt(int64(v.Vote), 10)
	err = verifySignature(v.Signature, v.PublicKey, msg)
	if err != nil {
		return "", err
	}

	// Verify record state
	state, err := tstore.RecordState(token)
	if err != nil {
		return "", err
	}
	if uint32(v.State) != uint32(state) {
		return "", backend.PluginError{
			PluginID:     comments.PluginID,
			ErrorCode:    uint32(comments.ErrorCodeRecordStateInvalid),
			ErrorContext: fmt.Sprintf("got %v, want %v", v.State, state),
		}
	}

	// Get the cached record index
	ridx, err := getRecordIndex(tstore, token, state)
	if err != nil {
		return "", err
	}

	// Verify comment exists
	cidx, ok := ridx.Comments[v.CommentID]
	if !ok {
		return "", backend.PluginError{
			PluginID:  comments.PluginID,
			ErrorCode: uint32(comments.ErrorCodeCommentNotFound),
		}
	}

	// Verify user has not exceeded max allowed vote changes
	if len(cidx.Votes[v.UserID]) > int(p.voteChangesMax) {
		return "", backend.PluginError{
			PluginID:  comments.PluginID,
			ErrorCode: uint32(comments.ErrorCodeVoteChangesMaxExceeded),
		}
	}

	// Verify user is not voting on their own comment
	cs, err := ridx.comments(tstore, []uint32{v.CommentID})
	if err != nil {
		return "", err
	}
	c, ok := cs[v.CommentID]
	if !ok {
		return "", errors.Errorf("comment not found %v", v.CommentID)
	}
	if v.UserID == c.UserID {
		return "", backend.PluginError{
			PluginID:     comments.PluginID,
			ErrorCode:    uint32(comments.ErrorCodeVoteInvalid),
			ErrorContext: "user cannot vote on their own comment",
		}
	}

	// Prepare comment vote
	receipt := p.identity.SignMessage([]byte(v.Signature))
	cv := comments.CommentVote{
		UserID:    v.UserID,
		State:     v.State,
		Token:     v.Token,
		CommentID: v.CommentID,
		Vote:      v.Vote,
		PublicKey: v.PublicKey,
		Signature: v.Signature,
		Timestamp: time.Now().Unix(),
		Receipt:   hex.EncodeToString(receipt[:]),
	}

	// Save comment vote
	digest, err := commentVoteSave(tstore, token, cv)
	if err != nil {
		return "", err
	}

	// Add vote to the comment index
	votes, ok := cidx.Votes[cv.UserID]
	if !ok {
		votes = make([]voteIndex, 0, 1)
	}
	votes = append(votes, voteIndex{
		Vote:   cv.Vote,
		Digest: digest,
	})
	cidx.Votes[cv.UserID] = votes
	ridx.Comments[cv.CommentID] = cidx

	// Save the updated index
	err = ridx.save(tstore, state)
	if err != nil {
		return "", err
	}

	// Calculate the new vote scores
	downvotes, upvotes := cidx.voteScore()

	// Prepare reply
	vr := comments.VoteReply{
		Downvotes: downvotes,
		Upvotes:   upvotes,
		Timestamp: cv.Timestamp,
		Receipt:   cv.Receipt,
	}
	reply, err := json.Marshal(vr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// cmdGet retrieves a batch of comments. The most recent version of each
// comment is returned.
func (p *commentsPlugin) cmdGet(tstore plugins.TstoreClient, token []byte, payload string) (string, error) {
	// Decode payload
	var g comments.Get
	err := json.Unmarshal([]byte(payload), &g)
	if err != nil {
		return "", err
	}

	// Get the cached record index
	state, err := tstore.RecordState(token)
	if err != nil {
		return "", err
	}
	ridx, err := getRecordIndex(tstore, token, state)
	if err != nil {
		return "", err
	}

	// Get the comments
	cs, err := ridx.comments(tstore, g.CommentIDs)
	if err != nil {
		return "", err
	}

	// Prepare reply
	gr := comments.GetReply{
		Comments: cs,
	}
	reply, err := json.Marshal(gr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// cmdGetAll retrieves all comments for a record. The latest version of each
// comment is returned.
func (p *commentsPlugin) cmdGetAll(tstore plugins.TstoreClient, token []byte) (string, error) {
	// Get the cached record index
	state, err := tstore.RecordState(token)
	if err != nil {
		return "", err
	}
	ridx, err := getRecordIndex(tstore, token, state)
	if err != nil {
		return "", err
	}

	// Compile the comment IDs to be retrieved
	commentIDs := make([]uint32, 0, len(ridx.Comments))
	for k := range ridx.Comments {
		commentIDs = append(commentIDs, k)
	}

	// Get the comments
	c, err := ridx.comments(tstore, commentIDs)
	if err != nil {
		return "", err
	}

	// Convert the comments from a map to a slice
	// that is ordered by comment ID.
	cs := make([]comments.Comment, 0, len(c))
	for _, v := range c {
		cs = append(cs, v)
	}
	sort.SliceStable(cs, func(i, j int) bool {
		return cs[i].CommentID < cs[j].CommentID
	})

	// Prepare reply
	gar := comments.GetAllReply{
		Comments: cs,
	}
	reply, err := json.Marshal(gar)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// cmdGetVersion retrieves the specified version of a comment.
func (p *commentsPlugin) cmdGetVersion(tstore plugins.TstoreClient, token []byte, payload string) (string, error) {
	// Decode payload
	var gv comments.GetVersion
	err := json.Unmarshal([]byte(payload), &gv)
	if err != nil {
		return "", err
	}

	// Get the cached record index
	state, err := tstore.RecordState(token)
	if err != nil {
		return "", err
	}
	ridx, err := getRecordIndex(tstore, token, state)
	if err != nil {
		return "", err
	}

	// Verify that the comment exists
	cidx, ok := ridx.Comments[gv.CommentID]
	if !ok {
		return "", backend.PluginError{
			PluginID:  comments.PluginID,
			ErrorCode: uint32(comments.ErrorCodeCommentNotFound),
		}
	}
	if cidx.Del != nil {
		return "", backend.PluginError{
			PluginID:     comments.PluginID,
			ErrorCode:    uint32(comments.ErrorCodeCommentNotFound),
			ErrorContext: "comment has been deleted",
		}
	}
	digest, ok := cidx.Adds[gv.Version]
	if !ok {
		return "", backend.PluginError{
			PluginID:  comments.PluginID,
			ErrorCode: uint32(comments.ErrorCodeCommentNotFound),
			ErrorContext: fmt.Sprintf("comment %v does not have version %v",
				gv.CommentID, gv.Version),
		}
	}

	// Get the comment add record
	adds, err := commentAdds(tstore, token, [][]byte{digest})
	if err != nil {
		return "", err
	}

	// Convert the comment add record to a comment
	c := commentAddConvert(adds[0])
	c.Downvotes, c.Upvotes = cidx.voteScore()

	// Prepare the reply
	gvr := comments.GetVersionReply{
		Comment: c,
	}
	reply, err := json.Marshal(gvr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// cmdCount retrieves the comments count for a record. The comments count is
// the number of comments that have been made on a record.
func (p *commentsPlugin) cmdCount(tstore plugins.TstoreClient, token []byte) (string, error) {
	// Get the cached record index
	state, err := tstore.RecordState(token)
	if err != nil {
		return "", err
	}
	ridx, err := getRecordIndex(tstore, token, state)
	if err != nil {
		return "", err
	}

	// Prepare reply
	cr := comments.CountReply{
		Count: uint32(len(ridx.Comments)),
	}
	reply, err := json.Marshal(cr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// cmdVotes retrieves the comment votes that meet the provided filtering
// criteria.
func (p *commentsPlugin) cmdVotes(tstore plugins.TstoreClient, token []byte, payload string) (string, error) {
	// Decode payload
	var v comments.Votes
	err := json.Unmarshal([]byte(payload), &v)
	if err != nil {
		return "", err
	}

	// Get the cached record index
	state, err := tstore.RecordState(token)
	if err != nil {
		return "", err
	}
	ridx, err := getRecordIndex(tstore, token, state)
	if err != nil {
		return "", err
	}

	// Compile the comment vote digests for all votes that
	// were cast by the specified user.
	digests := make([][]byte, 0, 256)
	for _, cidx := range ridx.Comments {
		voteIdxs, ok := cidx.Votes[v.UserID]
		if !ok {
			// User has not cast any votes for this comment
			continue
		}

		// User has cast votes on this comment
		for _, vidx := range voteIdxs {
			digests = append(digests, vidx.Digest)
		}
	}

	// Get the votes
	votes, err := commentVotes(tstore, token, digests)
	if err != nil {
		return "", err
	}

	// Prepare reply
	vr := comments.VotesReply{
		Votes: votes,
	}
	reply, err := json.Marshal(vr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// cmdTimestamps retrieves the timestamps for the comments of a record.
func (p *commentsPlugin) cmdTimestamps(tstore plugins.TstoreClient, token []byte, payload string) (string, error) {
	// Decode payload
	var t comments.Timestamps
	err := json.Unmarshal([]byte(payload), &t)
	if err != nil {
		return "", err
	}

	// Get timestamps
	ctr, err := commentTimestamps(tstore, token,
		t.CommentIDs, t.IncludeVotes)
	if err != nil {
		return "", err
	}

	// Prepare reply
	reply, err := json.Marshal(*ctr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// tokenDecode decodes a tstore token string into a byte slice. This function
// will error if the token is not a full length token.
func tokenDecode(token string) ([]byte, error) {
	return util.TokenDecode(util.TokenTypeTstore, token)
}

// tokenMatches verifies that the command token (the token for the record that
// this plugin command is being executed on) matches the payload token (the
// token that the plugin command payload contains that is typically used in the
// payload signature). The payload token must be the full length token.
func tokenMatches(cmdToken []byte, payloadToken string) error {
	pt, err := tokenDecode(payloadToken)
	if err != nil {
		return backend.PluginError{
			PluginID:     comments.PluginID,
			ErrorCode:    uint32(comments.ErrorCodeTokenInvalid),
			ErrorContext: util.TokenRegexp(),
		}
	}
	if !bytes.Equal(cmdToken, pt) {
		return backend.PluginError{
			PluginID:  comments.PluginID,
			ErrorCode: uint32(comments.ErrorCodeTokenInvalid),
			ErrorContext: fmt.Sprintf("payload token does not "+
				"match cmd token: got %x, want %x", pt, cmdToken),
		}
	}
	return nil
}

// commentAddEncode encodes a CommentAdd into a BlobEntry.
func commentAddEncode(c comments.CommentAdd) (*store.BlobEntry, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	dd := store.DataDescriptor{
		Type:       store.DataTypeStructure,
		Descriptor: dataDescriptorCommentAdd,
	}
	return store.NewBlobEntry(dd, data)
}

// commentAddDecode decodes a BlobEntry into a CommentAdd.
func commentAddDecode(be store.BlobEntry) (*comments.CommentAdd, error) {
	b, err := store.Decode(be, dataDescriptorCommentAdd)
	if err != nil {
		return nil, err
	}
	var c comments.CommentAdd
	err = json.Unmarshal(b, &c)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// commentAddConvert converts a CommentAdd to a Comment. Not all fields of the
// Comment will be populated. The Upvotes and Downvotes must be filled in
// separately.
func commentAddConvert(ca comments.CommentAdd) comments.Comment {
	return comments.Comment{
		UserID:        ca.UserID,
		State:         ca.State,
		Token:         ca.Token,
		ParentID:      ca.ParentID,
		Comment:       ca.Comment,
		PublicKey:     ca.PublicKey,
		Signature:     ca.Signature,
		CommentID:     ca.CommentID,
		Version:       ca.Version,
		Timestamp:     ca.Timestamp,
		Receipt:       ca.Receipt,
		Downvotes:     0, // Not part of commentAdd data
		Upvotes:       0, // Not part of commentAdd data
		Deleted:       false,
		Reason:        "",
		ExtraData:     ca.ExtraData,
		ExtraDataHint: ca.ExtraDataHint,
	}
}

// commentAddSave saves a CommentAdd to the backend.
func commentAddSave(tstore plugins.TstoreClient, token []byte, ca comments.CommentAdd) ([]byte, error) {
	be, err := commentAddEncode(ca)
	if err != nil {
		return nil, err
	}
	d, err := hex.DecodeString(be.Digest)
	if err != nil {
		return nil, err
	}
	err = tstore.BlobSave(token, *be)
	if err != nil {
		return nil, err
	}
	return d, nil
}

// commentAdds returns a commentAdd for each of the provided digests. A digest
// refers to the blob entry digest, which can be used to retrieve the blob
// entry from the backend. An error is returned if a blob entry is not found
// for any of the provided digests.
func commentAdds(tstore plugins.TstoreClient, token []byte, digests [][]byte) ([]comments.CommentAdd, error) {
	// Retrieve blobs
	blobs, err := tstore.Blobs(token, digests)
	if err != nil {
		return nil, err
	}
	if len(blobs) != len(digests) {
		notFound := make([]string, 0, len(blobs))
		for _, v := range digests {
			m := hex.EncodeToString(v)
			_, ok := blobs[m]
			if !ok {
				notFound = append(notFound, m)
			}
		}
		return nil, errors.Errorf("blobs not found: %v", notFound)
	}

	// Decode blobs
	adds := make([]comments.CommentAdd, 0, len(blobs))
	for _, v := range blobs {
		c, err := commentAddDecode(v)
		if err != nil {
			return nil, err
		}
		adds = append(adds, *c)
	}

	return adds, nil
}

// commentDelEncode encodes a CommentDel into a BlobEntry.
func commentDelEncode(c comments.CommentDel) (*store.BlobEntry, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	dd := store.DataDescriptor{
		Type:       store.DataTypeStructure,
		Descriptor: dataDescriptorCommentDel,
	}
	return store.NewBlobEntry(dd, data)
}

// commentDelDecode decodes a BlobEntry into a CommentDel.
func commentDelDecode(be store.BlobEntry) (*comments.CommentDel, error) {
	b, err := store.Decode(be, dataDescriptorCommentDel)
	if err != nil {
		return nil, err
	}
	var c comments.CommentDel
	err = json.Unmarshal(b, &c)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// commentDelConvert converts a commentDel into a Comment. Not all fields will
// be populated. The Upvotes and Downvotes must be filled in separately.
func commentDelConvert(cd comments.CommentDel) comments.Comment {
	return comments.Comment{
		UserID:    cd.UserID,
		State:     cd.State,
		Token:     cd.Token,
		ParentID:  cd.ParentID,
		Comment:   "",
		PublicKey: cd.PublicKey,
		Signature: cd.Signature,
		CommentID: cd.CommentID,
		Version:   0,
		Timestamp: cd.Timestamp,
		Receipt:   cd.Receipt,
		Downvotes: 0,
		Upvotes:   0,
		Deleted:   true,
		Reason:    cd.Reason,
	}
}

// commentDelSave saves a CommentDel to the backend.
func commentDelSave(tstore plugins.TstoreClient, token []byte, cd comments.CommentDel) ([]byte, error) {
	be, err := commentDelEncode(cd)
	if err != nil {
		return nil, err
	}
	d, err := hex.DecodeString(be.Digest)
	if err != nil {
		return nil, err
	}
	err = tstore.BlobSave(token, *be)
	if err != nil {
		return nil, err
	}
	return d, nil
}

// commentDels returns a CommentDel for each of the provided digests. A digest
// refers to the blob entry digest, which can be used to retrieve the blob
// entry from the backend. An error is returned if a blob entry is not found
// for any of the provided digests.
func commentDels(tstore plugins.TstoreClient, token []byte, digests [][]byte) ([]comments.CommentDel, error) {
	// Retrieve blobs
	blobs, err := tstore.Blobs(token, digests)
	if err != nil {
		return nil, err
	}
	if len(blobs) != len(digests) {
		notFound := make([]string, 0, len(blobs))
		for _, v := range digests {
			m := hex.EncodeToString(v)
			_, ok := blobs[m]
			if !ok {
				notFound = append(notFound, m)
			}
		}
		return nil, errors.Errorf("blobs not found: %v", notFound)
	}

	// Decode blobs
	dels := make([]comments.CommentDel, 0, len(blobs))
	for _, v := range blobs {
		d, err := commentDelDecode(v)
		if err != nil {
			return nil, err
		}
		dels = append(dels, *d)
	}

	return dels, nil
}

// commentVoteEncode encodes a CommentVote into a BlobEntry.
func commentVoteEncode(c comments.CommentVote) (*store.BlobEntry, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	dd := store.DataDescriptor{
		Type:       store.DataTypeStructure,
		Descriptor: dataDescriptorCommentVote,
	}
	return store.NewBlobEntry(dd, data)
}

// commentVoteDecode decodes a BlobEntry into a CommentVote.
func commentVoteDecode(be store.BlobEntry) (*comments.CommentVote, error) {
	b, err := store.Decode(be, dataDescriptorCommentVote)
	if err != nil {
		return nil, err
	}
	var cv comments.CommentVote
	err = json.Unmarshal(b, &cv)
	if err != nil {
		return nil, err
	}
	return &cv, nil
}

// commentVoteSave saves a CommentVote to the backend.
func commentVoteSave(tstore plugins.TstoreClient, token []byte, cv comments.CommentVote) ([]byte, error) {
	be, err := commentVoteEncode(cv)
	if err != nil {
		return nil, err
	}
	d, err := hex.DecodeString(be.Digest)
	if err != nil {
		return nil, err
	}
	err = tstore.BlobSave(token, *be)
	if err != nil {
		return nil, err
	}
	return d, nil
}

// commentVotes returns a CommentVote for each of the provided digests. A
// digest refers to the blob entry digest, which can be used to retrieve the
// blob entry from the backend. An error is returned if a blob entry is not
// found for any of the provided digests.
func commentVotes(tstore plugins.TstoreClient, token []byte, digests [][]byte) ([]comments.CommentVote, error) {
	// Retrieve blobs
	blobs, err := tstore.Blobs(token, digests)
	if err != nil {
		return nil, err
	}
	if len(blobs) != len(digests) {
		notFound := make([]string, 0, len(blobs))
		for _, v := range digests {
			m := hex.EncodeToString(v)
			_, ok := blobs[m]
			if !ok {
				notFound = append(notFound, m)
			}
		}
		return nil, errors.Errorf("blobs not found: %v", notFound)
	}

	// Decode blobs
	votes := make([]comments.CommentVote, 0, len(blobs))
	for _, v := range blobs {
		c, err := commentVoteDecode(v)
		if err != nil {
			return nil, err
		}
		votes = append(votes, *c)
	}

	return votes, nil
}

// commentTimestamps returns the CommentTimestamp for each of the provided
// comment IDs. If a timestamp is not found for a comment ID, the comment ID
// will not be included in the reply. An error is not returned. It is the
// responsibility of the caller to verify that a timestamp is returned for each
// of the provided comment IDs.
func commentTimestamps(tstore plugins.TstoreClient, token []byte, commentIDs []uint32, includeVotes bool) (*comments.TimestampsReply, error) {
	// Verify there is work to do
	if len(commentIDs) == 0 {
		return &comments.TimestampsReply{
			Comments: map[uint32]comments.CommentTimestamp{},
		}, nil
	}

	// Get the cached record index
	state, err := tstore.RecordState(token)
	if err != nil {
		return nil, err
	}
	ridx, err := getRecordIndex(tstore, token, state)
	if err != nil {
		return nil, err
	}

	// Get the timestamps for each comment ID
	cts := make(map[uint32]comments.CommentTimestamp, len(commentIDs))
	for _, cid := range commentIDs {
		cidx, ok := ridx.Comments[cid]
		if !ok {
			// Comment ID does not exist. Skip it.
			continue
		}

		// Get the timestamp for the comment add records
		adds := make([]comments.Timestamp, 0, len(cidx.Adds))
		for _, v := range cidx.Adds {
			ts, err := timestamp(tstore, token, v)
			if err != nil {
				return nil, err
			}
			adds = append(adds, *ts)
		}

		// Get the timestamp for the comment del record. This
		// will only exist if the comment has been deleted.
		var del *comments.Timestamp
		if cidx.Del != nil {
			ts, err := timestamp(tstore, token, cidx.Del)
			if err != nil {
				return nil, err
			}
			del = ts
		}

		// Get the timestamp for the comment vote records
		var votes []comments.Timestamp
		if includeVotes {
			votes = make([]comments.Timestamp, 0, len(cidx.Votes))
			for _, voteIdxs := range cidx.Votes {
				for _, v := range voteIdxs {
					ts, err := timestamp(tstore, token, v.Digest)
					if err != nil {
						return nil, err
					}
					votes = append(votes, *ts)
				}
			}
		}

		// Save the timestamp
		cts[cid] = comments.CommentTimestamp{
			Adds:  adds,
			Del:   del,
			Votes: votes,
		}
	}

	return &comments.TimestampsReply{
		Comments: cts,
	}, nil
}

// timestamp returns the timestamp for a blob entry digest.
func timestamp(tstore plugins.TstoreClient, token []byte, digest []byte) (*comments.Timestamp, error) {
	// Get timestamp
	t, err := tstore.Timestamp(token, digest)
	if err != nil {
		return nil, err
	}

	// Convert response
	proofs := make([]comments.Proof, 0, len(t.Proofs))
	for _, v := range t.Proofs {
		proofs = append(proofs, comments.Proof{
			Type:       v.Type,
			Digest:     v.Digest,
			MerkleRoot: v.MerkleRoot,
			MerklePath: v.MerklePath,
			ExtraData:  v.ExtraData,
		})
	}
	return &comments.Timestamp{
		Data:       t.Data,
		Digest:     t.Digest,
		TxID:       t.TxID,
		MerkleRoot: t.MerkleRoot,
		Proofs:     proofs,
	}, nil
}

// verifySignature provides a wrapper around the util VerifySignature method
// that converts any returned errors into comment plugin errors.
func verifySignature(signature, pubkey, msg string) error {
	err := util.VerifySignature(signature, pubkey, msg)
	if err != nil {
		return convertSignatureError(err)
	}
	return nil
}

// convertSignatureError converts a util SignatureError into a backend
// PluginError for the comments plugin.
func convertSignatureError(err error) backend.PluginError {
	var e util.SignatureError
	var s comments.ErrorCodeT
	if errors.As(err, &e) {
		switch e.ErrorCode {
		case util.ErrorStatusPublicKeyInvalid:
			s = comments.ErrorCodePublicKeyInvalid
		case util.ErrorStatusSignatureInvalid:
			s = comments.ErrorCodeSignatureInvalid
		}
	}
	return backend.PluginError{
		PluginID:     comments.PluginID,
		ErrorCode:    uint32(s),
		ErrorContext: e.ErrorContext,
	}
}
