// Copyright (c) 2020-2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package comments

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"time"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
	"github.com/decred/politeia/politeiad/plugins/comments"
	"github.com/decred/politeia/util"
	"github.com/pkg/errors"
)

const (
	pluginID = comments.PluginID

	// Blob entry data descriptors
	dataDescriptorCommentAdd  = pluginID + "-add-v1"
	dataDescriptorCommentDel  = pluginID + "-del-v1"
	dataDescriptorCommentVote = pluginID + "-vote-v1"

	// Key-value cache keys patterns
	cacheKeyPatternTimestamp = "timestamp-{shorttoken}-{commentID}"
)

// commentAddSave saves a CommentAdd to the backend.
func (p *commentsPlugin) commentAddSave(token []byte, ca comments.CommentAdd) ([]byte, error) {
	be, err := convertBlobEntryFromCommentAdd(ca)
	if err != nil {
		return nil, err
	}
	d, err := hex.DecodeString(be.Digest)
	if err != nil {
		return nil, err
	}
	err = p.tstore.BlobSave(token, *be)
	if err != nil {
		return nil, err
	}
	return d, nil
}

// commentAdds returns a commentAdd for each of the provided digests. A digest
// refers to the blob entry digest, which can be used to retrieve the blob
// entry from the backend.
func (p *commentsPlugin) commentAdds(token []byte, digests [][]byte) ([]comments.CommentAdd, error) {
	// Retrieve blobs
	blobs, err := p.tstore.Blobs(token, digests)
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
		return nil, fmt.Errorf("blobs not found: %v", notFound)
	}

	// Decode blobs
	adds := make([]comments.CommentAdd, 0, len(blobs))
	for _, v := range blobs {
		c, err := convertCommentAddFromBlobEntry(v)
		if err != nil {
			return nil, err
		}
		adds = append(adds, *c)
	}

	return adds, nil
}

// commentDelSave saves a CommentDel to the backend.
func (p *commentsPlugin) commentDelSave(token []byte, cd comments.CommentDel) ([]byte, error) {
	be, err := convertBlobEntryFromCommentDel(cd)
	if err != nil {
		return nil, err
	}
	d, err := hex.DecodeString(be.Digest)
	if err != nil {
		return nil, err
	}
	err = p.tstore.BlobSave(token, *be)
	if err != nil {
		return nil, err
	}
	return d, nil
}

// commentDels returns a commentDel for each of the provided digests. A digest
// refers to the blob entry digest, which can be used to retrieve the blob
// entry from the backend.
func (p *commentsPlugin) commentDels(token []byte, digests [][]byte) ([]comments.CommentDel, error) {
	// Retrieve blobs
	blobs, err := p.tstore.Blobs(token, digests)
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
		return nil, fmt.Errorf("blobs not found: %v", notFound)
	}

	// Decode blobs
	dels := make([]comments.CommentDel, 0, len(blobs))
	for _, v := range blobs {
		d, err := convertCommentDelFromBlobEntry(v)
		if err != nil {
			return nil, err
		}
		dels = append(dels, *d)
	}

	return dels, nil
}

// commentVoteSave saves a CommentVote to the backend.
func (p *commentsPlugin) commentVoteSave(token []byte, cv comments.CommentVote) ([]byte, error) {
	be, err := convertBlobEntryFromCommentVote(cv)
	if err != nil {
		return nil, err
	}
	d, err := hex.DecodeString(be.Digest)
	if err != nil {
		return nil, err
	}
	err = p.tstore.BlobSave(token, *be)
	if err != nil {
		return nil, err
	}
	return d, nil
}

// commentVotes returns a CommentVote for each of the provided digests. A
// digest refers to the blob entry digest, which can be used to retrieve the
// blob entry from the backend.
func (p *commentsPlugin) commentVotes(token []byte, digests [][]byte) ([]comments.CommentVote, error) {
	// Retrieve blobs
	blobs, err := p.tstore.Blobs(token, digests)
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
		return nil, fmt.Errorf("blobs not found: %v", notFound)
	}

	// Decode blobs
	votes := make([]comments.CommentVote, 0, len(blobs))
	for _, v := range blobs {
		c, err := convertCommentVoteFromBlobEntry(v)
		if err != nil {
			return nil, err
		}
		votes = append(votes, *c)
	}

	return votes, nil
}

// comments returns the most recent version of the specified comments. Deleted
// comments are returned with limited data. If a comment is not found for a
// provided comment IDs, the comment ID is excluded from the returned map. An
// error will not be returned. It is the responsibility of the caller to ensure
// a comment is returned for each of the provided comment IDs.
func (p *commentsPlugin) comments(token []byte, ridx recordIndex, commentIDs []uint32) (map[uint32]comments.Comment, error) {
	// Aggregate the digests for all records that need to be looked up.
	// If a comment has been deleted then the only record that will
	// still exist is the comment del record. If the comment has not
	// been deleted then the comment add record will need to be
	// retrieved for the latest version of the comment.
	var (
		digestAdds = make([][]byte, 0, len(commentIDs))
		digestDels = make([][]byte, 0, len(commentIDs))
	)
	for _, v := range commentIDs {
		cidx, ok := ridx.Comments[v]
		if !ok {
			// Comment does not exist
			continue
		}

		// Comment del record
		if cidx.Del != nil {
			digestDels = append(digestDels, cidx.Del)
			continue
		}

		// Comment add record
		version := commentVersionLatest(cidx)
		digestAdds = append(digestAdds, cidx.Adds[version])
	}

	// Get comment add records
	adds, err := p.commentAdds(token, digestAdds)
	if err != nil {
		return nil, errors.Errorf("commentAdds: %v", err)
	}
	if len(adds) != len(digestAdds) {
		return nil, errors.Errorf("wrong comment adds count; got %v, want %v",
			len(adds), len(digestAdds))
	}

	// Get comment del records
	dels, err := p.commentDels(token, digestDels)
	if err != nil {
		return nil, errors.Errorf("commentDels: %v", err)
	}
	if len(dels) != len(digestDels) {
		return nil, errors.Errorf("wrong comment dels count; got %v, want %v",
			len(dels), len(digestDels))
	}

	// Prepare comments
	cs := make(map[uint32]comments.Comment, len(commentIDs))
	for _, v := range adds {
		c := convertCommentFromCommentAdd(v)
		cidx, ok := ridx.Comments[c.CommentID]
		if !ok {
			return nil, errors.Errorf("comment index not found %v", c.CommentID)
		}
		c.Downvotes, c.Upvotes = voteScore(cidx)
		// Populate creation timestamp
		c.CreatedAt, err = p.commentCreationTimestamp(c, cidx)
		if err != nil {
			return nil, err
		}

		cs[v.CommentID] = c
	}
	for _, v := range dels {
		c := convertCommentFromCommentDel(v)
		cs[v.CommentID] = c
	}

	return cs, nil
}

// commentCreationTimestamp accepts the latest version of a comment with the
// comment index , and it returns the comment's creation timestamp.
func (p *commentsPlugin) commentCreationTimestamp(c comments.Comment, cidx commentIndex) (int64, error) {
	// If comment was not edited, then the comment creation timestamp is
	// equal to the first version's timestamp.
	if c.Version == 1 {
		return c.Timestamp, nil
	}

	// If comment was edited, we need to get the first version of the
	// comment in order to determine the creation timestamp.
	b, err := tokenDecode(c.Token)
	if err != nil {
		return 0, err
	}
	cf, err := p.commentFirstVersion(b, c.CommentID, cidx)
	if err != nil {
		return 0, err
	}

	return cf.Timestamp, nil
}

// comment returns the latest version of a comment.
func (p *commentsPlugin) comment(token []byte, ridx recordIndex, commentID uint32) (*comments.Comment, error) {
	cs, err := p.comments(token, ridx, []uint32{commentID})
	if err != nil {
		return nil, fmt.Errorf("comments: %v", err)
	}
	c, ok := cs[commentID]
	if !ok {
		return nil, fmt.Errorf("comment not found")
	}
	return &c, nil
}

// timestamp returns the timestamp for a blob entry digest.
func (p *commentsPlugin) timestamp(token []byte, digest []byte) (*comments.Timestamp, error) {
	// Get timestamp
	t, err := p.tstore.Timestamp(token, digest)
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

// commentTimestamps returns the CommentTimestamp for each of the provided
// comment IDs.
func (p *commentsPlugin) commentTimestamps(token []byte, commentIDs []uint32, includeVotes bool) (*comments.TimestampsReply, error) {
	// Verify there is work to do
	if len(commentIDs) == 0 {
		return &comments.TimestampsReply{
			Comments: map[uint32]comments.CommentTimestamp{},
		}, nil
	}

	// Look for final timestamps in the key-value store. Caching final timestamps
	// is necessary to improve the performance which is proportional to the tree
	// size.
	cts, err := p.cachedTimestamps(token, commentIDs)
	if err != nil {
		return nil, err
	}

	// Get record state
	state, err := p.tstore.RecordState(token)
	if err != nil {
		return nil, err
	}

	// Get record index
	ridx, err := p.recordIndex(token, state)
	if err != nil {
		return nil, err
	}

	// Get timestamps for each comment ID
	r := make(map[uint32]comments.CommentTimestamp, len(commentIDs))
	for _, cid := range commentIDs {
		cidx, ok := ridx.Comments[cid]
		if !ok {
			// Comment ID does not exist. Skip it.
			continue
		}

		// Get cached comment timestamp associated with current comment ID if one
		// exists, nil otherwise.
		ct := cts[cid]

		// Get comment add timestamps
		adds := make([]comments.Timestamp, 0, len(cidx.Adds))
		for _, v := range cidx.Adds {
			// Check if the comment add digest timestamp is final and already exists
			// in cache.
			t := cachedCommentAddTimestamp(ct, v)
			if t != nil {
				// Cached timestamp found, collect it and continue to next comment
				// add digest.
				adds = append(adds, *t)
				continue
			}

			// Comment add digest was not found in cache, get timestamp
			ts, err := p.timestamp(token, v)
			if err != nil {
				return nil, err
			}
			adds = append(adds, *ts)
		}

		// Get comment del timestamps. This will only exist if the
		// comment has been deleted.
		var del *comments.Timestamp
		if cidx.Del != nil {
			// Check if the comment del digest timestamp is final and already exists
			// in cache.
			t := cachedCommentDelTimestamp(ct,
				cidx.Del)
			switch {
			case t != nil:
				// Comment del timestamp found in cache, collect it
				del = t

			case t == nil:
				// Comment del timestamp was not found in cache, get timestamp
				ts, err := p.timestamp(token, cidx.Del)
				if err != nil {
					return nil, err
				}
				del = ts
			}
		}

		// Get comment vote timestamps
		var votes []comments.Timestamp
		if includeVotes {
			votes = make([]comments.Timestamp, 0, len(cidx.Votes))
			for _, voteIdxs := range cidx.Votes {
				for _, v := range voteIdxs {
					// Check if the comment vote digest timestamp is final and already
					// exists in cache.
					t := cachedCommentVoteTimestamp(ct,
						v.Digest)
					if t != nil {
						// Cached timestamp found, collect it and continue to next comment
						// vote digest.
						votes = append(votes, *t)
						continue
					}

					// Comment vote digest was not found in cache, get timestamp
					ts, err := p.timestamp(token, v.Digest)
					if err != nil {
						return nil, err
					}
					votes = append(votes, *ts)
				}
			}
		}

		// Save timestamp
		r[cid] = comments.CommentTimestamp{
			Adds:  adds,
			Del:   del,
			Votes: votes,
		}
	}

	// Cache final timestamps
	err = p.cacheFinalTimestamps(token, r)
	if err != nil {
		return nil, err
	}

	return &comments.TimestampsReply{
		Comments: r,
	}, nil
}

// cacheFinalTimestamps accepts a map of comment timestamps, it collects the
// final timestamps then stores them in the key-value store.
func (p *commentsPlugin) cacheFinalTimestamps(token []byte, cts map[uint32]comments.CommentTimestamp) error {
	finalTimestamps, err := finalCommentTimestamps(cts, token)
	if err != nil {
		return err
	}

	return p.saveTimestamps(token, finalTimestamps)
}

// finalCommentTimestamps accepts a map of comment timestamps, and it returns
// a new map with all final comment timestamps. A timestamp considered final
// if it was successfully timestamped on the DCR chain, meaning it's merkle
// root was included in a confirmed DCR transaction.
func finalCommentTimestamps(ts map[uint32]comments.CommentTimestamp, token []byte) (map[uint32]comments.CommentTimestamp, error) {
	fts := make(map[uint32]comments.CommentTimestamp, len(ts))
	for cid, t := range ts {
		// Search for final comment add timestamps
		for _, at := range t.Adds {
			if timestampIsFinal(at) {
				// Add final comment add to the final timestamps map.
				ct, exists := fts[cid]
				if !exists {
					ct = comments.CommentTimestamp{}
				}
				if len(ct.Adds) == 0 {
					ct.Adds = make([]comments.Timestamp, 0, len(t.Adds))
				}
				ct.Adds = append(ct.Adds, at)
				fts[cid] = ct
			}
		}

		// Search for final comment del timestamp
		if t.Del != nil && timestampIsFinal(*t.Del) {
			// Add final comment del to final timestamps map.
			ct, exists := fts[cid]
			if !exists {
				ct = comments.CommentTimestamp{}
			}
			ct.Del = t.Del
			fts[cid] = ct
		}

		// Search for final comment vote timestamps
		for _, vt := range t.Votes {
			if timestampIsFinal(vt) {
				// Add final comment add to the final timestamps map.
				ct, exists := fts[cid]
				if !exists {
					ct = comments.CommentTimestamp{}
				}
				if len(ct.Votes) == 0 {
					ct.Votes = make([]comments.Timestamp, 0, len(t.Votes))
				}
				ct.Votes = append(ct.Votes, vt)
				fts[cid] = ct
			}
		}
	}

	return fts, nil
}

// cachedCommentVoteTimestamp accepts a pointer to a CommentTimestamp, and a
// comment vote digest. It searches for the given comment vote digest in the
// given cached comment vote timestamps. It returns the timestamp if it finds
// it and nil otherwise.
func cachedCommentVoteTimestamp(ct *comments.CommentTimestamp, digest []byte) *comments.Timestamp {
	if ct == nil {
		return nil
	}

	for _, t := range ct.Votes {
		if t.Digest == hex.EncodeToString(digest) {
			return &t
		}
	}

	return nil
}

// commentDelCachedTimestamp accepts a pointer to a CommentTimestamp, and a
// comment del digest. It returns the timestamp of the given comment del digest
// if it finds it, and nil otherwise.
func cachedCommentDelTimestamp(ct *comments.CommentTimestamp, digest []byte) *comments.Timestamp {
	if ct == nil {
		return nil
	}

	if ct.Del != nil && ct.Del.Digest == hex.EncodeToString(digest) {
		return ct.Del
	}

	return nil
}

// cachedCommentAddTimestamp accepts a pointer to a CommentTimestamp, and a
// comment add digest. It searches for the given comment add digest in the
// given cached comment add timestamps. It returns the timestamp if it finds
// it and nil otherwise.
func cachedCommentAddTimestamp(ct *comments.CommentTimestamp, digest []byte) *comments.Timestamp {
	if ct == nil {
		return nil
	}

	for _, t := range ct.Adds {
		if t.Digest == hex.EncodeToString(digest) {
			return &t
		}
	}

	return nil
}

// voteScore returns the total number of downvotes and upvotes, respectively,
// for a comment.
func voteScore(cidx commentIndex) (uint64, uint64) {
	// Find the vote score by replaying all existing votes from all
	// users. The net effect of a new vote on a comment score depends
	// on the previous vote from that uuid. Example, a user upvotes a
	// comment that they have already upvoted, the resulting vote score
	// is 0 due to the second upvote removing the original upvote.
	var upvotes uint64
	var downvotes uint64
	for _, votes := range cidx.Votes {
		// Calculate the vote score that this user is contributing. This
		// can only ever be -1, 0, or 1.
		var score int64
		for _, v := range votes {
			vote := int64(v.Vote)
			switch {
			case score == 0:
				// No previous vote. New vote becomes the score.
				score = vote

			case score == vote:
				// New vote is the same as the previous vote. The vote gets
				// removed from the score, making the score 0.
				score = 0

			case score != vote:
				// New vote is different than the previous vote. New vote
				// becomes the score.
				score = vote
			}
		}

		// Add the net result of all votes from this user to the totals.
		switch score {
		case 0:
			// Nothing to do
		case -1:
			downvotes++
		case 1:
			upvotes++
		default:
			// Should not be possible
			panic(fmt.Errorf("unexpected vote score %v", score))
		}
	}

	return downvotes, upvotes
}

// cmdNew creates a new comment.
func (p *commentsPlugin) cmdNew(token []byte, payload string) (string, error) {
	// Decode payload
	var n comments.New
	err := json.Unmarshal([]byte(payload), &n)
	if err != nil {
		return "", err
	}

	// Verify token
	err = tokenVerify(token, n.Token)
	if err != nil {
		return "", err
	}

	// Ensure no extra data provided if not allowed
	err = p.verifyExtraData(n.ExtraData, n.ExtraDataHint)
	if err != nil {
		return "", err
	}

	// Verify signature
	msg := strconv.FormatUint(uint64(n.State), 10) + n.Token +
		strconv.FormatUint(uint64(n.ParentID), 10) + n.Comment +
		n.ExtraData + n.ExtraDataHint
	err = util.VerifySignature(n.Signature, n.PublicKey, msg)
	if err != nil {
		return "", convertSignatureError(err)
	}

	// Verify comment
	if len(n.Comment) > int(p.commentLengthMax) {
		return "", backend.PluginError{
			PluginID:  comments.PluginID,
			ErrorCode: uint32(comments.ErrorCodeMaxLengthExceeded),
			ErrorContext: fmt.Sprintf("max length is %v characters",
				p.commentLengthMax),
		}
	}

	// Verify record state
	state, err := p.tstore.RecordState(token)
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

	// Get record index
	ridx, err := p.recordIndex(token, state)
	if err != nil {
		return "", err
	}

	// Verify parent comment exists if set. A parent ID of 0 means that
	// this is a base level comment, not a reply to another comment.
	if n.ParentID > 0 && !commentExists(*ridx, n.ParentID) {
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
		CommentID:     commentIDLatest(*ridx) + 1,
		Version:       1,
		Timestamp:     time.Now().Unix(),
		Receipt:       hex.EncodeToString(receipt[:]),
		ExtraData:     n.ExtraData,
		ExtraDataHint: n.ExtraDataHint,
	}

	// Save comment
	digest, err := p.commentAddSave(token, ca)
	if err != nil {
		return "", err
	}

	// Update the index
	ridx.Comments[ca.CommentID] = commentIndex{
		Adds: map[uint32][]byte{
			1: digest,
		},
		Del:   nil,
		Votes: make(map[string][]voteIndex),
	}

	// Save the updated index
	p.recordIndexSave(token, state, *ridx)

	log.Debugf("Comment saved to record %v comment ID %v",
		ca.Token, ca.CommentID)

	// Return new comment
	c, err := p.comment(token, *ridx, ca.CommentID)
	if err != nil {
		return "", fmt.Errorf("comment %x %v: %v", token, ca.CommentID, err)
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

// cmdEdit edits an existing comment.
func (p *commentsPlugin) cmdEdit(token []byte, payload string) (string, error) {
	// Check if comment edits are allowed
	if !p.allowEdits {
		return "", backend.PluginError{
			PluginID:     comments.PluginID,
			ErrorCode:    uint32(comments.ErrorCodeEditNotAllowed),
			ErrorContext: "comments plugin setting 'allowedits' is off",
		}
	}

	// Decode payload
	var e comments.Edit
	err := json.Unmarshal([]byte(payload), &e)
	if err != nil {
		return "", err
	}

	// Verify token
	err = tokenVerify(token, e.Token)
	if err != nil {
		return "", err
	}

	// Ensure no extra data provided if not allowed
	err = p.verifyExtraData(e.ExtraData, e.ExtraDataHint)
	if err != nil {
		return "", err
	}

	// Verify signature
	msg := strconv.FormatUint(uint64(e.State), 10) + e.Token +
		strconv.FormatUint(uint64(e.ParentID), 10) +
		strconv.FormatUint(uint64(e.CommentID), 10) +
		e.Comment + e.ExtraData + e.ExtraDataHint
	err = util.VerifySignature(e.Signature, e.PublicKey, msg)
	if err != nil {
		return "", convertSignatureError(err)
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
	state, err := p.tstore.RecordState(token)
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

	// Get record index
	ridx, err := p.recordIndex(token, state)
	if err != nil {
		return "", err
	}

	cidx, ok := ridx.Comments[e.CommentID]
	if !ok {
		// Comment not found
		return "", backend.PluginError{
			PluginID:  comments.PluginID,
			ErrorCode: uint32(comments.ErrorCodeCommentNotFound),
		}
	}

	// Get first version of the comment
	cf, err := p.commentFirstVersion(token, e.CommentID, cidx)
	if err != nil {
		return "", err
	}

	// Comment edits are allowed only during the timeframe
	// set by the editPeriod plugin setting.
	if time.Now().Unix() > cf.Timestamp+int64(p.editPeriod) {
		return "", backend.PluginError{
			PluginID:     comments.PluginID,
			ErrorCode:    uint32(comments.ErrorCodeEditNotAllowed),
			ErrorContext: "comment edits timeframe has expired",
		}
	}

	// Get the existing comment
	cs, err := p.comments(token, *ridx, []uint32{e.CommentID})
	if err != nil {
		return "", fmt.Errorf("comments %v: %v", e.CommentID, err)
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

	// Verify extra data hint. This doesn't really belong here, and should be
	// left up to the application plugin (i.e. the pi plugin) to decide. It was
	// put here to prevent application plugin from needing to pull the prior
	// version of the comment, which is expensive since it causes a tlog tree
	// retrieval.
	if e.ExtraDataHint != existing.ExtraDataHint {
		return "", backend.PluginError{
			PluginID:     comments.PluginID,
			ErrorCode:    uint32(comments.ErrorCodeEditNotAllowed),
			ErrorContext: "extra data hint edits are not allowed",
		}
	}

	// Verify comment changes
	if e.Comment == existing.Comment &&
		e.ExtraData == existing.ExtraData {
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
	digest, err := p.commentAddSave(token, ca)
	if err != nil {
		return "", err
	}

	// Update the index
	ridx.Comments[ca.CommentID].Adds[ca.Version] = digest

	// Save the updated index
	p.recordIndexSave(token, state, *ridx)

	log.Debugf("Comment edited on record %v comment ID %v",
		ca.Token, ca.CommentID)

	// Return updated comment
	c, err := p.comment(token, *ridx, e.CommentID)
	if err != nil {
		return "", fmt.Errorf("comment %x %v: %v", token, e.CommentID, err)
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

// commentFirstVersion returns the first version of the specified comment. The
// returned comment does not include the vote score.
func (p *commentsPlugin) commentFirstVersion(token []byte, commentID uint32, cidx commentIndex) (*comments.Comment, error) {
	// First version comment add digest
	digest := cidx.Adds[1]

	// Comment add record
	adds, err := p.commentAdds(token, [][]byte{digest})
	if err != nil {
		return nil, errors.Errorf("commentAdds: %v", err)
	}
	if len(adds) != 1 {
		return nil, errors.Errorf("wrong comment adds count; got %v, want %v",
			len(adds), 1)
	}

	// Convert comment add
	c := convertCommentFromCommentAdd(adds[0])

	return &c, nil
}

// verifyExtraData ensures no extra data provided if it's not allowed.
func (p *commentsPlugin) verifyExtraData(extraData, extraDataHint string) error {
	if !p.allowExtraData && (extraData != "" || extraDataHint != "") {
		return backend.PluginError{
			PluginID:  comments.PluginID,
			ErrorCode: uint32(comments.ErrorCodeExtraDataNotAllowed),
		}
	}
	return nil
}

// cmdDel deletes a comment.
func (p *commentsPlugin) cmdDel(token []byte, payload string) (string, error) {
	// Decode payload
	var d comments.Del
	err := json.Unmarshal([]byte(payload), &d)
	if err != nil {
		return "", err
	}

	// Verify token
	err = tokenVerify(token, d.Token)
	if err != nil {
		return "", err
	}

	// Verify signature
	msg := strconv.FormatUint(uint64(d.State), 10) + d.Token +
		strconv.FormatUint(uint64(d.CommentID), 10) + d.Reason
	err = util.VerifySignature(d.Signature, d.PublicKey, msg)
	if err != nil {
		return "", convertSignatureError(err)
	}

	// Verify record state
	state, err := p.tstore.RecordState(token)
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

	// Get record index
	ridx, err := p.recordIndex(token, state)
	if err != nil {
		return "", err
	}

	// Get the existing comment
	cs, err := p.comments(token, *ridx, []uint32{d.CommentID})
	if err != nil {
		return "", fmt.Errorf("comments %v: %v", d.CommentID, err)
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
	digest, err := p.commentDelSave(token, cd)
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
	p.recordIndexSave(token, state, *ridx)

	// Delete all comment versions. A comment is considered deleted
	// once the CommenDel record has been saved. If attempts to
	// actually delete the blobs fails, simply log the error and
	// continue command execution. The period fsck will clean this up
	// next time it is run.
	digests := make([][]byte, 0, len(cidx.Adds))
	for _, v := range cidx.Adds {
		digests = append(digests, v)
	}
	err = p.tstore.BlobsDel(token, digests)
	if err != nil {
		log.Errorf("comments cmdDel %x: BlobsDel %x: %v ",
			token, digests, err)
	}

	// Return updated comment
	c, err := p.comment(token, *ridx, d.CommentID)
	if err != nil {
		return "", fmt.Errorf("comment %v: %v", d.CommentID, err)
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

// cmdVote casts a upvote/downvote for a comment.
func (p *commentsPlugin) cmdVote(token []byte, payload string) (string, error) {
	// Decode payload
	var v comments.Vote
	err := json.Unmarshal([]byte(payload), &v)
	if err != nil {
		return "", err
	}

	// Verify token
	err = tokenVerify(token, v.Token)
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
	err = util.VerifySignature(v.Signature, v.PublicKey, msg)
	if err != nil {
		return "", convertSignatureError(err)
	}

	// Verify record state
	state, err := p.tstore.RecordState(token)
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

	// Get record index
	ridx, err := p.recordIndex(token, state)
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
	cs, err := p.comments(token, *ridx, []uint32{v.CommentID})
	if err != nil {
		return "", fmt.Errorf("comments %v: %v", v.CommentID, err)
	}
	c, ok := cs[v.CommentID]
	if !ok {
		return "", fmt.Errorf("comment not found %v", v.CommentID)
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
	digest, err := p.commentVoteSave(token, cv)
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
	p.recordIndexSave(token, state, *ridx)

	// Calculate the new vote scores
	downvotes, upvotes := voteScore(cidx)

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

// cmdGet retrieves a batch of specified comments. The most recent version of
// each comment is returned.
func (p *commentsPlugin) cmdGet(token []byte, payload string) (string, error) {
	// Decode payload
	var g comments.Get
	err := json.Unmarshal([]byte(payload), &g)
	if err != nil {
		return "", err
	}

	// Get record state
	state, err := p.tstore.RecordState(token)
	if err != nil {
		return "", err
	}

	// Get record index
	ridx, err := p.recordIndex(token, state)
	if err != nil {
		return "", err
	}

	// Get comments
	cs, err := p.comments(token, *ridx, g.CommentIDs)
	if err != nil {
		return "", fmt.Errorf("comments: %v", err)
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
func (p *commentsPlugin) cmdGetAll(token []byte) (string, error) {
	// Get record state
	state, err := p.tstore.RecordState(token)
	if err != nil {
		return "", err
	}

	// Compile comment IDs
	ridx, err := p.recordIndex(token, state)
	if err != nil {
		return "", err
	}
	commentIDs := make([]uint32, 0, len(ridx.Comments))
	for k := range ridx.Comments {
		commentIDs = append(commentIDs, k)
	}

	// Get comments
	c, err := p.comments(token, *ridx, commentIDs)
	if err != nil {
		return "", fmt.Errorf("comments: %v", err)
	}

	// Convert comments from a map to a slice
	cs := make([]comments.Comment, 0, len(c))
	for _, v := range c {
		cs = append(cs, v)
	}

	// Order comments by comment ID
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
func (p *commentsPlugin) cmdGetVersion(token []byte, payload string) (string, error) {
	// Decode payload
	var gv comments.GetVersion
	err := json.Unmarshal([]byte(payload), &gv)
	if err != nil {
		return "", err
	}

	// Get record state
	state, err := p.tstore.RecordState(token)
	if err != nil {
		return "", err
	}

	// Get record index
	ridx, err := p.recordIndex(token, state)
	if err != nil {
		return "", err
	}

	// Verify comment exists
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

	// Get comment add record
	adds, err := p.commentAdds(token, [][]byte{digest})
	if err != nil {
		return "", fmt.Errorf("commentAdds: %v", err)
	}
	if len(adds) != 1 {
		return "", fmt.Errorf("wrong comment adds count; got %v, want 1",
			len(adds))
	}

	// Convert to a comment
	c := convertCommentFromCommentAdd(adds[0])
	c.Downvotes, c.Upvotes = voteScore(cidx)

	// Prepare reply
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
func (p *commentsPlugin) cmdCount(token []byte) (string, error) {
	// Get record state
	state, err := p.tstore.RecordState(token)
	if err != nil {
		return "", err
	}

	// Get record index
	ridx, err := p.recordIndex(token, state)
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
func (p *commentsPlugin) cmdVotes(token []byte, payload string) (string, error) {
	// Decode payload
	var v comments.Votes
	err := json.Unmarshal([]byte(payload), &v)
	if err != nil {
		return "", err
	}

	// Get record state
	state, err := p.tstore.RecordState(token)
	if err != nil {
		return "", err
	}

	// Get record index
	ridx, err := p.recordIndex(token, state)
	if err != nil {
		return "", err
	}

	// Collect the requested page of comment vote digests
	digests := collectVoteDigestsPage(ridx.Comments, v.UserID, v.Page,
		p.votesPageSize)

	// Lookup votes
	votes, err := p.commentVotes(token, digests)
	if err != nil {
		return "", fmt.Errorf("commentVotes: %v", err)
	}

	// Sort comment votes by timestamp from newest to oldest.
	sort.SliceStable(votes, func(i, j int) bool {
		return votes[i].Timestamp > votes[j].Timestamp
	})

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

// collectVoteDigestsPage accepts a map of all comment indexes with a
// filtering criteria and it collects the requested page.
func collectVoteDigestsPage(commentIdxes map[uint32]commentIndex, userID string, page, pageSize uint32) [][]byte {
	// Default to first page if page is not provided
	if page == 0 {
		page = 1
	}

	digests := make([][]byte, 0, pageSize)
	var (
		pageFirstIndex uint32 = (page - 1) * pageSize
		pageLastIndex  uint32 = page * pageSize
		idx            uint32 = 0
		filterByUserID        = userID != ""
	)

	// Iterate over record index comments map deterministically; start from
	// comment id 1 upwards.
	for commentID := 1; commentID <= len(commentIdxes); commentID++ {
		cidx := commentIdxes[uint32(commentID)]
		switch {
		// User ID filtering criteria is applied. Collect the requested page of
		// the user's comment votes.
		case filterByUserID:
			voteIdxs, ok := cidx.Votes[userID]
			if !ok {
				// User has not cast any votes for this comment
				continue
			}
			for _, vidx := range voteIdxs {
				// Add digest if it's part of the requested page
				if isInPageRange(idx, pageFirstIndex, pageLastIndex) {
					digests = append(digests, vidx.Digest)

					// If digests page is full, then we are done
					if len(digests) == int(pageSize) {
						return digests
					}
				}
				idx++
			}

		// No filtering criteria is applied. The votes are indexed by user ID and
		// saved in a map. In order to return a page of votes in a deterministic
		// manner, the user IDs must first be sorted, then the pagination is
		// applied.
		default:
			userIDs := getSortedUserIDs(cidx.Votes)
			for _, userID := range userIDs {
				for _, vidx := range cidx.Votes[userID] {
					// Add digest if it's part of the requested page
					if isInPageRange(idx, pageFirstIndex, pageLastIndex) {
						digests = append(digests, vidx.Digest)

						// If digests page is full, then we are done
						if len(digests) == int(pageSize) {
							return digests
						}
					}
					idx++
				}
			}
		}
	}

	return digests
}

// getSortedUserIDs accepts a map of comment vote indexes indexed by user IDs,
// it collects the keys, sorts them and finally returns them as sorted slice.
func getSortedUserIDs(m map[string][]voteIndex) []string {
	userIDs := make([]string, 0, len(m))
	for userID := range m {
		userIDs = append(userIDs, userID)
	}

	// Sort keys
	sort.Strings(userIDs)

	return userIDs
}

// isInPageRange determines whether the given index is part of the given
// page range.
func isInPageRange(idx, pageFirstIndex, pageLastIndex uint32) bool {
	return idx >= pageFirstIndex && idx <= pageLastIndex
}

// cmdTimestamps retrieves the timestamps for the comments of a record.
func (p *commentsPlugin) cmdTimestamps(token []byte, payload string) (string, error) {
	// Decode payload
	var t comments.Timestamps
	err := json.Unmarshal([]byte(payload), &t)
	if err != nil {
		return "", err
	}

	// Get timestamps
	ctr, err := p.commentTimestamps(token, t.CommentIDs, t.IncludeVotes)
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

// tokenDecode decodes a tstore token. It only accepts full length tokens.
func tokenDecode(token string) ([]byte, error) {
	return util.TokenDecode(util.TokenTypeTstore, token)
}

// tokenVerify verifies that a token that is part of a plugin command payload
// is valid. This is applicable when a plugin command payload contains a
// signature that includes the record token. The token included in payload must
// be a valid, full length record token and it must match the token that was
// passed into the politeiad API for this plugin command, i.e. the token for
// the record that this plugin command is being executed on.
func tokenVerify(cmdToken []byte, payloadToken string) error {
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
			ErrorContext: fmt.Sprintf("payload token does not match "+
				"command token: got %x, want %x", pt, cmdToken),
		}
	}
	return nil
}

// commentVersionLatest returns the latest comment version.
func commentVersionLatest(cidx commentIndex) uint32 {
	var maxVersion uint32
	for version := range cidx.Adds {
		if version > maxVersion {
			maxVersion = version
		}
	}
	return maxVersion
}

// commentExists returns whether the provided comment ID exists.
func commentExists(ridx recordIndex, commentID uint32) bool {
	_, ok := ridx.Comments[commentID]
	return ok
}

// commentIDLatest returns the latest comment ID.
func commentIDLatest(idx recordIndex) uint32 {
	var maxID uint32
	for id := range idx.Comments {
		if id > maxID {
			maxID = id
		}
	}
	return maxID
}

func convertCommentFromCommentAdd(ca comments.CommentAdd) comments.Comment {
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

func convertCommentFromCommentDel(cd comments.CommentDel) comments.Comment {
	// Score needs to be filled in separately
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

func convertBlobEntryFromCommentAdd(c comments.CommentAdd) (*store.BlobEntry, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	hint, err := json.Marshal(
		store.DataDescriptor{
			Type:       store.DataTypeStructure,
			Descriptor: dataDescriptorCommentAdd,
		})
	if err != nil {
		return nil, err
	}
	be := store.NewBlobEntry(hint, data)
	return &be, nil
}

func convertBlobEntryFromCommentDel(c comments.CommentDel) (*store.BlobEntry, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	hint, err := json.Marshal(
		store.DataDescriptor{
			Type:       store.DataTypeStructure,
			Descriptor: dataDescriptorCommentDel,
		})
	if err != nil {
		return nil, err
	}
	be := store.NewBlobEntry(hint, data)
	return &be, nil
}

func convertBlobEntryFromCommentVote(c comments.CommentVote) (*store.BlobEntry, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	hint, err := json.Marshal(
		store.DataDescriptor{
			Type:       store.DataTypeStructure,
			Descriptor: dataDescriptorCommentVote,
		})
	if err != nil {
		return nil, err
	}
	be := store.NewBlobEntry(hint, data)
	return &be, nil
}

func convertCommentAddFromBlobEntry(be store.BlobEntry) (*comments.CommentAdd, error) {
	// Decode and validate data hint
	b, err := base64.StdEncoding.DecodeString(be.DataHint)
	if err != nil {
		return nil, fmt.Errorf("decode DataHint: %v", err)
	}
	var dd store.DataDescriptor
	err = json.Unmarshal(b, &dd)
	if err != nil {
		return nil, fmt.Errorf("unmarshal DataHint: %v", err)
	}
	if dd.Descriptor != dataDescriptorCommentAdd {
		return nil, fmt.Errorf("unexpected data descriptor: got %v, want %v",
			dd.Descriptor, dataDescriptorCommentAdd)
	}

	// Decode data
	b, err = base64.StdEncoding.DecodeString(be.Data)
	if err != nil {
		return nil, fmt.Errorf("decode Data: %v", err)
	}
	digest, err := hex.DecodeString(be.Digest)
	if err != nil {
		return nil, fmt.Errorf("decode digest: %v", err)
	}
	if !bytes.Equal(util.Digest(b), digest) {
		return nil, fmt.Errorf("data is not coherent; got %x, want %x",
			util.Digest(b), digest)
	}
	var c comments.CommentAdd
	err = json.Unmarshal(b, &c)
	if err != nil {
		return nil, fmt.Errorf("unmarshal CommentAdd: %v", err)
	}

	return &c, nil
}

func convertCommentDelFromBlobEntry(be store.BlobEntry) (*comments.CommentDel, error) {
	// Decode and validate data hint
	b, err := base64.StdEncoding.DecodeString(be.DataHint)
	if err != nil {
		return nil, fmt.Errorf("decode DataHint: %v", err)
	}
	var dd store.DataDescriptor
	err = json.Unmarshal(b, &dd)
	if err != nil {
		return nil, fmt.Errorf("unmarshal DataHint: %v", err)
	}
	if dd.Descriptor != dataDescriptorCommentDel {
		return nil, fmt.Errorf("unexpected data descriptor: got %v, want %v",
			dd.Descriptor, dataDescriptorCommentDel)
	}

	// Decode data
	b, err = base64.StdEncoding.DecodeString(be.Data)
	if err != nil {
		return nil, fmt.Errorf("decode Data: %v", err)
	}
	digest, err := hex.DecodeString(be.Digest)
	if err != nil {
		return nil, fmt.Errorf("decode digest: %v", err)
	}
	if !bytes.Equal(util.Digest(b), digest) {
		return nil, fmt.Errorf("data is not coherent; got %x, want %x",
			util.Digest(b), digest)
	}
	var c comments.CommentDel
	err = json.Unmarshal(b, &c)
	if err != nil {
		return nil, fmt.Errorf("unmarshal CommentDel: %v", err)
	}

	return &c, nil
}

func convertCommentVoteFromBlobEntry(be store.BlobEntry) (*comments.CommentVote, error) {
	// Decode and validate data hint
	b, err := base64.StdEncoding.DecodeString(be.DataHint)
	if err != nil {
		return nil, fmt.Errorf("decode DataHint: %v", err)
	}
	var dd store.DataDescriptor
	err = json.Unmarshal(b, &dd)
	if err != nil {
		return nil, fmt.Errorf("unmarshal DataHint: %v", err)
	}
	if dd.Descriptor != dataDescriptorCommentVote {
		return nil, fmt.Errorf("unexpected data descriptor: got %v, want %v",
			dd.Descriptor, dataDescriptorCommentVote)
	}

	// Decode data
	b, err = base64.StdEncoding.DecodeString(be.Data)
	if err != nil {
		return nil, fmt.Errorf("decode Data: %v", err)
	}
	digest, err := hex.DecodeString(be.Digest)
	if err != nil {
		return nil, fmt.Errorf("decode digest: %v", err)
	}
	if !bytes.Equal(util.Digest(b), digest) {
		return nil, fmt.Errorf("data is not coherent; got %x, want %x",
			util.Digest(b), digest)
	}
	var cv comments.CommentVote
	err = json.Unmarshal(b, &cv)
	if err != nil {
		return nil, fmt.Errorf("unmarshal CommentVote: %v", err)
	}

	return &cv, nil
}
