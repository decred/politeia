// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package comments

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/plugins/comments"
	"github.com/decred/politeia/util"
	pkgerrors "github.com/pkg/errors"
)

// recordIndex contains a commentIndex for all comments made on a record. The
// record index is saved to the tstore cache.
type recordIndex struct {
	Token    string                  `json:"token"`    // Hex encoded
	Comments map[uint32]commentIndex `json:"comments"` // [commentID]comment
}

// newRecordIndex returns a new recordIndex.
func newRecordIndex(token []byte) recordIndex {
	return recordIndex{
		Token:    hex.EncodeToString(token),
		Comments: make(map[uint32]commentIndex, 256),
	}
}

// commentIDLatest returns the latest comment ID.
func (r *recordIndex) commentIDLatest() uint32 {
	var maxID uint32
	for id := range idx.Comments {
		if id > maxID {
			maxID = id
		}
	}
	return maxID
}

// commentExists returns whether the provided comment ID exists.
func (r *recordIndex) commentExists(commentID uint32) bool {
	_, ok := r.Comments[commentID]
	return ok
}

// comment returns the latest version of a comment.
func (r *recordIndex) comment(commentID uint32) (*comments.Comment, error) {
	cs, err := r.comments([]uint32{commentID})
	if err != nil {
		return nil, err
	}
	c, ok := cs[commentID]
	if !ok {
		return nil, pkgerrors.Errorf("comment not found %v %v",
			r.Token, commentID)
	}
	return &c, nil
}

// comments returns the most recent version of the specified comments. Deleted
// comments are returned with limited data. If a comment is not found the
// comment ID is excluded from the returned map. An error will not be returned.
// It is the responsibility of the caller to ensure a comment is returned for
// each of the provided comment IDs.
func (r *recordIndex) comments(commentIDs []uint32) (map[uint32]comments.Comment, error) {
	// Aggregate the digests for all records that need to be
	// looked up. If a comment has been deleted then the only
	// record that will still exist is the comment del record.
	// If the comment has not been deleted then the comment add
	// record will need to be retrieved for the latest version
	// of the comment.
	var (
		addDigests = make([][]byte, 0, len(commentIDs))
		delDigests = make([][]byte, 0, len(commentIDs))
	)
	for _, cid := range commentIDs {
		// Get the comment index
		cidx, ok := r.Comments[cid]
		if !ok {
			// Comment does not exist
			continue
		}

		// Get the digest of the comment record that needs to be
		// retreived. If a comment has not been deleted we get the
		// most recent CommentAdd record. If a comment has been
		// deleted we get the CommentDel record.
		add, del := cidx.digests()
		switch {
		case del != nil:
			delDigests = append(delDigests, del)
		case add != nil:
			addDigests = append(addDigests, add)
		default:
			return nil, pkgerrors.Errorf("incoherent comment index %v", cid)
		}
	}

	// Get CommentAdd records
	adds, err := commentAdds(r.Token, addDigests)
	if err != nil {
		return nil, err
	}

	// Get CommentDel records
	dels, err := commentDels(r.Token, delDigests)
	if err != nil {
		return nil, err
	}

	// Prepare reply
	cs := make(map[uint32]comments.Comment, len(commentIDs))
	for _, v := range adds {
		// Setup comment
		c := commentAddConvert(v)

		// Populate the vote score
		cidx, ok := ridx.Comments[c.CommentID]
		if !ok {
			return nil, pkgerrors.Errorf("comment index not found %v",
				c.CommentID)
		}
		c.Downvotes, c.Upvotes = cidx.voteScore()

		// Save comment
		cs[v.CommentID] = c
	}
	for _, v := range dels {
		cs[v.CommentID] = commentDelConvert(v)
	}

	return cs, nil
}

// commentIndex contains the digests of all CommentAdd, CommentDel, and
// CommentVote records for a comment. A del digest will only exist if the
// comment has been deleted. If a del digest exists it means that all of the
// CommentAdd records have been deleted from tstore.
type commentIndex struct {
	Adds map[uint32][]byte `json:"adds"` // [version]digest
	Del  []byte            `json:"del,omitempty"`

	// Votes contains the vote history for each uuid that voted on the
	// comment. This data is cached because the effect of a new vote
	// on a comment depends on the previous vote from that uuid.
	// Example, a user upvotes a comment that they have already
	// upvoted, the resulting vote score is 0 due to the second upvote
	// removing the original upvote.
	Votes map[string][]voteIndex `json:"votes"` // [uuid]votes
}

// newCommentIndex returns a commentIndex for a new comment.
func newCommentIndex(digest []byte) commentIndex {
	return commentIndex{
		Adds: map[uint32][]byte{
			1: digest,
		},
		Del:   nil,
		Votes: make(map[string][]voteIndex),
	}
}

// version returns the current version for the comment.
func (c *commentIndex) version() uint32 {
	var maxVersion uint32
	for version := range c.Adds {
		if version > maxVersion {
			maxVersion = version
		}
	}
	return maxVersion
}

// digests returns the digest of the most recent CommentAdd and the digest of
// the CommentDel if one exists.
func (c *commentIndex) digests() ([]byte, []byte) {
	return c.Adds[c.version()], c.Del
}

// voteScore returns the total number of downvotes and upvotes, respectively,
// for a comment.
func (c *commentsIndex) voteScore() (uint64, uint64) {
	// Find the vote score by replaying all existing votes from all
	// users. The net effect of a new vote on a comment score depends
	// on the previous vote from that uuid. Example, a user upvotes a
	// comment that they have already upvoted, the resulting vote score
	// is 0 due to the second upvote removing the original upvote.
	var upvotes uint64
	var downvotes uint64
	for _, votes := range c.Votes {
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
			panic(fmt.Sprintf("unexpected vote score %v", score))
		}
	}

	return downvotes, upvotes
}

// voteIndex contains the comment vote and the digest of the vote record.
// Caching the vote allows us to tally the votes for a comment without needing
// to pull the vote blobs from tstore. The digest allows us to retrieve the
// vote blob if we need to.
type voteIndex struct {
	Vote   comments.VoteT `json:"vote"`
	Digest []byte         `json:"digest"`
}

const (
	// Keys for the record indexes that are saved to the tstore cache.
	keyRecordIndexUnvetted = "{shorttoken}-index-unvetted.json"
	keyRecordIndexVetted   = "{shorttoken}-index-vetted.json"
)

// recordIndexKey returns the key-value store key for a cached record index. It
// accepts both the full length token or the short token, but the short token
// is always used in the file path string.
func recordIndexKey(token []byte, s backend.StateT) (string, error) {
	var key string
	switch s {
	case backend.StateUnvetted:
		key = keyRecordIndexUnvetted
	case backend.StateVetted:
		key = keyRecordIndexVetted
	default:
		return "", pkgerrors.Errorf("invalid state %v", s)
	}

	t, err := util.ShortTokenEncode(token)
	if err != nil {
		return "", err
	}

	return strings.Replace(key, "{shorttoken}", t, 1), nil
}

// recordIndexSave saves the provided recordIndex to the tstore cache.
func recordIndexSave(tstore plugins.TstoreClient, token []byte, s backend.StateT, ridx recordIndex) error {
	b, err := json.Marshal(ridx)
	if err != nil {
		return err
	}
	key, err := recordIndexKey(token, s)
	if err != nil {
		return err
	}
	return tstore.CacheSave(map[string][]byte{key: b})
}

// recordIndex returns the cached recordIndex for the provided record. If a
// cached recordIndex does not exist, a new one will be returned.
func (p *commentsPlugin) recordIndex(tstore plugins.TstoreClient, token []byte, s backend.StateT) (*recordIndex, error) {
	key, err := recordIndexKey(token, s)
	if err != nil {
		return nil, err
	}

	blobs, err := tstore.CacheGet([]string{key})
	if err != nil {
		return nil, err
	}
	b, ok := blobs[key]
	if !ok {
		// Cached recordIndex does't exist. Return a new one.
		return newRecordIndex(token), nil
	}

	var ridx recordIndex
	err = json.Unmarshal(b, &ridx)
	if err != nil {
		return nil, err
	}

	return &ridx, nil
}
