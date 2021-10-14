// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package comments

import (
	"encoding/hex"

	"github.com/pkg/errors"
)

// digests is used to hold comment digests retrieved from tstore to avoid
// having to retrieve them again when rebuilding the cache, if needed.
type digests struct {
	adds  [][]byte
	dels  [][]byte
	votes [][]byte
}

// verifyRecordIndex verifies the coherency of the record index cache.
func (p *commentsPlugin) verifyRecordIndex(token []byte) (bool, *digests, error) {
	// Get comment add digests for this record token.
	digestsAdd, err := p.tstore.DigestsByDataDesc(token,
		[]string{dataDescriptorCommentAdd})
	if err != nil {
		return false, nil, err
	}
	// Get comment del digests for this record token.
	digestsDel, err := p.tstore.DigestsByDataDesc(token,
		[]string{dataDescriptorCommentDel})
	if err != nil {
		return false, nil, err
	}
	// Get comment vote digests for this record token.
	digestsVote, err := p.tstore.DigestsByDataDesc(token,
		[]string{dataDescriptorCommentVote})
	if err != nil {
		return false, nil, err
	}

	// Create map to verify digests.
	addMap := make(map[string][]byte, len(digestsAdd))
	for _, d := range digestsAdd {
		addMap[hex.EncodeToString(d)] = d
	}
	delMap := make(map[string][]byte, len(digestsDel))
	for _, d := range digestsDel {
		delMap[hex.EncodeToString(d)] = d
	}
	voteMap := make(map[string][]byte, len(digestsVote))
	for _, d := range digestsVote {
		voteMap[hex.EncodeToString(d)] = d
	}

	// Get cached record index.
	state, err := p.tstore.RecordState(token)
	if err != nil {
		return false, nil, err
	}
	cached, err := p.recordIndex(token, state)
	if err != nil {
		return false, nil, err
	}

	// Verify that digests contained in the record index cache are valid.
	// Also, verify that all valid digests are contained in the record
	// index.
	var (
		isCoherent   = true
		addsCounter  = 0
		delsCounter  = 0
		votesCounter = 0
	)
	for _, commentIndex := range cached.Comments {
		// Verify comment add digests.
		for _, add := range commentIndex.Adds {
			_, ok := addMap[hex.EncodeToString(add)]
			if !ok {
				isCoherent = false
				break
			}
			addsCounter++
		}
		// Verify comment del digest, if it is set on the index.
		if len(commentIndex.Del) != 0 {
			digest := hex.EncodeToString(commentIndex.Del)
			_, ok := delMap[digest]
			if !ok {
				isCoherent = false
				break
			}
			_, ok = addMap[digest]
			if ok {
				// This should not happen since the corresponding comment
				// add from a del entry should be deleted from the db.
				return false, nil, errors.Errorf("digest %v contained as a"+
					"comment del and comment add", digest)
			}
			delsCounter++
		}
		// Verify comment vote digests.
		for _, votes := range commentIndex.Votes {
			for _, vote := range votes {
				_, ok := voteMap[hex.EncodeToString(vote.Digest)]
				if !ok {
					isCoherent = false
					break
				}
				votesCounter++
			}
		}
	}
	// Verify that all valid digests are contained on the record index.
	if addsCounter != len(digestsAdd) {
		isCoherent = false
	}
	if delsCounter != len(digestsDel) {
		isCoherent = false
	}
	if votesCounter != len(digestsVote) {
		isCoherent = false
	}

	return isCoherent, &digests{
		adds:  digestsAdd,
		dels:  digestsDel,
		votes: digestsVote,
	}, nil
}

// rebuildRecordIndex rebuilds a record index cache when it is not coherent.
func (p *commentsPlugin) rebuildRecordIndex(token []byte, ds digests) error {
	// Initialize map for the comment indexes.
	index := make(map[uint32]*commentIndex)

	// Get comment add for the add digests.
	adds, err := p.commentAdds(token, ds.adds)
	if err != nil {
		return err
	}
	// Initialize maps on the comment index for this record. Since all
	// votes need a corresponding add to be valid, it's ok to initialize
	// them by ranging the comment adds.
	for _, c := range adds {
		id := c.CommentID
		index[id] = &commentIndex{
			Adds:  make(map[uint32][]byte),
			Votes: make(map[string][]voteIndex),
		}
	}
	// Build the comment adds entry for the comment index.
	for k, c := range adds {
		id := c.CommentID
		version := c.Version
		index[id].Adds[version] = ds.adds[k]
	}

	// Get comment dels for the del digest.
	dels, err := p.commentDels(token, ds.dels)
	if err != nil {
		return err
	}
	// Build the del entry for the comment index.
	for k, c := range dels {
		id := c.CommentID
		index[id].Del = ds.dels[k]
	}

	// Get comment votes for the vote digests
	votes, err := p.commentVotes(token, ds.votes)
	if err != nil {
		return err
	}
	// Build the votes entry for the comment index.
	for k, v := range votes {
		userID := v.UserID
		commentID := v.CommentID
		index[commentID].Votes[userID] = append(
			index[commentID].Votes[userID], voteIndex{
				Vote:   v.Vote,
				Digest: ds.votes[k],
			})
	}

	// Get record state.
	state, err := p.tstore.RecordState(token)
	if err != nil {
		return err
	}

	// Remove current record index before saving new one.
	err = p.recordIndexRemove(token, state)
	if err != nil {
		return err
	}

	// Build record index with the comment indexes previously built.
	var ri recordIndex
	ri.Comments = make(map[uint32]commentIndex)
	for id, indx := range index {
		ri.Comments[id] = *indx
	}

	// Save record index cache.
	p.recordIndexSave(token, state, ri)

	return nil
}
