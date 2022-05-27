// Copyright (c) 2021-2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package comments

import (
	"encoding/hex"
)

// fsckRecordIndex verifies the coherency of a record index. The record index
// is rebuilt from scratch if any errors are found. The returned bool will be
// true if the record index was rebuilt.
func (p *commentsPlugin) fsckRecordIndex(token []byte) (bool, error) {
	log.Debugf("%x fsck record index", token)

	// Get the digests for all of the comment add, del, and
	// vote entries for the record. The digests are the keys
	// that are used to pull the full entries from tstore.
	addD, err := p.tstore.DigestsByDataDesc(token,
		[]string{dataDescriptorCommentAdd})
	if err != nil {
		return false, err
	}
	delD, err := p.tstore.DigestsByDataDesc(token,
		[]string{dataDescriptorCommentDel})
	if err != nil {
		return false, err
	}
	voteD, err := p.tstore.DigestsByDataDesc(token,
		[]string{dataDescriptorCommentVote})
	if err != nil {
		return false, err
	}

	// Get the cached record index
	state, err := p.tstore.RecordState(token)
	if err != nil {
		return false, err
	}
	rindex, err := p.recordIndex(token, state)
	if err != nil {
		return false, err
	}

	// Verify the coherency of the record index
	if recordIndexIsCoherent(*rindex, addD, delD, voteD) {
		log.Debugf("%x indexes are coherent", token)

		return false, nil
	}

	// The record index is not coherent. Rebuilt it from scratch.
	log.Infof("%x rebuilding indexes", token)

	err = p.rebuildRecordIndex(token, addD, delD, voteD)
	if err != nil {
		return false, err
	}

	return true, nil
}

// rebuildRecordIndex rebuilds a recordIndex and saves it to the cache. If
// a recordIndex already exists in the cache for this token, it will be
// overwritten by this function.
func (p *commentsPlugin) rebuildRecordIndex(token []byte, addDigests, delDigests, voteDigests [][]byte) error {
	// indexes contains a commentIndex for each comment
	// that has been made on the record.
	//
	// A commentIndex contains pointers to the full comment
	// add, del, and vote records for a comment.
	indexes := make(map[uint32]commentIndex)

	// Add the adds to the comment indexes
	adds, err := p.commentAdds(token, addDigests)
	if err != nil {
		return err
	}
	for i, a := range adds {
		index, ok := indexes[a.CommentID]
		if !ok {
			index = newCommentIndex()
		}
		index.Adds[a.Version] = addDigests[i]
		indexes[a.CommentID] = index
	}

	// Add the dels to the comment indexes
	dels, err := p.commentDels(token, delDigests)
	if err != nil {
		return err
	}
	for i, d := range dels {
		// A commentIndex should always exist. The
		// code below will panic if one doesn't.
		cindex := indexes[d.CommentID]
		cindex.Del = delDigests[i]
		indexes[d.CommentID] = cindex
	}

	// Add the votes to the comment indexes
	votes, err := p.commentVotes(token, voteDigests)
	if err != nil {
		return err
	}
	for i, v := range votes {
		// A commentIndex should always exist. The
		// code below will panic if one doesn't.
		cindex := indexes[v.CommentID]

		voteIndexes, ok := cindex.Votes[v.UserID]
		if !ok {
			voteIndexes = make([]voteIndex, 0, 1024)
		}
		voteIndexes = append(voteIndexes, voteIndex{
			Vote:   v.Vote,
			Digest: voteDigests[i],
		})

		cindex.Votes[v.UserID] = voteIndexes
		indexes[v.CommentID] = cindex
	}

	// Save the record index to the cache. This
	// will overwrite any existing record index.
	state, err := p.tstore.RecordState(token)
	if err != nil {
		return err
	}
	rindex := recordIndex{
		Comments: indexes,
	}
	p.recordIndexSave(token, state, rindex)

	return nil
}

// recordIndexIsCoherent returns whether the provided recordIndex contains all
// of the provided comment add, del, and vote digests. If any of the provided
// digests are not found then the recordIndex is considered incoherent and this
// function will return false.
func recordIndexIsCoherent(rindex recordIndex, addDigests, delDigests, voteDigests [][]byte) bool {
	// digests contains all of the digests found in the
	// record index. This includes the digests for all
	// comment add, del, and vote entries.
	digests := make(map[string]struct{}, 1024)

	// Aggregate all of the digests that are included in the
	// record index.
	for _, cindex := range rindex.Comments {
		for _, addDigest := range cindex.Adds {
			digests[hex.EncodeToString(addDigest)] = struct{}{}
		}
		for _, voteIndexes := range cindex.Votes {
			for _, voteIndex := range voteIndexes {
				digests[hex.EncodeToString(voteIndex.Digest)] = struct{}{}
			}
		}
		if len(cindex.Del) > 0 {
			digests[hex.EncodeToString(cindex.Del)] = struct{}{}
		}
	}

	// Verify that each of the provided add, del, and vote digests
	// have a corresponding entry in the record index. If a match
	// is not found for any of the provided digests then the record
	// index is not coherent.
	for _, d := range addDigests {
		_, ok := digests[hex.EncodeToString(d)]
		if !ok {
			return false
		}
	}
	for _, d := range delDigests {
		_, ok := digests[hex.EncodeToString(d)]
		if !ok {
			return false
		}
	}
	for _, d := range voteDigests {
		_, ok := digests[hex.EncodeToString(d)]
		if !ok {
			return false
		}
	}

	return true
}
