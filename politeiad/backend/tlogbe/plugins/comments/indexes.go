// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package comments

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/decred/politeia/politeiad/plugins/comments"
	"github.com/decred/politeia/util"
)

const (
	// filenameRecordIndex is the file name of the record index that
	// is saved to the comments plugin data dir.
	filenameRecordIndex = "{tokenPrefix}-index.json"
)

// voteIndex contains the comment vote and the digest of the vote record.
type voteIndex struct {
	Vote   comments.VoteT `json:"vote"`
	Digest []byte         `json:"digest"`
}

// commentIndex contains the digests of all comment add, dels, and votes for a
// comment ID.
type commentIndex struct {
	Adds map[uint32][]byte `json:"adds"` // [version]digest
	Del  []byte            `json:"del"`

	// Votes contains the vote history for each uuid that voted on the
	// comment. This data is cached because the effect of a new vote
	// on a comment depends on the previous vote from that uuid.
	// Example, a user upvotes a comment that they have already
	// upvoted, the resulting vote score is 0 due to the second upvote
	// removing the original upvote.
	Votes map[string][]voteIndex `json:"votes"` // [uuid]votes
}

// recordIndex contains the indexes for all comments made on a record.
type recordIndex struct {
	Comments map[uint32]commentIndex `json:"comments"` // [commentID]comment
}

// recordIndexPath accepts full length token or token prefixes, but always uses
// prefix when generating the comments index path string.
func (p *commentsPlugin) recordIndexPath(token []byte) (string, error) {
	tp := util.TokenPrefix(token)
	fn := strings.Replace(filenameRecordIndex, "{tokenPrefix}", tp, 1)
	return filepath.Join(p.dataDir, fn), nil
}

// recordIndexLocked returns the cached recordIndex for the provided record.
// If a cached recordIndex does not exist, a new one will be returned.
//
// This function must be called WITH the lock held.
func (p *commentsPlugin) recordIndexLocked(token []byte) (*recordIndex, error) {
	fp, err := p.recordIndexPath(token)
	if err != nil {
		return nil, err
	}
	b, err := ioutil.ReadFile(fp)
	if err != nil {
		var e *os.PathError
		if errors.As(err, &e) && !os.IsExist(err) {
			// File does't exist. Return a new recordIndex instead.
			return &recordIndex{
				Comments: make(map[uint32]commentIndex),
			}, nil
		}
		return nil, err
	}

	var ridx recordIndex
	err = json.Unmarshal(b, &ridx)
	if err != nil {
		return nil, err
	}

	return &ridx, nil
}

// recordIndex returns the cached recordIndex for the provided record. If a
// cached recordIndex does not exist, a new one will be returned.
//
// This function must be called WITHOUT the lock held.
func (p *commentsPlugin) recordIndex(token []byte) (*recordIndex, error) {
	m := p.mutex(token)
	m.Lock()
	defer m.Unlock()

	return p.recordIndexLocked(token)
}

// recordIndexSaveLocked saves the provided recordIndex to the comments
// plugin data dir.
//
// This function must be called WITH the lock held.
func (p *commentsPlugin) recordIndexSaveLocked(token []byte, ridx recordIndex) error {
	b, err := json.Marshal(ridx)
	if err != nil {
		return err
	}
	fp, err := p.recordIndexPath(token)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(fp, b, 0664)
	if err != nil {
		return err
	}
	return nil
}
