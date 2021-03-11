// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package comments

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/plugins/comments"
	"github.com/decred/politeia/util"
)

const (
	// Filenames of the record indexes that are saved to the comments
	// plugin data dir.
	fnRecordIndexUnvetted = "{tokenPrefix}-index-unvetted.json"
	fnRecordIndexVetted   = "{tokenPrefix}-index-vetted.json"
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
func (p *commentsPlugin) recordIndexPath(token []byte, s backend.StateT) string {
	var fn string
	switch s {
	case backend.StateUnvetted:
		fn = fnRecordIndexUnvetted
	case backend.StateVetted:
		fn = fnRecordIndexVetted
	default:
		e := fmt.Sprintf("invalid state %x %v", token, s)
		panic(e)
	}

	tp := util.TokenPrefix(token)
	fn = strings.Replace(fn, "{tokenPrefix}", tp, 1)
	return filepath.Join(p.dataDir, fn)
}

// recordIndex returns the cached recordIndex for the provided record. If a
// cached recordIndex does not exist, a new one will be returned.
//
// This function must be called WITHOUT the read lock held.
func (p *commentsPlugin) recordIndex(token []byte, s backend.StateT) (*recordIndex, error) {
	p.RLock()
	defer p.RUnlock()

	fp := p.recordIndexPath(token, s)
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

// recordIndexSave saves the provided recordIndex to the comments plugin data
// dir.
//
// This function must be called WITHOUT the read/write lock held.
func (p *commentsPlugin) recordIndexSave(token []byte, s backend.StateT, ridx recordIndex) error {
	p.Lock()
	defer p.Unlock()

	b, err := json.Marshal(ridx)
	if err != nil {
		return err
	}
	fp := p.recordIndexPath(token, s)
	err = ioutil.WriteFile(fp, b, 0664)
	if err != nil {
		return err
	}
	return nil
}
