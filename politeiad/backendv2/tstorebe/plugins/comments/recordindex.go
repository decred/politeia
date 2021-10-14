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
	fnRecordIndexUnvetted = "{shorttoken}-index-unvetted.json"
	fnRecordIndexVetted   = "{shorttoken}-index-vetted.json"
)

// voteIndex contains the comment vote and the digest of the vote record.
// Caching the vote allows us to tally the votes for a comment without needing
// to pull the vote blobs from the backend. The digest allows us to retrieve
// the vote blob if we need to.
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

// recordIndexPath returns the file path for a cached record index. It accepts
// both the full length token or the short token, but the short token is always
// used in the file path string.
func (p *commentsPlugin) recordIndexPath(token []byte, s backend.StateT) (string, error) {
	var fn string
	switch s {
	case backend.StateUnvetted:
		fn = fnRecordIndexUnvetted
	case backend.StateVetted:
		fn = fnRecordIndexVetted
	default:
		return "", fmt.Errorf("invalid state")
	}

	t, err := util.ShortTokenEncode(token)
	if err != nil {
		return "", err
	}
	fn = strings.Replace(fn, "{shorttoken}", t, 1)
	return filepath.Join(p.dataDir, fn), nil
}

// recordIndex returns the cached recordIndex for the provided record. If a
// cached recordIndex does not exist, a new one will be returned.
//
// This function must be called WITHOUT the read lock held.
func (p *commentsPlugin) recordIndex(token []byte, s backend.StateT) (*recordIndex, error) {
	fp, err := p.recordIndexPath(token, s)
	if err != nil {
		return nil, err
	}

	p.RLock()
	defer p.RUnlock()

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

// _recordIndexSave saves the provided recordIndex to the comments plugin data dir.
//
// This function must be called WITHOUT the read/write lock held.
func (p *commentsPlugin) _recordIndexSave(token []byte, s backend.StateT, ridx recordIndex) error {
	b, err := json.Marshal(ridx)
	if err != nil {
		return err
	}
	fp, err := p.recordIndexPath(token, s)
	if err != nil {
		return err
	}

	p.Lock()
	defer p.Unlock()

	err = ioutil.WriteFile(fp, b, 0664)
	if err != nil {
		return err
	}
	return nil
}

// recordIndexSave is a wrapper around the _recordIndexSave method that allows
// us to decide how update errors should be handled. For now we just panic.
// If an error occurs the cache is no longer coherent and the only way to fix
// it is to rebuild it.
func (p *commentsPlugin) recordIndexSave(token []byte, s backend.StateT, ridx recordIndex) {
	err := p._recordIndexSave(token, s, ridx)
	if err != nil {
		panic(err)
	}
}

// recordIndexRemove removes the record index cache from the path of the
// provided record token and state.
func (p *commentsPlugin) recordIndexRemove(token []byte, s backend.StateT) error {
	p.Lock()
	defer p.Unlock()

	path, err := p.recordIndexPath(token, s)
	if err != nil {
		return err
	}

	return os.RemoveAll(path)
}
