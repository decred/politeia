// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package comments

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"

	"github.com/decred/politeia/plugins/comments"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe"
	"github.com/decred/politeia/politeiad/backend/tlogbe/plugin"
	"github.com/decred/politeia/politeiad/backend/tlogbe/store"
	"github.com/decred/politeia/politeiad/backend/tlogbe/store/filesystem"
)

const (
	commentsDirname = "comments"

	// Data descriptors
	dataDescriptorRecordComments = "recordcomments"
	dataDescriptorComment        = "comment"

	// Key-value store key prefixes
	keyPrefixRecordComments = "record"
	keyPrefixComment        = "comment"
)

var (
	_ plugin.Plugin = (*commentsPlugin)(nil)
)

// TODO unvetted comments should be encrypted
// TODO journal should be encrypted

type commentsPlugin struct {
	sync.RWMutex
	id            *identity.FullIdentity
	encyrptionKey *tlogbe.EncryptionKey
	tlog          *tlogbe.TrillianClient
	backend       backend.Backend
	store         store.Blob

	// Mutexes contains a mutex for each record. The mutexes are lazy
	// loaded.
	mutexes map[string]*sync.RWMutex // [token]mutex
}

type commentIndex struct {
	CommentID uint32            `json:"commentid"`
	Versions  map[uint32][]byte `json:"versions"` // [version]merkleLeafHash
}

// recordComments contains the comment index for all comments made on a record.
type recordComments struct {
	Token string `json:"token"`

	// LastID contains the last comment ID that has been assigned for
	// this record. Comment IDs are sequential starting with 1. The
	// state of the record, unvetted or vetted, does not impact the
	// comment ID that is assinged.
	LastID uint32 `json:"lastid"`

	// Unvetted contains comments that were made on the record when it
	// was in an unvetted state. Unvetted comments are encrypted before
	// being saved to the key-value store. They remain encrypted for
	// the duration of their lifetime, even after the record itself
	// becomes vetted.
	//
	// map[commentID]commentIndex
	Unvetted map[uint32]commentIndex `json:"unvetted"`

	// Vetted contains comments that were made on a vetted record.
	// Vetted comments are stored in the key-value store unencrypted.
	//
	// map[commentID]commentIndex
	Vetted map[uint32]commentIndex `json:"vetted"`
}

func keyRecordComments(token string) string {
	return keyPrefixRecordComments + token
}

// keyComment returns the key for a comment in the key-value store.
func keyComment(token string, merkleLeafHash []byte) string {
	return keyPrefixComment + hex.EncodeToString(merkleLeafHash)
}

/*
func convertBlobEntryFromRecordComments(rc recordComments) (*blobEntry, error) {
	data, err := json.Marshal(rc)
	if err != nil {
		return nil, err
	}
	hint, err := json.Marshal(
		dataDescriptor{
			Type:       dataTypeStructure,
			Descriptor: dataDescriptorRecordComments,
		})
	if err != nil {
		return nil, err
	}
	be := blobEntryNew(hint, data)
	return &be, nil
}

// mutex returns the mutex for the provided token. This function assumes that
// the provided token has already been validated and corresponds to a record in
// the Backend.
func (p *commentsPlugin) mutex(token string) (*sync.RWMutex, error) {
	p.Lock()
	defer p.Unlock()

	m, ok := p.mutexes[token]
	if !ok {
		// Mutexes is lazy loaded
		m = &sync.RWMutex{}
		p.mutexes[token] = m
	}

	return m, nil
}

// recordExists returns whether the provided record exists in the backend.
// This function does not differentiate between unvetted and vetted records.
func (p *commentsPlugin) recordExists(token string) bool {
	t, err := hex.DecodeString(token)
	if err != nil {
		return false
	}
	if p.backend.UnvettedExists(t) {
		return true
	}
	if p.backend.VettedExists(t) {
		return true
	}
	return false
}

/*
func (p *commentsPlugin) recordComments(token string) (*recordComments, error) {
	be, err := p.store.Get(keyRecordComments(token))
	if err != nil {
		return nil, err
	}
	rc, err := convertBlobEntryFromRecordComments(be)
	if err != nil {
		return nil, err
	}
	return &rc, nil
}

func (p *commentsPlugin) commentExists(token string, commentID uint32) bool {
	ri, err := p.recordComments(token)
	if err != nil {
		return false
	}
	_, ok := ri.Unvetted[commentID]
	if ok {
		return true
	}
	_, ok = ri.Vetted[commentID]
	if ok {
		return true
	}
	return false
}

func (p *commentsPlugin) cmdNew(payload string) (string, error) {
	n, err := comments.DecodeNew([]byte(payload))
	if err != nil {
		return "", err
	}

	// Verify signature
	err = comments.VerifyCommentSignature(n.Signature, n.PublicKey,
		n.Token, n.ParentID, n.Comment)
	if err != nil {
		return "", err
	}

	// Ensure record exists
	if !p.recordExists(n.Token) {
		return "", fmt.Errorf("record not found %v", n.Token)
	}

	// Ensure parent comment exists if set. A parent ID of 0 means that
	// this is a base level comment, not a reply comment.
	if n.ParentID > 0 && !p.commentExists(n.Token, n.ParentID) {
		e := fmt.Sprintf("parent ID %v comment", n.ParentID)
		return "", comments.PluginError{
			ErrorCode:    comments.ErrorStatusCommentNotFound,
			ErrorContext: []string{e},
		}
	}

	// Setup the comment
	c := comments.Comment{
		Token:     n.Token,
		ParentID:  n.ParentID,
		Comment:   n.Comment,
		PublicKey: n.PublicKey,
		Signature: n.Signature,
		// CommentID: ,
		// Version: ,
		// Receipt: "",
		Timestamp: time.Now().Unix(),
		// Score: 0,
		Deleted:  false,
		Censored: false,
	}
	_ = c

	// Append to trillian tree

	// Save to key-value store

	// Prepare reply

	return "", nil
}
*/

func (p *commentsPlugin) Cmd(id, payload string) (string, error) {
	switch id {
	case comments.CmdNew:
		// return p.cmdNew(payload)
	}
	return "", plugin.ErrInvalidPluginCmd
}

func (p *commentsPlugin) Setup() error {
	return nil
}

func New(dataDir string, tlog *tlogbe.TrillianClient, backend backend.Backend) (*commentsPlugin, error) {
	// Setup key-value store
	fp := filepath.Join(dataDir, commentsDirname)
	err := os.MkdirAll(fp, 0700)
	if err != nil {
		return nil, err
	}
	store := filesystem.New(fp)

	return &commentsPlugin{
		tlog:    tlog,
		store:   store,
		backend: backend,
	}, nil
}
