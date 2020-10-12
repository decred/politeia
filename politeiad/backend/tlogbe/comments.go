// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlogbe

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe/store"
	"github.com/decred/politeia/politeiad/plugins/comments"
	"github.com/decred/politeia/util"
)

// TODO holding the lock before verifying the token can allow the mutexes to
// be spammed. Create an infinite amount of them with invalid tokens. The fix
// is to check if the record exists in the mutexes function to ensure a token
// is valid before holding the lock on it. This is where we can return a
// record doesn't exist user error too.

const (
	// Blob entry data descriptors
	dataDescriptorCommentAdd  = "commentadd"
	dataDescriptorCommentDel  = "commentdel"
	dataDescriptorCommentVote = "commentvote"

	// Prefixes that are appended to key-value store keys before
	// storing them in the log leaf ExtraData field.
	keyPrefixCommentAdd  = "commentadd:"
	keyPrefixCommentDel  = "commentdel:"
	keyPrefixCommentVote = "commentvote:"

	// Filenames of cached data saved to the plugin data dir. Brackets
	// are used to indicate a variable that should be replaced in the
	// filename.
	filenameCommentsIndex = "{state}-{token}-commentsindex.json"
)

var (
	_ pluginClient = (*commentsPlugin)(nil)
)

// commentsPlugin is the tlog backend implementation of the comments plugin.
//
// commentsPlugin satisfies the pluginClient interface.
type commentsPlugin struct {
	sync.Mutex
	backend backend.Backend
	tlog    tlogClient

	// dataDir is the comments plugin data directory. The only data
	// that is stored here is cached data that can be re-created at any
	// time by walking the trillian trees.
	dataDir string

	// identity contains the full identity that the plugin uses to
	// create receipts, i.e. signatures of user provided data that
	// prove the backend received and processed a plugin command.
	identity *identity.FullIdentity

	// Mutexes contains a mutex for each record. The mutexes are lazy
	// loaded.
	mutexes map[string]*sync.Mutex // [string]mutex
}

type voteIndex struct {
	Vote   comments.VoteT `json:"vote"`
	Merkle []byte         `json:"merkle"` // Log leaf merkle leaf hash
}

type commentIndex struct {
	Adds map[uint32][]byte `json:"adds"` // [version]merkleHash
	Del  []byte            `json:"del"`  // Merkle hash of delete record

	// Votes contains the vote history for each uuid that voted on the
	// comment. This data is cached because the effect of a new vote
	// on a comment depends on the previous vote from that uuid.
	// Example, a user upvotes a comment that they have already
	// upvoted, the resulting vote score is 0 due to the second upvote
	// removing the original upvote.
	Votes map[string][]voteIndex `json:"votes"` // [uuid]votes
}

// commentsIndex contains the indexes for all comments made on a record.
type commentsIndex struct {
	Comments map[uint32]commentIndex `json:"comments"` // [commentID]comment
}

// mutex returns the mutex for the specified record.
func (p *commentsPlugin) mutex(token string) *sync.Mutex {
	p.Lock()
	defer p.Unlock()

	m, ok := p.mutexes[token]
	if !ok {
		// Mutexes is lazy loaded
		m = &sync.Mutex{}
		p.mutexes[token] = m
	}

	return m
}

func (p *commentsPlugin) commentsIndexPath(s comments.StateT, token string) string {
	fn := filenameCommentsIndex
	switch s {
	case comments.StateUnvetted:
		fn = strings.Replace(fn, "{state}", "unvetted", 1)
	case comments.StateVetted:
		fn = strings.Replace(fn, "{state}", "vetted", 1)
	default:
		e := fmt.Errorf("unknown comments state: %v", s)
		panic(e)
	}
	fn = strings.Replace(fn, "{token}", token, 1)
	return filepath.Join(p.dataDir, fn)
}

// commentsIndexLocked returns the cached commentsIndex for the provided
// record. If a cached commentsIndex does not exist, a new one will be
// returned.
//
// This function must be called WITH the lock held.
func (p *commentsPlugin) commentsIndexLocked(s comments.StateT, token []byte) (*commentsIndex, error) {
	fp := p.commentsIndexPath(s, hex.EncodeToString(token))
	b, err := ioutil.ReadFile(fp)
	if err != nil {
		var e *os.PathError
		if errors.As(err, &e) && !os.IsExist(err) {
			// File does't exist. Return a new commentsIndex instead.
			return &commentsIndex{
				Comments: make(map[uint32]commentIndex),
			}, nil
		}
		return nil, err
	}

	var idx commentsIndex
	err = json.Unmarshal(b, &idx)
	if err != nil {
		return nil, err
	}

	return &idx, nil
}

// commentsIndex returns the cached commentsIndex for the provided
// record. If a cached commentsIndex does not exist, a new one will be
// returned.
//
// This function must be called WITHOUT the lock held.
func (p *commentsPlugin) commentsIndex(s comments.StateT, token []byte) (*commentsIndex, error) {
	m := p.mutex(hex.EncodeToString(token))
	m.Lock()
	defer m.Unlock()

	return p.commentsIndexLocked(s, token)
}

// commentsIndexSaveLocked saves the provided commentsIndex to the comments
// plugin data dir.
//
// This function must be called WITH the lock held.
func (p *commentsPlugin) commentsIndexSaveLocked(s comments.StateT, token []byte, idx commentsIndex) error {
	b, err := json.Marshal(idx)
	if err != nil {
		return err
	}

	fp := p.commentsIndexPath(s, hex.EncodeToString(token))
	err = ioutil.WriteFile(fp, b, 0664)
	if err != nil {
		return err
	}

	return nil
}

func tlogIDFromCommentState(s comments.StateT) string {
	switch s {
	case comments.StateUnvetted:
		return tlogIDUnvetted
	case comments.StateVetted:
		return tlogIDVetted
	default:
		e := fmt.Sprintf("unknown state %v", s)
		panic(e)
	}
}

func encryptFromCommentState(s comments.StateT) bool {
	switch s {
	case comments.StateUnvetted:
		return true
	case comments.StateVetted:
		return false
	default:
		e := fmt.Sprintf("unknown state %v", s)
		panic(e)
	}
}

func convertCommentsErrorFromSignatureError(err error) backend.PluginUserError {
	var e util.SignatureError
	var s comments.ErrorStatusT
	if errors.As(err, &e) {
		switch e.ErrorCode {
		case util.ErrorStatusPublicKeyInvalid:
			s = comments.ErrorStatusPublicKeyInvalid
		case util.ErrorStatusSignatureInvalid:
			s = comments.ErrorStatusSignatureInvalid
		}
	}
	return backend.PluginUserError{
		PluginID:     comments.ID,
		ErrorCode:    int(s),
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
	hash, err := hex.DecodeString(be.Hash)
	if err != nil {
		return nil, fmt.Errorf("decode hash: %v", err)
	}
	if !bytes.Equal(util.Digest(b), hash) {
		return nil, fmt.Errorf("data is not coherent; got %x, want %x",
			util.Digest(b), hash)
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
	hash, err := hex.DecodeString(be.Hash)
	if err != nil {
		return nil, fmt.Errorf("decode hash: %v", err)
	}
	if !bytes.Equal(util.Digest(b), hash) {
		return nil, fmt.Errorf("data is not coherent; got %x, want %x",
			util.Digest(b), hash)
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
	hash, err := hex.DecodeString(be.Hash)
	if err != nil {
		return nil, fmt.Errorf("decode hash: %v", err)
	}
	if !bytes.Equal(util.Digest(b), hash) {
		return nil, fmt.Errorf("data is not coherent; got %x, want %x",
			util.Digest(b), hash)
	}
	var cv comments.CommentVote
	err = json.Unmarshal(b, &cv)
	if err != nil {
		return nil, fmt.Errorf("unmarshal CommentVote: %v", err)
	}

	return &cv, nil
}

func convertCommentFromCommentAdd(ca comments.CommentAdd) comments.Comment {
	return comments.Comment{
		UserID:    ca.UserID,
		State:     ca.State,
		Token:     ca.Token,
		ParentID:  ca.ParentID,
		Comment:   ca.Comment,
		PublicKey: ca.PublicKey,
		Signature: ca.Signature,
		CommentID: ca.CommentID,
		Version:   ca.Version,
		Timestamp: ca.Timestamp,
		Receipt:   ca.Receipt,
		Downvotes: 0, // Not part of commentAdd data
		Upvotes:   0, // Not part of commentAdd data
		Deleted:   false,
		Reason:    "",
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
		Signature: "",
		CommentID: cd.CommentID,
		Version:   0,
		Timestamp: cd.Timestamp,
		Receipt:   "",
		Downvotes: 0,
		Upvotes:   0,
		Deleted:   true,
		Reason:    cd.Reason,
	}
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
func commentExists(idx commentsIndex, commentID uint32) bool {
	_, ok := idx.Comments[commentID]
	return ok
}

// commentIDLatest returns the latest comment ID.
func commentIDLatest(idx commentsIndex) uint32 {
	var maxID uint32
	for id := range idx.Comments {
		if id > maxID {
			maxID = id
		}
	}
	return maxID
}

func (p *commentsPlugin) commentAddSave(ca comments.CommentAdd) ([]byte, error) {
	// Prepare blob
	be, err := convertBlobEntryFromCommentAdd(ca)
	if err != nil {
		return nil, err
	}
	h, err := hex.DecodeString(be.Hash)
	if err != nil {
		return nil, err
	}
	b, err := store.Blobify(*be)
	if err != nil {
		return nil, err
	}

	// Prepare tlog args
	tlogID := tlogIDFromCommentState(ca.State)
	encrypt := encryptFromCommentState(ca.State)
	token, err := hex.DecodeString(ca.Token)
	if err != nil {
		return nil, err
	}

	// Save blob
	merkles, err := p.tlog.save(tlogID, token, keyPrefixCommentAdd,
		[][]byte{b}, [][]byte{h}, encrypt)
	if err != nil {
		return nil, err
	}
	if len(merkles) != 1 {
		return nil, fmt.Errorf("invalid merkle leaf hash count; got %v, want 1",
			len(merkles))
	}

	return merkles[0], nil
}

// commentAdds returns the commentAdd for all specified merkle hashes.
func (p *commentsPlugin) commentAdds(s comments.StateT, token []byte, merkles [][]byte) ([]comments.CommentAdd, error) {
	// Retrieve blobs
	tlogID := tlogIDFromCommentState(s)
	blobs, err := p.tlog.blobsByMerkle(tlogID, token, merkles)
	if err != nil {
		return nil, err
	}
	if len(blobs) != len(merkles) {
		notFound := make([]string, 0, len(blobs))
		for _, v := range merkles {
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
		be, err := store.Deblob(v)
		if err != nil {
			return nil, err
		}
		c, err := convertCommentAddFromBlobEntry(*be)
		if err != nil {
			return nil, err
		}
		adds = append(adds, *c)
	}

	return adds, nil
}

func (p *commentsPlugin) commentDelSave(cd comments.CommentDel) ([]byte, error) {
	// Prepare blob
	be, err := convertBlobEntryFromCommentDel(cd)
	if err != nil {
		return nil, err
	}
	h, err := hex.DecodeString(be.Hash)
	if err != nil {
		return nil, err
	}
	b, err := store.Blobify(*be)
	if err != nil {
		return nil, err
	}

	// Prepare tlog args
	tlogID := tlogIDFromCommentState(cd.State)
	token, err := hex.DecodeString(cd.Token)
	if err != nil {
		return nil, err
	}

	// Save blob
	merkles, err := p.tlog.save(tlogID, token, keyPrefixCommentDel,
		[][]byte{b}, [][]byte{h}, false)
	if err != nil {
		return nil, err
	}
	if len(merkles) != 1 {
		return nil, fmt.Errorf("invalid merkle leaf hash count; got %v, want 1",
			len(merkles))
	}

	return merkles[0], nil
}

func (p *commentsPlugin) commentDels(s comments.StateT, token []byte, merkles [][]byte) ([]comments.CommentDel, error) {
	// Retrieve blobs
	tlogID := tlogIDFromCommentState(s)
	blobs, err := p.tlog.blobsByMerkle(tlogID, token, merkles)
	if err != nil {
		return nil, err
	}
	if len(blobs) != len(merkles) {
		notFound := make([]string, 0, len(blobs))
		for _, v := range merkles {
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
		be, err := store.Deblob(v)
		if err != nil {
			return nil, err
		}
		c, err := convertCommentDelFromBlobEntry(*be)
		if err != nil {
			return nil, err
		}
		dels = append(dels, *c)
	}

	return dels, nil
}

func (p *commentsPlugin) commentVoteSave(cv comments.CommentVote) ([]byte, error) {
	// Prepare blob
	be, err := convertBlobEntryFromCommentVote(cv)
	if err != nil {
		return nil, err
	}
	h, err := hex.DecodeString(be.Hash)
	if err != nil {
		return nil, err
	}
	b, err := store.Blobify(*be)
	if err != nil {
		return nil, err
	}

	// Prepare tlog args
	tlogID := tlogIDFromCommentState(cv.State)
	token, err := hex.DecodeString(cv.Token)
	if err != nil {
		return nil, err
	}

	// Save blob
	merkles, err := p.tlog.save(tlogID, token, keyPrefixCommentVote,
		[][]byte{b}, [][]byte{h}, false)
	if err != nil {
		return nil, err
	}
	if len(merkles) != 1 {
		return nil, fmt.Errorf("invalid merkle leaf hash count; got %v, want 1",
			len(merkles))
	}

	return merkles[0], nil
}

func (p *commentsPlugin) commentVotes(s comments.StateT, token []byte, merkles [][]byte) ([]comments.CommentVote, error) {
	// Retrieve blobs
	tlogID := tlogIDFromCommentState(s)
	blobs, err := p.tlog.blobsByMerkle(tlogID, token, merkles)
	if err != nil {
		return nil, err
	}
	if len(blobs) != len(merkles) {
		notFound := make([]string, 0, len(blobs))
		for _, v := range merkles {
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
		be, err := store.Deblob(v)
		if err != nil {
			return nil, err
		}
		c, err := convertCommentVoteFromBlobEntry(*be)
		if err != nil {
			return nil, err
		}
		votes = append(votes, *c)
	}

	return votes, nil
}

// comments returns the most recent version of the specified comments. Deleted
// comments are returned with limited data. Comment IDs that do not correspond
// to an actual comment are not included in the returned map. It is the
// responsibility of the caller to ensure a comment is returned for each of the
// provided comment IDs. The comments index that was looked up during this
// process is also returned.
func (p *commentsPlugin) comments(s comments.StateT, token []byte, idx commentsIndex, commentIDs []uint32) (map[uint32]comments.Comment, error) {
	// Aggregate the merkle hashes for all records that need to be
	// looked up. If a comment has been deleted then the only record
	// that will still exist is the comment del record. If the comment
	// has not been deleted then the comment add record will need to be
	// retrieved for the latest version of the comment.
	var (
		merkleAdds = make([][]byte, 0, len(commentIDs))
		merkleDels = make([][]byte, 0, len(commentIDs))
	)
	for _, v := range commentIDs {
		cidx, ok := idx.Comments[v]
		if !ok {
			// Comment does not exist
			continue
		}

		// Comment del record
		if cidx.Del != nil {
			merkleDels = append(merkleDels, cidx.Del)
			continue
		}

		// Comment add record
		version := commentVersionLatest(cidx)
		merkleAdds = append(merkleAdds, cidx.Adds[version])
	}

	// Get comment add records
	adds, err := p.commentAdds(s, token, merkleAdds)
	if err != nil {
		if errors.Is(err, errRecordNotFound) {
			return nil, err
		}
		return nil, fmt.Errorf("commentAdds: %v", err)
	}
	if len(adds) != len(merkleAdds) {
		return nil, fmt.Errorf("wrong comment adds count; got %v, want %v",
			len(adds), len(merkleAdds))
	}

	// Get comment del records
	dels, err := p.commentDels(s, token, merkleDels)
	if err != nil {
		return nil, fmt.Errorf("commentDels: %v", err)
	}
	if len(dels) != len(merkleDels) {
		return nil, fmt.Errorf("wrong comment dels count; got %v, want %v",
			len(dels), len(merkleDels))
	}

	// Prepare comments
	cs := make(map[uint32]comments.Comment, len(commentIDs))
	for _, v := range adds {
		c := convertCommentFromCommentAdd(v)
		cidx, ok := idx.Comments[c.CommentID]
		if !ok {
			return nil, fmt.Errorf("comment index not found %v", c.CommentID)
		}
		c.Downvotes, c.Upvotes = calcVoteScore(cidx)
		cs[v.CommentID] = c
	}
	for _, v := range dels {
		c := convertCommentFromCommentDel(v)
		cs[v.CommentID] = c
	}

	return cs, nil
}

func (p *commentsPlugin) cmdNew(payload string) (string, error) {
	log.Tracef("comments cmdNew: %v", payload)

	// Decode payload
	n, err := comments.DecodeNew([]byte(payload))
	if err != nil {
		return "", err
	}

	// Verify state
	switch n.State {
	case comments.StateUnvetted, comments.StateVetted:
		// Allowed; continue
	default:
		return "", backend.PluginUserError{
			PluginID:  comments.ID,
			ErrorCode: int(comments.ErrorStatusStateInvalid),
		}
	}

	// Verify token
	token, err := util.ConvertStringToken(n.Token)
	if err != nil {
		return "", backend.PluginUserError{
			PluginID:  comments.ID,
			ErrorCode: int(comments.ErrorStatusTokenInvalid),
		}
	}

	// Verify signature
	msg := strconv.Itoa(int(n.State)) + n.Token +
		strconv.FormatUint(uint64(n.ParentID), 10) + n.Comment
	err = util.VerifySignature(n.Signature, n.PublicKey, msg)
	if err != nil {
		return "", convertCommentsErrorFromSignatureError(err)
	}

	// Verify comment
	if len(n.Comment) > comments.PolicyCommentLengthMax {
		return "", backend.PluginUserError{
			PluginID:     comments.ID,
			ErrorCode:    int(comments.ErrorStatusCommentTextInvalid),
			ErrorContext: []string{"exceeds max length"},
		}
	}

	// The comments index must be pulled and updated. The record lock
	// must be held for the remainder of this function.
	m := p.mutex(n.Token)
	m.Lock()
	defer m.Unlock()

	// Get comments index
	idx, err := p.commentsIndexLocked(n.State, token)
	if err != nil {
		return "", err
	}

	// Verify parent comment exists if set. A parent ID of 0 means that
	// this is a base level comment, not a reply to another comment.
	if n.ParentID > 0 && !commentExists(*idx, n.ParentID) {
		return "", backend.PluginUserError{
			PluginID:     comments.ID,
			ErrorCode:    int(comments.ErrorStatusParentIDInvalid),
			ErrorContext: []string{"parent ID comment not found"},
		}
	}

	// Setup comment
	receipt := p.identity.SignMessage([]byte(n.Signature))
	ca := comments.CommentAdd{
		UserID:    n.UserID,
		State:     n.State,
		Token:     n.Token,
		ParentID:  n.ParentID,
		Comment:   n.Comment,
		PublicKey: n.PublicKey,
		Signature: n.Signature,
		CommentID: commentIDLatest(*idx) + 1,
		Version:   1,
		Timestamp: time.Now().Unix(),
		Receipt:   hex.EncodeToString(receipt[:]),
	}

	// Save comment
	merkleHash, err := p.commentAddSave(ca)
	if err != nil {
		if errors.Is(err, errRecordNotFound) {
			return "", backend.PluginUserError{
				PluginID:  comments.ID,
				ErrorCode: int(comments.ErrorStatusRecordNotFound),
			}
		}
		return "", fmt.Errorf("commentAddSave: %v", err)
	}

	// Update index
	idx.Comments[ca.CommentID] = commentIndex{
		Adds: map[uint32][]byte{
			1: merkleHash,
		},
		Del:   nil,
		Votes: make(map[string][]voteIndex),
	}

	// Save index
	err = p.commentsIndexSaveLocked(n.State, token, *idx)
	if err != nil {
		return "", err
	}

	log.Debugf("Comment saved to record %v comment ID %v",
		ca.Token, ca.CommentID)

	// Prepare reply
	nr := comments.NewReply{
		CommentID: ca.CommentID,
		Timestamp: ca.Timestamp,
		Receipt:   ca.Receipt,
	}
	reply, err := comments.EncodeNewReply(nr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

func (p *commentsPlugin) cmdEdit(payload string) (string, error) {
	log.Tracef("comments cmdEdit: %v", payload)

	// Decode payload
	e, err := comments.DecodeEdit([]byte(payload))
	if err != nil {
		return "", err
	}

	// Verify state
	switch e.State {
	case comments.StateUnvetted, comments.StateVetted:
		// Allowed; continue
	default:
		return "", backend.PluginUserError{
			PluginID:  comments.ID,
			ErrorCode: int(comments.ErrorStatusTokenInvalid),
		}
	}

	// Verify token
	token, err := util.ConvertStringToken(e.Token)
	if err != nil {
		return "", backend.PluginUserError{
			PluginID:  comments.ID,
			ErrorCode: int(comments.ErrorStatusTokenInvalid),
		}
	}

	// Verify signature
	msg := strconv.Itoa(int(e.State)) + e.Token +
		strconv.FormatUint(uint64(e.ParentID), 10) + e.Comment
	err = util.VerifySignature(e.Signature, e.PublicKey, msg)
	if err != nil {
		return "", convertCommentsErrorFromSignatureError(err)
	}

	// Verify comment
	if len(e.Comment) > comments.PolicyCommentLengthMax {
		return "", backend.PluginUserError{
			PluginID:     comments.ID,
			ErrorCode:    int(comments.ErrorStatusCommentTextInvalid),
			ErrorContext: []string{"exceeds max length"},
		}
	}

	// The comments index must be pulled and updated. The record lock
	// must be held for the remainder of this function.
	m := p.mutex(e.Token)
	m.Lock()
	defer m.Unlock()

	// Get comments index
	idx, err := p.commentsIndexLocked(e.State, token)
	if err != nil {
		return "", err
	}

	// Get the existing comment
	cs, err := p.comments(e.State, token, *idx, []uint32{e.CommentID})
	if err != nil {
		return "", fmt.Errorf("comments %v: %v", e.CommentID, err)
	}
	existing, ok := cs[e.CommentID]
	if !ok {
		return "", backend.PluginUserError{
			PluginID:  comments.ID,
			ErrorCode: int(comments.ErrorStatusCommentNotFound),
		}
	}

	// Verify the user ID
	if e.UserID != existing.UserID {
		return "", backend.PluginUserError{
			PluginID:  comments.ID,
			ErrorCode: int(comments.ErrorStatusUserUnauthorized),
		}
	}

	// Verify the parent ID
	if e.ParentID != existing.ParentID {
		e := fmt.Sprintf("parent id cannot change; got %v, want %v",
			e.ParentID, existing.ParentID)
		return "", backend.PluginUserError{
			PluginID:     comments.ID,
			ErrorCode:    int(comments.ErrorStatusParentIDInvalid),
			ErrorContext: []string{e},
		}
	}

	// Verify comment changes
	if e.Comment == existing.Comment {
		return "", backend.PluginUserError{
			PluginID:     comments.ID,
			ErrorCode:    int(comments.ErrorStatusCommentTextInvalid),
			ErrorContext: []string{"comment did not change"},
		}
	}

	// Create a new comment version
	receipt := p.identity.SignMessage([]byte(e.Signature))
	ca := comments.CommentAdd{
		UserID:    e.UserID,
		Token:     e.Token,
		ParentID:  e.ParentID,
		Comment:   e.Comment,
		PublicKey: e.PublicKey,
		Signature: e.Signature,
		CommentID: e.CommentID,
		Version:   existing.Version + 1,
		Timestamp: time.Now().Unix(),
		Receipt:   hex.EncodeToString(receipt[:]),
	}

	// Save comment
	merkle, err := p.commentAddSave(ca)
	if err != nil {
		if errors.Is(err, errRecordNotFound) {
			return "", backend.PluginUserError{
				PluginID:  comments.ID,
				ErrorCode: int(comments.ErrorStatusRecordNotFound),
			}
		}
		return "", fmt.Errorf("commentSave: %v", err)
	}

	// Update index
	idx.Comments[ca.CommentID].Adds[ca.Version] = merkle

	// Save index
	err = p.commentsIndexSaveLocked(e.State, token, *idx)
	if err != nil {
		return "", err
	}

	log.Debugf("Comment edited on record %v comment ID %v",
		ca.Token, ca.CommentID)

	// Prepare reply
	er := comments.EditReply{
		Version:   ca.Version,
		Timestamp: ca.Timestamp,
		Receipt:   ca.Receipt,
	}
	reply, err := comments.EncodeEditReply(er)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

func (p *commentsPlugin) cmdDel(payload string) (string, error) {
	log.Tracef("comments cmdDel: %v", payload)

	// Decode payload
	d, err := comments.DecodeDel([]byte(payload))
	if err != nil {
		return "", err
	}

	// Verify state
	switch d.State {
	case comments.StateUnvetted, comments.StateVetted:
		// Allowed; continue
	default:
		return "", backend.PluginUserError{
			PluginID:  comments.ID,
			ErrorCode: int(comments.ErrorStatusTokenInvalid),
		}
	}

	// Verify token
	token, err := util.ConvertStringToken(d.Token)
	if err != nil {
		return "", backend.PluginUserError{
			PluginID:  comments.ID,
			ErrorCode: int(comments.ErrorStatusTokenInvalid),
		}
	}

	// Verify signature
	msg := strconv.Itoa(int(d.State)) + d.Token +
		strconv.FormatUint(uint64(d.CommentID), 10) + d.Reason
	err = util.VerifySignature(d.Signature, d.PublicKey, msg)
	if err != nil {
		return "", convertCommentsErrorFromSignatureError(err)
	}

	// The comments index must be pulled and updated. The record lock
	// must be held for the remainder of this function.
	m := p.mutex(d.Token)
	m.Lock()
	defer m.Unlock()

	// Get comments index
	idx, err := p.commentsIndexLocked(d.State, token)
	if err != nil {
		return "", err
	}

	// Get the existing comment
	cs, err := p.comments(d.State, token, *idx, []uint32{d.CommentID})
	if err != nil {
		return "", fmt.Errorf("comments %v: %v", d.CommentID, err)
	}
	existing, ok := cs[d.CommentID]
	if !ok {
		return "", backend.PluginUserError{
			PluginID:  comments.ID,
			ErrorCode: int(comments.ErrorStatusCommentNotFound),
		}
	}

	// Prepare comment delete
	receipt := p.identity.SignMessage([]byte(d.Signature))
	cd := comments.CommentDel{
		State:     d.State,
		Token:     d.Token,
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
	merkle, err := p.commentDelSave(cd)
	if err != nil {
		if errors.Is(err, errRecordNotFound) {
			return "", backend.PluginUserError{
				PluginID:  comments.ID,
				ErrorCode: int(comments.ErrorStatusRecordNotFound),
			}
		}
		return "", fmt.Errorf("commentDelSave: %v", err)
	}

	// Update index
	cidx, ok := idx.Comments[d.CommentID]
	if !ok {
		// This should not be possible
		e := fmt.Sprintf("comment not found in index: %v", d.CommentID)
		panic(e)
	}
	cidx.Del = merkle
	idx.Comments[d.CommentID] = cidx

	// Save index
	err = p.commentsIndexSaveLocked(d.State, token, *idx)
	if err != nil {
		return "", err
	}

	// Delete all comment versions
	merkles := make([][]byte, 0, len(cidx.Adds))
	for _, v := range cidx.Adds {
		merkles = append(merkles, v)
	}
	tlogID := tlogIDFromCommentState(d.State)
	err = p.tlog.del(tlogID, token, merkles)
	if err != nil {
		return "", fmt.Errorf("del: %v", err)
	}

	// Prepare reply
	dr := comments.DelReply{
		Timestamp: cd.Timestamp,
		Receipt:   cd.Receipt,
	}
	reply, err := comments.EncodeDelReply(dr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// calcVoteScore returns the vote score for the provided comment index. The
// returned values are the downvotes and upvotes, respectively.
func calcVoteScore(cidx commentIndex) (uint64, uint64) {
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
			// Something went wrong
			e := fmt.Errorf("unexpected vote score %v", score)
			panic(e)
		}
	}

	return downvotes, upvotes
}

func (p *commentsPlugin) cmdVote(payload string) (string, error) {
	log.Tracef("comments cmdVote: %v", payload)

	// Decode payload
	v, err := comments.DecodeVote([]byte(payload))
	if err != nil {
		return "", err
	}

	// Verify state
	switch v.State {
	case comments.StateUnvetted, comments.StateVetted:
		// Allowed; continue
	default:
		return "", backend.PluginUserError{
			PluginID:  comments.ID,
			ErrorCode: int(comments.ErrorStatusTokenInvalid),
		}
	}

	// Verify token
	token, err := util.ConvertStringToken(v.Token)
	if err != nil {
		return "", backend.PluginUserError{
			PluginID:  comments.ID,
			ErrorCode: int(comments.ErrorStatusTokenInvalid),
		}
	}

	// Verify vote
	switch v.Vote {
	case comments.VoteDownvote, comments.VoteUpvote:
		// These are allowed
	default:
		return "", backend.PluginUserError{
			PluginID:  comments.ID,
			ErrorCode: int(comments.ErrorStatusVoteInvalid),
		}
	}

	// Verify signature
	msg := strconv.Itoa(int(v.State)) + v.Token +
		strconv.FormatUint(uint64(v.CommentID), 10) +
		strconv.FormatInt(int64(v.Vote), 10)
	err = util.VerifySignature(v.Signature, v.PublicKey, msg)
	if err != nil {
		return "", convertCommentsErrorFromSignatureError(err)
	}

	// The comments index must be pulled and updated. The record lock
	// must be held for the remainder of this function.
	m := p.mutex(v.Token)
	m.Lock()
	defer m.Unlock()

	// Get comments index
	idx, err := p.commentsIndexLocked(v.State, token)
	if err != nil {
		return "", err
	}

	// Verify comment exists
	cidx, ok := idx.Comments[v.CommentID]
	if !ok {
		return "", backend.PluginUserError{
			PluginID:  comments.ID,
			ErrorCode: int(comments.ErrorStatusCommentNotFound),
		}
	}

	// Verify user has not exceeded max allowed vote changes
	uvotes, ok := cidx.Votes[v.UserID]
	if !ok {
		uvotes = make([]voteIndex, 0)
	}
	if len(uvotes) > comments.PolicyVoteChangesMax {
		return "", backend.PluginUserError{
			PluginID:  comments.ID,
			ErrorCode: int(comments.ErrorStatusVoteChangesMax),
		}
	}

	// Verify user is not voting on their own comment
	cs, err := p.comments(v.State, token, *idx, []uint32{v.CommentID})
	if err != nil {
		return "", fmt.Errorf("comments %v: %v", v.CommentID, err)
	}
	c, ok := cs[v.CommentID]
	if !ok {
		return "", fmt.Errorf("comment not found %v", v.CommentID)
	}
	if v.UserID == c.UserID {
		return "", backend.PluginUserError{
			PluginID:     comments.ID,
			ErrorCode:    int(comments.ErrorStatusVoteInvalid),
			ErrorContext: []string{"user cannot vote on their own comment"},
		}
	}

	// Prepare comment vote
	receipt := p.identity.SignMessage([]byte(v.Signature))
	cv := comments.CommentVote{
		State:     v.State,
		UserID:    v.UserID,
		Token:     v.Token,
		CommentID: v.CommentID,
		Vote:      v.Vote,
		PublicKey: v.PublicKey,
		Signature: v.Signature,
		Timestamp: time.Now().Unix(),
		Receipt:   hex.EncodeToString(receipt[:]),
	}

	// Save comment vote
	merkle, err := p.commentVoteSave(cv)
	if err != nil {
		if errors.Is(err, errRecordNotFound) {
			return "", backend.PluginUserError{
				PluginID:  comments.ID,
				ErrorCode: int(comments.ErrorStatusRecordNotFound),
			}
		}
		return "", fmt.Errorf("commentVoteSave: %v", err)
	}

	// Add vote to the comment index
	votes, ok := cidx.Votes[cv.UserID]
	if !ok {
		votes = make([]voteIndex, 0, 1)
	}
	votes = append(votes, voteIndex{
		Vote:   cv.Vote,
		Merkle: merkle,
	})
	cidx.Votes[cv.UserID] = votes

	// Update the comments index
	idx.Comments[cv.CommentID] = cidx

	// Save index
	err = p.commentsIndexSaveLocked(cv.State, token, *idx)
	if err != nil {
		return "", err
	}

	// Calculate the new vote scores
	downvotes, upvotes := calcVoteScore(cidx)

	// Prepare reply
	vr := comments.VoteReply{
		Downvotes: downvotes,
		Upvotes:   upvotes,
		Timestamp: cv.Timestamp,
		Receipt:   cv.Receipt,
	}
	reply, err := comments.EncodeVoteReply(vr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

func (p *commentsPlugin) cmdGet(payload string) (string, error) {
	log.Tracef("comments cmdGet: %v", payload)

	// Decode payload
	g, err := comments.DecodeGet([]byte(payload))
	if err != nil {
		return "", err
	}

	// Verify state
	switch g.State {
	case comments.StateUnvetted, comments.StateVetted:
		// Allowed; continue
	default:
		return "", backend.PluginUserError{
			PluginID:  comments.ID,
			ErrorCode: int(comments.ErrorStatusTokenInvalid),
		}
	}

	// Verify token
	token, err := util.ConvertStringToken(g.Token)
	if err != nil {
		return "", backend.PluginUserError{
			PluginID:  comments.ID,
			ErrorCode: int(comments.ErrorStatusTokenInvalid),
		}
	}

	// Get comments index
	idx, err := p.commentsIndex(g.State, token)
	if err != nil {
		return "", err
	}

	// Get comments
	cs, err := p.comments(g.State, token, *idx, g.CommentIDs)
	if err != nil {
		if errors.Is(err, errRecordNotFound) {
			return "", backend.PluginUserError{
				PluginID:  comments.ID,
				ErrorCode: int(comments.ErrorStatusRecordNotFound),
			}
		}
		return "", fmt.Errorf("comments: %v", err)
	}

	// Prepare reply
	gr := comments.GetReply{
		Comments: cs,
	}
	reply, err := comments.EncodeGetReply(gr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

func (p *commentsPlugin) cmdGetAll(payload string) (string, error) {
	log.Tracef("comments cmdGetAll: %v", payload)

	// Decode payload
	ga, err := comments.DecodeGetAll([]byte(payload))
	if err != nil {
		return "", err
	}

	// Verify state
	switch ga.State {
	case comments.StateUnvetted, comments.StateVetted:
		// Allowed; continue
	default:
		return "", backend.PluginUserError{
			PluginID:  comments.ID,
			ErrorCode: int(comments.ErrorStatusTokenInvalid),
		}
	}

	// Verify token
	token, err := util.ConvertStringToken(ga.Token)
	if err != nil {
		return "", backend.PluginUserError{
			PluginID:  comments.ID,
			ErrorCode: int(comments.ErrorStatusTokenInvalid),
		}
	}

	// Get comments index
	idx, err := p.commentsIndex(ga.State, token)
	if err != nil {
		return "", err
	}

	// Compile comment IDs
	commentIDs := make([]uint32, 0, len(idx.Comments))
	for k := range idx.Comments {
		commentIDs = append(commentIDs, k)
	}

	// Get comments
	c, err := p.comments(ga.State, token, *idx, commentIDs)
	if err != nil {
		if errors.Is(err, errRecordNotFound) {
			return "", backend.PluginUserError{
				PluginID:  comments.ID,
				ErrorCode: int(comments.ErrorStatusRecordNotFound),
			}
		}
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
	reply, err := comments.EncodeGetAllReply(gar)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

func (p *commentsPlugin) cmdGetVersion(payload string) (string, error) {
	log.Tracef("comments cmdGetVersion: %v", payload)

	// Decode payload
	gv, err := comments.DecodeGetVersion([]byte(payload))
	if err != nil {
		return "", err
	}

	// Verify state
	switch gv.State {
	case comments.StateUnvetted, comments.StateVetted:
		// Allowed; continue
	default:
		return "", backend.PluginUserError{
			PluginID:  comments.ID,
			ErrorCode: int(comments.ErrorStatusTokenInvalid),
		}
	}

	// Verify token
	token, err := util.ConvertStringToken(gv.Token)
	if err != nil {
		return "", backend.PluginUserError{
			PluginID:  comments.ID,
			ErrorCode: int(comments.ErrorStatusTokenInvalid),
		}
	}

	// Get comments index
	idx, err := p.commentsIndex(gv.State, token)
	if err != nil {
		return "", err
	}

	// Verify comment exists
	cidx, ok := idx.Comments[gv.CommentID]
	if !ok {
		return "", backend.PluginUserError{
			PluginID:  comments.ID,
			ErrorCode: int(comments.ErrorStatusCommentNotFound),
		}
	}
	if cidx.Del != nil {
		return "", backend.PluginUserError{
			PluginID:     comments.ID,
			ErrorCode:    int(comments.ErrorStatusCommentNotFound),
			ErrorContext: []string{"comment has been deleted"},
		}
	}
	merkle, ok := cidx.Adds[gv.Version]
	if !ok {
		e := fmt.Sprintf("comment %v does not have version %v",
			gv.CommentID, gv.Version)
		return "", backend.PluginUserError{
			PluginID:     comments.ID,
			ErrorCode:    int(comments.ErrorStatusCommentNotFound),
			ErrorContext: []string{e},
		}
	}

	// Get comment add record
	adds, err := p.commentAdds(gv.State, token, [][]byte{merkle})
	if err != nil {
		return "", fmt.Errorf("commentAdds: %v", err)
	}
	if len(adds) != 1 {
		return "", fmt.Errorf("wrong comment adds count; got %v, want 1",
			len(adds))
	}

	// Convert to a comment
	c := convertCommentFromCommentAdd(adds[0])
	c.Downvotes, c.Upvotes = calcVoteScore(cidx)

	// Prepare reply
	gvr := comments.GetVersionReply{
		Comment: c,
	}
	reply, err := comments.EncodeGetVersionReply(gvr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

func (p *commentsPlugin) cmdCount(payload string) (string, error) {
	log.Tracef("comments cmdCount: %v", payload)

	// Decode payload
	c, err := comments.DecodeCount([]byte(payload))
	if err != nil {
		return "", err
	}

	// Verify state
	switch c.State {
	case comments.StateUnvetted, comments.StateVetted:
		// Allowed; continue
	default:
		return "", backend.PluginUserError{
			PluginID:  comments.ID,
			ErrorCode: int(comments.ErrorStatusTokenInvalid),
		}
	}

	// Verify token
	token, err := util.ConvertStringToken(c.Token)
	if err != nil {
		return "", backend.PluginUserError{
			PluginID:  comments.ID,
			ErrorCode: int(comments.ErrorStatusTokenInvalid),
		}
	}

	// Get comments index
	idx, err := p.commentsIndex(c.State, token)
	if err != nil {
		return "", err
	}

	// Prepare reply
	cr := comments.CountReply{
		Count: uint64(len(idx.Comments)),
	}
	reply, err := comments.EncodeCountReply(cr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

func (p *commentsPlugin) cmdVotes(payload string) (string, error) {
	log.Tracef("comments cmdVotes: %v", payload)

	// Decode payload
	v, err := comments.DecodeVotes([]byte(payload))
	if err != nil {
		return "", err
	}

	// Verify state
	switch v.State {
	case comments.StateUnvetted, comments.StateVetted:
		// Allowed; continue
	default:
		return "", backend.PluginUserError{
			PluginID:  comments.ID,
			ErrorCode: int(comments.ErrorStatusTokenInvalid),
		}
	}

	// Verify token
	token, err := util.ConvertStringToken(v.Token)
	if err != nil {
		return "", backend.PluginUserError{
			PluginID:  comments.ID,
			ErrorCode: int(comments.ErrorStatusTokenInvalid),
		}
	}

	// Get comments index
	idx, err := p.commentsIndex(v.State, token)
	if err != nil {
		return "", err
	}

	// Compile the comment vote merkles for all votes that were cast
	// by the specified user.
	merkles := make([][]byte, 0, 256)
	for _, cidx := range idx.Comments {
		voteIdxs, ok := cidx.Votes[v.UserID]
		if !ok {
			// User has not cast any votes for this comment
			continue
		}

		// User has cast votes on this comment
		for _, vidx := range voteIdxs {
			merkles = append(merkles, vidx.Merkle)
		}
	}

	// Lookup votes
	votes, err := p.commentVotes(v.State, token, merkles)
	if err != nil {
		return "", fmt.Errorf("commentVotes: %v", err)
	}

	// Prepare reply
	vr := comments.VotesReply{
		Votes: votes,
	}
	reply, err := comments.EncodeVotesReply(vr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// cmd executes a plugin command.
//
// This function satisfies the pluginClient interface.
func (p *commentsPlugin) cmd(cmd, payload string) (string, error) {
	log.Tracef("comments cmd: %v", cmd)

	switch cmd {
	case comments.CmdNew:
		return p.cmdNew(payload)
	case comments.CmdEdit:
		return p.cmdEdit(payload)
	case comments.CmdDel:
		return p.cmdDel(payload)
	case comments.CmdVote:
		return p.cmdVote(payload)
	case comments.CmdGet:
		return p.cmdGet(payload)
	case comments.CmdGetAll:
		return p.cmdGetAll(payload)
	case comments.CmdGetVersion:
		return p.cmdGetVersion(payload)
	case comments.CmdCount:
		return p.cmdCount(payload)
	case comments.CmdVotes:
		return p.cmdVotes(payload)
	}

	return "", backend.ErrPluginCmdInvalid
}

// hook executes a plugin hook.
//
// This function satisfies the pluginClient interface.
func (p *commentsPlugin) hook(h hookT, payload string) error {
	log.Tracef("comments hook: %v", hooks[h])

	return nil
}

// fsck performs a plugin filesystem check.
//
// This function satisfies the pluginClient interface.
func (p *commentsPlugin) fsck() error {
	log.Tracef("comments fsck")

	// Make sure CommentDel blobs were actually deleted

	return nil
}

// setup performs any plugin setup work that needs to be done.
//
// This function satisfies the pluginClient interface.
func (p *commentsPlugin) setup() error {
	log.Tracef("comments setup")

	return nil
}

// newCommentsPlugin returns a new comments plugin.
func newCommentsPlugin(backend backend.Backend, tlog tlogClient, settings []backend.PluginSetting, id *identity.FullIdentity) (*commentsPlugin, error) {
	// Unpack plugin settings
	var (
		dataDir string
	)
	for _, v := range settings {
		switch v.Key {
		case pluginSettingDataDir:
			dataDir = v.Value
		default:
			return nil, fmt.Errorf("invalid plugin setting '%v'", v.Key)
		}
	}

	// Verify plugin settings
	switch {
	case dataDir == "":
		return nil, fmt.Errorf("plugin setting not found: %v",
			pluginSettingDataDir)
	}

	// Create the plugin data directory
	dataDir = filepath.Join(dataDir, comments.ID)
	err := os.MkdirAll(dataDir, 0700)
	if err != nil {
		return nil, err
	}

	return &commentsPlugin{
		backend:  backend,
		tlog:     tlog,
		identity: id,
		dataDir:  dataDir,
		mutexes:  make(map[string]*sync.Mutex),
	}, nil
}
