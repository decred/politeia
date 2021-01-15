// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package comments

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe/plugins"
	"github.com/decred/politeia/politeiad/backend/tlogbe/store"
	"github.com/decred/politeia/politeiad/backend/tlogbe/tlogclient"
	"github.com/decred/politeia/politeiad/plugins/comments"
	"github.com/decred/politeia/util"
)

// TODO prevent duplicate comments
// TODO upvoting a comment twice in the same second causes a duplicate leaf
// error which causes a 500. Solution: add the timestamp to the vote index.

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
	filenameRecordIndex = "{tokenPrefix}-index.json"
)

var (
	_ plugins.Client = (*commentsPlugin)(nil)
)

// commentsPlugin is the tlog backend implementation of the comments plugin.
//
// commentsPlugin satisfies the plugins.Client interface.
type commentsPlugin struct {
	sync.Mutex
	tlog tlogclient.Client

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

// mutex returns the mutex for a record.
func (p *commentsPlugin) mutex(token []byte) *sync.Mutex {
	p.Lock()
	defer p.Unlock()

	t := hex.EncodeToString(token)
	m, ok := p.mutexes[t]
	if !ok {
		// Mutexes is lazy loaded
		m = &sync.Mutex{}
		p.mutexes[t] = m
	}

	return m
}

func tokenDecode(token string) ([]byte, error) {
	return util.TokenDecode(util.TokenTypeTlog, token)
}

func convertSignatureError(err error) backend.PluginUserError {
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
	return backend.PluginUserError{
		PluginID:     comments.ID,
		ErrorCode:    int(s),
		ErrorContext: strings.Join(e.ErrorContext, ", "),
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
		Token:     cd.Token,
		ParentID:  cd.ParentID,
		Comment:   "",
		Signature: "",
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

func (p *commentsPlugin) commentAddSave(treeID int64, ca comments.CommentAdd) ([]byte, error) {
	be, err := convertBlobEntryFromCommentAdd(ca)
	if err != nil {
		return nil, err
	}
	merkle, err := p.tlog.BlobSave(treeID, keyPrefixCommentAdd, *be)
	if err != nil {
		return nil, err
	}
	return merkle, nil
}

// commentAdds returns the commentAdd for all specified merkle hashes.
func (p *commentsPlugin) commentAdds(treeID int64, merkles [][]byte) ([]comments.CommentAdd, error) {
	// Retrieve blobs
	blobs, err := p.tlog.BlobsByMerkle(treeID, merkles)
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

func (p *commentsPlugin) commentDelSave(treeID int64, cd comments.CommentDel) ([]byte, error) {
	be, err := convertBlobEntryFromCommentDel(cd)
	if err != nil {
		return nil, err
	}
	merkle, err := p.tlog.BlobSave(treeID, keyPrefixCommentDel, *be)
	if err != nil {
		return nil, err
	}
	return merkle, nil
}

func (p *commentsPlugin) commentDels(treeID int64, merkles [][]byte) ([]comments.CommentDel, error) {
	// Retrieve blobs
	blobs, err := p.tlog.BlobsByMerkle(treeID, merkles)
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

func (p *commentsPlugin) commentVoteSave(treeID int64, cv comments.CommentVote) ([]byte, error) {
	be, err := convertBlobEntryFromCommentVote(cv)
	if err != nil {
		return nil, err
	}
	merkle, err := p.tlog.BlobSave(treeID, keyPrefixCommentVote, *be)
	if err != nil {
		return nil, err
	}
	return merkle, nil
}

func (p *commentsPlugin) commentVotes(treeID int64, merkles [][]byte) ([]comments.CommentVote, error) {
	// Retrieve blobs
	blobs, err := p.tlog.BlobsByMerkle(treeID, merkles)
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
// provided comment IDs.
func (p *commentsPlugin) comments(treeID int64, ridx recordIndex, commentIDs []uint32) (map[uint32]comments.Comment, error) {
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
		cidx, ok := ridx.Comments[v]
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
	adds, err := p.commentAdds(treeID, merkleAdds)
	if err != nil {
		return nil, fmt.Errorf("commentAdds: %v", err)
	}
	if len(adds) != len(merkleAdds) {
		return nil, fmt.Errorf("wrong comment adds count; got %v, want %v",
			len(adds), len(merkleAdds))
	}

	// Get comment del records
	dels, err := p.commentDels(treeID, merkleDels)
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
		cidx, ok := ridx.Comments[c.CommentID]
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

// comment returns the latest version of the provided comment.
func (p *commentsPlugin) comment(treeID int64, ridx recordIndex, commentID uint32) (*comments.Comment, error) {
	cs, err := p.comments(treeID, ridx, []uint32{commentID})
	if err != nil {
		return nil, fmt.Errorf("comments: %v", err)
	}
	c, ok := cs[commentID]
	if !ok {
		return nil, fmt.Errorf("comment not found")
	}
	return &c, nil
}

func (p *commentsPlugin) timestamp(treeID int64, merkle []byte) (*comments.Timestamp, error) {
	// Get timestamp
	t, err := p.tlog.Timestamp(treeID, merkle)
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

func (p *commentsPlugin) cmdNew(treeID int64, token []byte, payload string) (string, error) {
	log.Tracef("cmdNew: %v %x %v", treeID, token, payload)

	// Decode payload
	var n comments.New
	err := json.Unmarshal([]byte(payload), &n)
	if err != nil {
		return "", err
	}

	// Verify token
	t, err := tokenDecode(n.Token)
	if err != nil {
		return "", backend.PluginUserError{
			PluginID:     comments.ID,
			ErrorCode:    int(comments.ErrorCodeTokenInvalid),
			ErrorContext: err.Error(),
		}
	}
	if !bytes.Equal(t, token) {
		e := fmt.Sprintf("comment token does not match route token: "+
			"got %x, want %x", t, token)
		return "", backend.PluginUserError{
			PluginID:     comments.ID,
			ErrorCode:    int(comments.ErrorCodeTokenInvalid),
			ErrorContext: e,
		}
	}

	// Verify signature
	msg := n.Token + strconv.FormatUint(uint64(n.ParentID), 10) + n.Comment
	err = util.VerifySignature(n.Signature, n.PublicKey, msg)
	if err != nil {
		return "", convertSignatureError(err)
	}

	// Verify comment
	if len(n.Comment) > comments.PolicyCommentLengthMax {
		return "", backend.PluginUserError{
			PluginID:     comments.ID,
			ErrorCode:    int(comments.ErrorCodeCommentTextInvalid),
			ErrorContext: "exceeds max length",
		}
	}

	// The record index must be pulled and updated. The record lock
	// must be held for the remainder of this function.
	m := p.mutex(token)
	m.Lock()
	defer m.Unlock()

	// Get record index
	ridx, err := p.recordIndexLocked(token)
	if err != nil {
		return "", err
	}

	// Verify parent comment exists if set. A parent ID of 0 means that
	// this is a base level comment, not a reply to another comment.
	if n.ParentID > 0 && !commentExists(*ridx, n.ParentID) {
		return "", backend.PluginUserError{
			PluginID:     comments.ID,
			ErrorCode:    int(comments.ErrorCodeParentIDInvalid),
			ErrorContext: "parent ID comment not found",
		}
	}

	// Setup comment
	receipt := p.identity.SignMessage([]byte(n.Signature))
	ca := comments.CommentAdd{
		UserID:    n.UserID,
		Token:     n.Token,
		ParentID:  n.ParentID,
		Comment:   n.Comment,
		PublicKey: n.PublicKey,
		Signature: n.Signature,
		CommentID: commentIDLatest(*ridx) + 1,
		Version:   1,
		Timestamp: time.Now().Unix(),
		Receipt:   hex.EncodeToString(receipt[:]),
	}

	// Save comment
	merkleHash, err := p.commentAddSave(treeID, ca)
	if err != nil {
		return "", fmt.Errorf("commentAddSave: %v", err)
	}

	// Update index
	ridx.Comments[ca.CommentID] = commentIndex{
		Adds: map[uint32][]byte{
			1: merkleHash,
		},
		Del:   nil,
		Votes: make(map[string][]voteIndex),
	}

	// Save index
	err = p.recordIndexSaveLocked(token, *ridx)
	if err != nil {
		return "", err
	}

	log.Debugf("Comment saved to record %v comment ID %v",
		ca.Token, ca.CommentID)

	// Return new comment
	c, err := p.comment(treeID, *ridx, ca.CommentID)
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

func (p *commentsPlugin) cmdEdit(treeID int64, token []byte, payload string) (string, error) {
	log.Tracef("cmdEdit: %v %x %v", treeID, token, payload)

	// Decode payload
	var e comments.Edit
	err := json.Unmarshal([]byte(payload), &e)
	if err != nil {
		return "", err
	}

	// Verify token
	t, err := tokenDecode(e.Token)
	if err != nil {
		return "", backend.PluginUserError{
			PluginID:     comments.ID,
			ErrorCode:    int(comments.ErrorCodeTokenInvalid),
			ErrorContext: err.Error(),
		}
	}
	if !bytes.Equal(t, token) {
		e := fmt.Sprintf("comment token does not match route token: "+
			"got %x, want %x", t, token)
		return "", backend.PluginUserError{
			PluginID:     comments.ID,
			ErrorCode:    int(comments.ErrorCodeTokenInvalid),
			ErrorContext: e,
		}
	}

	// Verify signature
	msg := e.Token + strconv.FormatUint(uint64(e.ParentID), 10) + e.Comment
	err = util.VerifySignature(e.Signature, e.PublicKey, msg)
	if err != nil {
		return "", convertSignatureError(err)
	}

	// Verify comment
	if len(e.Comment) > comments.PolicyCommentLengthMax {
		return "", backend.PluginUserError{
			PluginID:     comments.ID,
			ErrorCode:    int(comments.ErrorCodeCommentTextInvalid),
			ErrorContext: "exceeds max length",
		}
	}

	// The record index must be pulled and updated. The record lock
	// must be held for the remainder of this function.
	m := p.mutex(token)
	m.Lock()
	defer m.Unlock()

	// Get record index
	ridx, err := p.recordIndexLocked(token)
	if err != nil {
		return "", err
	}

	// Get the existing comment
	cs, err := p.comments(treeID, *ridx, []uint32{e.CommentID})
	if err != nil {
		return "", fmt.Errorf("comments %v: %v", e.CommentID, err)
	}
	existing, ok := cs[e.CommentID]
	if !ok {
		return "", backend.PluginUserError{
			PluginID:  comments.ID,
			ErrorCode: int(comments.ErrorCodeCommentNotFound),
		}
	}

	// Verify the user ID
	if e.UserID != existing.UserID {
		return "", backend.PluginUserError{
			PluginID:  comments.ID,
			ErrorCode: int(comments.ErrorCodeUserUnauthorized),
		}
	}

	// Verify the parent ID
	if e.ParentID != existing.ParentID {
		e := fmt.Sprintf("parent id cannot change; got %v, want %v",
			e.ParentID, existing.ParentID)
		return "", backend.PluginUserError{
			PluginID:     comments.ID,
			ErrorCode:    int(comments.ErrorCodeParentIDInvalid),
			ErrorContext: e,
		}
	}

	// Verify comment changes
	if e.Comment == existing.Comment {
		return "", backend.PluginUserError{
			PluginID:     comments.ID,
			ErrorCode:    int(comments.ErrorCodeCommentTextInvalid),
			ErrorContext: "comment did not change",
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
	merkle, err := p.commentAddSave(treeID, ca)
	if err != nil {
		return "", fmt.Errorf("commentAddSave: %v", err)
	}

	// Update index
	ridx.Comments[ca.CommentID].Adds[ca.Version] = merkle

	// Save index
	err = p.recordIndexSaveLocked(token, *ridx)
	if err != nil {
		return "", err
	}

	log.Debugf("Comment edited on record %v comment ID %v",
		ca.Token, ca.CommentID)

	// Return updated comment
	c, err := p.comment(treeID, *ridx, e.CommentID)
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

func (p *commentsPlugin) cmdDel(treeID int64, token []byte, payload string) (string, error) {
	log.Tracef("cmdDel: %v %x %v", treeID, token, payload)

	// Decode payload
	var d comments.Del
	err := json.Unmarshal([]byte(payload), &d)
	if err != nil {
		return "", err
	}

	// Verify token
	t, err := tokenDecode(d.Token)
	if err != nil {
		return "", backend.PluginUserError{
			PluginID:     comments.ID,
			ErrorCode:    int(comments.ErrorCodeTokenInvalid),
			ErrorContext: err.Error(),
		}
	}
	if !bytes.Equal(t, token) {
		e := fmt.Sprintf("comment token does not match route token: "+
			"got %x, want %x", t, token)
		return "", backend.PluginUserError{
			PluginID:     comments.ID,
			ErrorCode:    int(comments.ErrorCodeTokenInvalid),
			ErrorContext: e,
		}
	}

	// Verify signature
	msg := d.Token + strconv.FormatUint(uint64(d.CommentID), 10) + d.Reason
	err = util.VerifySignature(d.Signature, d.PublicKey, msg)
	if err != nil {
		return "", convertSignatureError(err)
	}

	// The record index must be pulled and updated. The record lock
	// must be held for the remainder of this function.
	m := p.mutex(token)
	m.Lock()
	defer m.Unlock()

	// Get record index
	ridx, err := p.recordIndexLocked(token)
	if err != nil {
		return "", err
	}

	// Get the existing comment
	cs, err := p.comments(treeID, *ridx, []uint32{d.CommentID})
	if err != nil {
		return "", fmt.Errorf("comments %v: %v", d.CommentID, err)
	}
	existing, ok := cs[d.CommentID]
	if !ok {
		return "", backend.PluginUserError{
			PluginID:  comments.ID,
			ErrorCode: int(comments.ErrorCodeCommentNotFound),
		}
	}

	// Prepare comment delete
	receipt := p.identity.SignMessage([]byte(d.Signature))
	cd := comments.CommentDel{
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
	merkle, err := p.commentDelSave(treeID, cd)
	if err != nil {
		return "", fmt.Errorf("commentDelSave: %v", err)
	}

	// Update index
	cidx, ok := ridx.Comments[d.CommentID]
	if !ok {
		// This should not be possible
		e := fmt.Sprintf("comment not found in index: %v", d.CommentID)
		panic(e)
	}
	cidx.Del = merkle
	ridx.Comments[d.CommentID] = cidx

	// Save index
	err = p.recordIndexSaveLocked(token, *ridx)
	if err != nil {
		return "", err
	}

	// Delete all comment versions
	merkles := make([][]byte, 0, len(cidx.Adds))
	for _, v := range cidx.Adds {
		merkles = append(merkles, v)
	}
	err = p.tlog.BlobsDel(treeID, merkles)
	if err != nil {
		return "", fmt.Errorf("del: %v", err)
	}

	// Return updated comment
	c, err := p.comment(treeID, *ridx, d.CommentID)
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

func (p *commentsPlugin) cmdVote(treeID int64, token []byte, payload string) (string, error) {
	log.Tracef("cmdVote: %v %x %v", treeID, token, payload)

	// Decode payload
	var v comments.Vote
	err := json.Unmarshal([]byte(payload), &v)
	if err != nil {
		return "", err
	}

	// Verify token
	t, err := tokenDecode(v.Token)
	if err != nil {
		return "", backend.PluginUserError{
			PluginID:     comments.ID,
			ErrorCode:    int(comments.ErrorCodeTokenInvalid),
			ErrorContext: err.Error(),
		}
	}
	if !bytes.Equal(t, token) {
		e := fmt.Sprintf("comment token does not match route token: "+
			"got %x, want %x", t, token)
		return "", backend.PluginUserError{
			PluginID:     comments.ID,
			ErrorCode:    int(comments.ErrorCodeTokenInvalid),
			ErrorContext: e,
		}
	}

	// Verify vote
	switch v.Vote {
	case comments.VoteDownvote, comments.VoteUpvote:
		// These are allowed
	default:
		return "", backend.PluginUserError{
			PluginID:  comments.ID,
			ErrorCode: int(comments.ErrorCodeVoteInvalid),
		}
	}

	// Verify signature
	msg := v.Token + strconv.FormatUint(uint64(v.CommentID), 10) +
		strconv.FormatInt(int64(v.Vote), 10)
	err = util.VerifySignature(v.Signature, v.PublicKey, msg)
	if err != nil {
		return "", convertSignatureError(err)
	}

	// The record index must be pulled and updated. The record lock
	// must be held for the remainder of this function.
	m := p.mutex(token)
	m.Lock()
	defer m.Unlock()

	// Get record index
	ridx, err := p.recordIndexLocked(token)
	if err != nil {
		return "", err
	}

	// Verify comment exists
	cidx, ok := ridx.Comments[v.CommentID]
	if !ok {
		return "", backend.PluginUserError{
			PluginID:  comments.ID,
			ErrorCode: int(comments.ErrorCodeCommentNotFound),
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
			ErrorCode: int(comments.ErrorCodeVoteChangesMax),
		}
	}

	// Verify user is not voting on their own comment
	cs, err := p.comments(treeID, *ridx, []uint32{v.CommentID})
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
			ErrorCode:    int(comments.ErrorCodeVoteInvalid),
			ErrorContext: "user cannot vote on their own comment",
		}
	}

	// Prepare comment vote
	receipt := p.identity.SignMessage([]byte(v.Signature))
	cv := comments.CommentVote{
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
	merkle, err := p.commentVoteSave(treeID, cv)
	if err != nil {
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

	// Update the record index
	ridx.Comments[cv.CommentID] = cidx

	// Save index
	err = p.recordIndexSaveLocked(token, *ridx)
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
	reply, err := json.Marshal(vr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

func (p *commentsPlugin) cmdGet(treeID int64, token []byte, payload string) (string, error) {
	log.Tracef("cmdGet: %v %x %v", treeID, token, payload)

	// Decode payload
	var g comments.Get
	err := json.Unmarshal([]byte(payload), &g)
	if err != nil {
		return "", err
	}

	// Get record index
	ridx, err := p.recordIndex(token)
	if err != nil {
		return "", err
	}

	// Get comments
	cs, err := p.comments(treeID, *ridx, g.CommentIDs)
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

func (p *commentsPlugin) cmdGetAll(treeID int64, token []byte, payload string) (string, error) {
	log.Tracef("cmdGetAll: %v %x %v", treeID, token, payload)

	// Decode payload
	var ga comments.GetAll
	err := json.Unmarshal([]byte(payload), &ga)
	if err != nil {
		return "", err
	}

	// Compile comment IDs
	ridx, err := p.recordIndex(token)
	if err != nil {
		return "", err
	}
	commentIDs := make([]uint32, 0, len(ridx.Comments))
	for k := range ridx.Comments {
		commentIDs = append(commentIDs, k)
	}

	// Get comments
	c, err := p.comments(treeID, *ridx, commentIDs)
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

func (p *commentsPlugin) cmdGetVersion(treeID int64, token []byte, payload string) (string, error) {
	log.Tracef("cmdGetVersion: %v %x %v", treeID, token, payload)

	// Decode payload
	var gv comments.GetVersion
	err := json.Unmarshal([]byte(payload), &gv)
	if err != nil {
		return "", err
	}

	// Get record index
	ridx, err := p.recordIndex(token)
	if err != nil {
		return "", err
	}

	// Verify comment exists
	cidx, ok := ridx.Comments[gv.CommentID]
	if !ok {
		return "", backend.PluginUserError{
			PluginID:  comments.ID,
			ErrorCode: int(comments.ErrorCodeCommentNotFound),
		}
	}
	if cidx.Del != nil {
		return "", backend.PluginUserError{
			PluginID:     comments.ID,
			ErrorCode:    int(comments.ErrorCodeCommentNotFound),
			ErrorContext: "comment has been deleted",
		}
	}
	merkle, ok := cidx.Adds[gv.Version]
	if !ok {
		e := fmt.Sprintf("comment %v does not have version %v",
			gv.CommentID, gv.Version)
		return "", backend.PluginUserError{
			PluginID:     comments.ID,
			ErrorCode:    int(comments.ErrorCodeCommentNotFound),
			ErrorContext: e,
		}
	}

	// Get comment add record
	adds, err := p.commentAdds(treeID, [][]byte{merkle})
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
	reply, err := json.Marshal(gvr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

func (p *commentsPlugin) cmdCount(treeID int64, token []byte, payload string) (string, error) {
	log.Tracef("cmdCount: %v %x %v", treeID, token, payload)

	// Decode payload
	var c comments.Count
	err := json.Unmarshal([]byte(payload), &c)
	if err != nil {
		return "", err
	}

	// Get record index
	ridx, err := p.recordIndex(token)
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

func (p *commentsPlugin) cmdVotes(treeID int64, token []byte, payload string) (string, error) {
	log.Tracef("cmdVotes: %v %x %v", treeID, token, payload)

	// Decode payload
	var v comments.Votes
	err := json.Unmarshal([]byte(payload), &v)
	if err != nil {
		return "", err
	}

	// Get record index
	ridx, err := p.recordIndex(token)
	if err != nil {
		return "", err
	}

	// Compile the comment vote merkles for all votes that were cast
	// by the specified user.
	merkles := make([][]byte, 0, 256)
	for _, cidx := range ridx.Comments {
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
	votes, err := p.commentVotes(treeID, merkles)
	if err != nil {
		return "", fmt.Errorf("commentVotes: %v", err)
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

func (p *commentsPlugin) cmdTimestamps(treeID int64, token []byte, payload string) (string, error) {
	log.Tracef("cmdTimestamps: %v %x %v", treeID, token, payload)

	// Decode payload
	var t comments.Timestamps
	err := json.Unmarshal([]byte(payload), &t)
	if err != nil {
		return "", err
	}

	// Get record index
	ridx, err := p.recordIndex(token)
	if err != nil {
		return "", err
	}

	// If no comment IDs were given then we need to return the
	// timestamps for all comments.
	if len(t.CommentIDs) == 0 {
		commentIDs := make([]uint32, 0, len(ridx.Comments))
		for k := range ridx.Comments {
			commentIDs = append(commentIDs, k)
		}
		t.CommentIDs = commentIDs
	}

	// Get timestamps
	cmts := make(map[uint32][]comments.Timestamp, len(t.CommentIDs))
	votes := make(map[uint32][]comments.Timestamp, len(t.CommentIDs))
	for _, commentID := range t.CommentIDs {
		cidx, ok := ridx.Comments[commentID]
		if !ok {
			// Comment ID does not exist. Skip it.
			continue
		}

		// Get timestamps for adds
		ts := make([]comments.Timestamp, 0, len(cidx.Adds)+1)
		for _, v := range cidx.Adds {
			t, err := p.timestamp(treeID, v)
			if err != nil {
				return "", err
			}
			ts = append(ts, *t)
		}

		// Get timestamp for del
		if cidx.Del != nil {
			t, err := p.timestamp(treeID, cidx.Del)
			if err != nil {
				return "", err
			}
			ts = append(ts, *t)
		}

		// Save timestamps
		cmts[commentID] = ts

		// Only get the comment vote timestamps if specified
		if !t.IncludeVotes {
			continue
		}

		// Get timestamps for votes
		ts = make([]comments.Timestamp, 0, len(cidx.Votes))
		for _, votes := range cidx.Votes {
			for _, v := range votes {
				t, err := p.timestamp(treeID, v.Merkle)
				if err != nil {
					return "", err
				}
				ts = append(ts, *t)
			}
		}

		// Save timestamps
		votes[commentID] = ts
	}

	// Prepare reply
	ts := comments.TimestampsReply{
		Comments: cmts,
		Votes:    votes,
	}
	reply, err := json.Marshal(ts)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// Setup performs any plugin setup work that needs to be done.
//
// This function satisfies the plugins.Client interface.
func (p *commentsPlugin) Setup() error {
	log.Tracef("Setup")

	return nil
}

// Cmd executes a plugin command.
//
// This function satisfies the plugins.Client interface.
func (p *commentsPlugin) Cmd(treeID int64, token []byte, cmd, payload string) (string, error) {
	log.Tracef("Cmd: %v %v %x %v", treeID, token, cmd, payload)

	switch cmd {
	case comments.CmdNew:
		return p.cmdNew(treeID, token, payload)
	case comments.CmdEdit:
		return p.cmdEdit(treeID, token, payload)
	case comments.CmdDel:
		return p.cmdDel(treeID, token, payload)
	case comments.CmdVote:
		return p.cmdVote(treeID, token, payload)
	case comments.CmdGet:
		return p.cmdGet(treeID, token, payload)
	case comments.CmdGetAll:
		return p.cmdGetAll(treeID, token, payload)
	case comments.CmdGetVersion:
		return p.cmdGetVersion(treeID, token, payload)
	case comments.CmdCount:
		return p.cmdCount(treeID, token, payload)
	case comments.CmdVotes:
		return p.cmdVotes(treeID, token, payload)
	case comments.CmdTimestamps:
		return p.cmdTimestamps(treeID, token, payload)
	}

	return "", backend.ErrPluginCmdInvalid
}

// Hook executes a plugin hook.
//
// This function satisfies the plugins.Client interface.
func (p *commentsPlugin) Hook(h plugins.HookT, payload string) error {
	log.Tracef("Hook: %v", plugins.Hooks[h])

	return nil
}

// Fsck performs a plugin filesystem check.
//
// This function satisfies the plugins.Client interface.
func (p *commentsPlugin) Fsck() error {
	log.Tracef("Fsck")

	// TODO Make sure CommentDel blobs were actually deleted

	return nil
}

// New returns a new comments plugin.
func New(tlog tlogclient.Client, settings []backend.PluginSetting, id *identity.FullIdentity, dataDir string) (*commentsPlugin, error) {
	// Setup comments plugin data dir
	dataDir = filepath.Join(dataDir, comments.ID)
	err := os.MkdirAll(dataDir, 0700)
	if err != nil {
		return nil, err
	}

	return &commentsPlugin{
		tlog:     tlog,
		identity: id,
		dataDir:  dataDir,
		mutexes:  make(map[string]*sync.Mutex),
	}, nil
}
