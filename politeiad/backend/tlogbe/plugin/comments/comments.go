// Copyright (c) 2020 The Decred developers
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
	"sync"
	"time"

	"github.com/decred/politeia/plugins/comments"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe"
	"github.com/decred/politeia/politeiad/backend/tlogbe/plugin"
	"github.com/decred/politeia/politeiad/backend/tlogbe/store"
	"github.com/decred/politeia/util"
)

const (
	// Blob entry data descriptors
	dataDescriptorCommentAdd    = "commentadd"
	dataDescriptorCommentDel    = "commentdel"
	dataDescriptorCommentVote   = "commentvote"
	dataDescriptorCommentsIndex = "commentsindex"

	// Prefixes that are appended to key-value store keys before
	// storing them in the log leaf ExtraData field.
	keyPrefixCommentAdd    = "commentadd:"
	keyPrefixCommentDel    = "commentdel:"
	keyPrefixCommentVote   = "commentvote:"
	keyPrefixCommentsIndex = "commentsindex:"
)

var (
	_ plugin.Plugin = (*commentsPlugin)(nil)
)

type commentsPlugin struct {
	sync.Mutex
	id      *identity.FullIdentity
	backend *tlogbe.Tlogbe

	// Mutexes contains a mutex for each record. The mutexes are lazy
	// loaded.
	mutexes map[string]*sync.Mutex // [string]mutex
}

type voteIndex struct {
	Vote       comments.VoteT `json:"vote"`
	MerkleHash []byte         `json:"merklehash"`
}

type commentIndex struct {
	Adds  map[uint32][]byte `json:"adds"`  // [version]merkleHash
	Del   []byte            `json:"del"`   // Merkle hash of delete record
	Score int64             `json:"score"` // Vote score

	// Votes contains the vote history for each uuid that voted on the
	// comment. This data is memoized because the effect of a new vote
	// on a comment depends on the previous vote from that uuid.
	// Example, a user upvotes a comment that they have already
	// upvoted, the resulting vote score is 0 due to the second upvote
	// removing the original upvote.
	Votes map[string][]voteIndex `json:"votes"` // [uuid]votes
}

// TODO this is not very efficient and probably needs to be improved.
// It duplicates a lot of data and requires fetching all the tree
// leaves to get. This may be problematic when there are 20,000 vote
// leaves and you just want to get the comments count for a record.
type index struct {
	Comments map[uint32]commentIndex `json:"comments"` // [commentID]comment
}

// TODO this needs to go in util
func verifySignature(signature, pubkey, msg string) error {
	sig, err := util.ConvertSignature(signature)
	if err != nil {
		return comments.UserError{
			ErrorCode:    comments.ErrorStatusSignatureInvalid,
			ErrorContext: []string{err.Error()},
		}
	}
	b, err := hex.DecodeString(pubkey)
	if err != nil {
		return comments.UserError{
			ErrorCode:    comments.ErrorStatusPublicKeyInvalid,
			ErrorContext: []string{"key is not hex"},
		}
	}
	pk, err := identity.PublicIdentityFromBytes(b)
	if err != nil {
		return comments.UserError{
			ErrorCode:    comments.ErrorStatusPublicKeyInvalid,
			ErrorContext: []string{err.Error()},
		}
	}
	if !pk.VerifyMessage([]byte(msg), sig) {
		return comments.UserError{
			ErrorCode:    comments.ErrorStatusSignatureInvalid,
			ErrorContext: []string{err.Error()},
		}
	}
	return nil
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

func convertBlobEntryFromCommentAdd(c commentAdd) (*store.BlobEntry, error) {
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
	be := store.BlobEntryNew(hint, data)
	return &be, nil
}

func convertBlobEntryFromCommentDel(c commentDel) (*store.BlobEntry, error) {
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
	be := store.BlobEntryNew(hint, data)
	return &be, nil
}

func convertBlobEntryFromCommentVote(c commentVote) (*store.BlobEntry, error) {
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
	be := store.BlobEntryNew(hint, data)
	return &be, nil
}

func convertBlobEntryFromIndex(idx index) (*store.BlobEntry, error) {
	data, err := json.Marshal(idx)
	if err != nil {
		return nil, err
	}
	hint, err := json.Marshal(
		store.DataDescriptor{
			Type:       store.DataTypeStructure,
			Descriptor: dataDescriptorCommentsIndex,
		})
	if err != nil {
		return nil, err
	}
	be := store.BlobEntryNew(hint, data)
	return &be, nil
}

func convertCommentAddFromBlobEntry(be store.BlobEntry) (*commentAdd, error) {
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
	var c commentAdd
	err = json.Unmarshal(b, &c)
	if err != nil {
		return nil, fmt.Errorf("unmarshal index: %v", err)
	}

	return &c, nil
}

func convertIndexFromBlobEntry(be store.BlobEntry) (*index, error) {
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
	if dd.Descriptor != dataDescriptorCommentsIndex {
		return nil, fmt.Errorf("unexpected data descriptor: got %v, want %v",
			dd.Descriptor, dataDescriptorCommentsIndex)
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
	var idx index
	err = json.Unmarshal(b, &idx)
	if err != nil {
		return nil, fmt.Errorf("unmarshal index: %v", err)
	}

	return &idx, nil
}

func convertCommentFromCommentAdd(ca commentAdd) comments.Comment {
	// Score needs to be filled in seperately
	return comments.Comment{
		Token:     ca.Token,
		ParentID:  ca.ParentID,
		Comment:   ca.Comment,
		PublicKey: ca.PublicKey,
		Signature: ca.Signature,
		CommentID: ca.CommentID,
		Version:   ca.Version,
		Receipt:   ca.Receipt,
		Timestamp: ca.Timestamp,
		Score:     0,
		Deleted:   false,
	}
}

func commentAddSave(client *tlogbe.PluginClient, c commentAdd, encrypt bool) ([]byte, error) {
	// Prepare blob
	be, err := convertBlobEntryFromCommentAdd(c)
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

	// Save blob
	merkles, err := client.BlobsSave(keyPrefixCommentAdd,
		[][]byte{b}, [][]byte{h}, encrypt)
	if err != nil {
		return nil, fmt.Errorf("BlobsSave: %v", err)
	}
	if len(merkles) != 1 {
		return nil, fmt.Errorf("invalid merkle leaf hash count; got %v, want 1",
			len(merkles))
	}

	return merkles[0], nil
}

func commentAdds(client *tlogbe.PluginClient, merkleHashes [][]byte) ([]commentAdd, error) {
	// Retrieve blobs
	blobs, err := client.BlobsByMerkleHash(merkleHashes)
	if err != nil {
		return nil, err
	}
	if len(blobs) != len(merkleHashes) {
		notFound := make([]string, 0, len(blobs))
		for _, v := range merkleHashes {
			m := hex.EncodeToString(v)
			_, ok := blobs[m]
			if !ok {
				notFound = append(notFound, m)
			}
		}
		return nil, fmt.Errorf("blobs not found: %v", notFound)
	}

	// Decode blobs
	adds := make([]commentAdd, 0, len(blobs))
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

func commentDelSave(client *tlogbe.PluginClient, c commentDel) ([]byte, error) {
	// Prepare blob
	be, err := convertBlobEntryFromCommentDel(c)
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

	// Save blob
	merkles, err := client.BlobsSave(keyPrefixCommentDel,
		[][]byte{b}, [][]byte{h}, false)
	if err != nil {
		return nil, fmt.Errorf("BlobsSave: %v", err)
	}
	if len(merkles) != 1 {
		return nil, fmt.Errorf("invalid merkle leaf hash count; got %v, want 1",
			len(merkles))
	}

	return merkles[0], nil
}

func commentVoteSave(client *tlogbe.PluginClient, c commentVote) ([]byte, error) {
	// Prepare blob
	be, err := convertBlobEntryFromCommentVote(c)
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

	// Save blob
	merkles, err := client.BlobsSave(keyPrefixCommentAdd,
		[][]byte{b}, [][]byte{h}, false)
	if err != nil {
		return nil, fmt.Errorf("BlobsSave: %v", err)
	}
	if len(merkles) != 1 {
		return nil, fmt.Errorf("invalid merkle leaf hash count; got %v, want 1",
			len(merkles))
	}

	return merkles[0], nil
}

func indexSave(client *tlogbe.PluginClient, idx index) error {
	// Prepare blob
	be, err := convertBlobEntryFromIndex(idx)
	if err != nil {
		return err
	}
	h, err := hex.DecodeString(be.Hash)
	if err != nil {
		return err
	}
	b, err := store.Blobify(*be)
	if err != nil {
		return err
	}

	// Save blob
	merkles, err := client.BlobsSave(keyPrefixCommentsIndex,
		[][]byte{b}, [][]byte{h}, false)
	if err != nil {
		return fmt.Errorf("BlobsSave: %v", err)
	}
	if len(merkles) != 1 {
		return fmt.Errorf("invalid merkle leaf hash count; got %v, want 1",
			len(merkles))
	}

	return nil
}

func indexLatest(client *tlogbe.PluginClient) (*index, error) {
	// Get all comment indexes
	blobs, err := client.BlobsByKeyPrefix(keyPrefixCommentsIndex)
	if err != nil {
		return nil, err
	}
	if len(blobs) == 0 {
		// A comments index does not exist. This can happen when no
		// comments have been made on the record yet. Return a new one.
		return &index{
			Comments: make(map[uint32]commentIndex),
		}, nil
	}

	// Decode the most recent index
	b := blobs[len(blobs)-1]
	be, err := store.Deblob(b)
	if err != nil {
		return nil, err
	}
	return convertIndexFromBlobEntry(*be)
}

func commentIDLatest(idx index) uint32 {
	var maxID uint32
	for id := range idx.Comments {
		if id > maxID {
			maxID = id
		}
	}
	return maxID
}

func commentVersionLatest(cidx commentIndex) uint32 {
	var maxVersion uint32
	for version := range cidx.Adds {
		if version > maxVersion {
			maxVersion = version
		}
	}
	return maxVersion
}

func commentExists(idx index, commentID uint32) bool {
	_, ok := idx.Comments[commentID]
	return ok
}

// commentsLatest returns the most recent version of the specified comments.
// Deleted comments are returned with limited data. Comment IDs that do not
// correspond to an actual comment are not included in the returned map. It is
// the responsibility of the caller to ensure a comment is returned for each of
// the provided comment IDs. The comments index that was looked up during this
// process is also returned.
func commentsLatest(client *tlogbe.PluginClient, commentIDs []uint32) (map[uint32]comments.Comment, *index, error) {
	// Get comments index
	idx, err := indexLatest(client)
	if err != nil {
		return nil, nil, fmt.Errorf("indexLatest: %v", err)
	}

	// Aggregate merkle hashes of the comment add records that need to
	// be looked up. If the comment has been deleted then there is
	// nothing to look up.
	var (
		merkles = make([][]byte, 0, len(commentIDs))
		dels    = make([]uint32, 0, len(commentIDs))
	)
	for _, v := range commentIDs {
		cidx, ok := idx.Comments[v]
		if !ok {
			// Comment does not exist
			continue
		}
		if cidx.Del != nil {
			// Comment has been deleted
			dels = append(dels, v)
			continue
		}

		// Save the merkle hash for the latest version
		version := commentVersionLatest(cidx)
		merkles = append(merkles, cidx.Adds[version])
	}

	// Get comment add records
	adds, err := commentAdds(client, merkles)
	if err != nil {
		return nil, nil, fmt.Errorf("commentAdds: %v", err)
	}
	if len(adds) != len(merkles) {
		return nil, nil, fmt.Errorf("wrong comment adds count; got %v, want %v",
			len(adds), len(merkles))
	}

	// Prepare comments
	cs := make(map[uint32]comments.Comment, len(commentIDs))
	for _, v := range adds {
		c := convertCommentFromCommentAdd(v)
		c.Score = idx.Comments[c.CommentID].Score
		cs[v.CommentID] = c
	}
	for _, commentID := range dels {
		score := idx.Comments[commentID].Score
		cs[commentID] = comments.Comment{
			Token:     hex.EncodeToString(client.Token),
			CommentID: commentID,
			Score:     score,
			Deleted:   true,
		}
	}

	return cs, idx, nil
}

// This function must be called WITH the record lock held.
func (p *commentsPlugin) new(client *tlogbe.PluginClient, n comments.New, encrypt bool) (*comments.NewReply, error) {
	// Pull comments index
	idx, err := indexLatest(client)
	if err != nil {
		return nil, err
	}

	// Ensure parent comment exists if set. A parent ID of 0 means that
	// this is a base level comment, not a reply to another comment.
	if n.ParentID > 0 && !commentExists(*idx, n.ParentID) {
		return nil, comments.UserError{
			ErrorCode:    comments.ErrorStatusParentIDInvalid,
			ErrorContext: []string{"comment not found"},
		}
	}

	// Setup comment
	receipt := p.id.SignMessage([]byte(n.Signature))
	c := commentAdd{
		Token:     n.Token,
		ParentID:  n.ParentID,
		Comment:   n.Comment,
		PublicKey: n.PublicKey,
		Signature: n.Signature,
		CommentID: commentIDLatest(*idx) + 1,
		Version:   1,
		Receipt:   hex.EncodeToString(receipt[:]),
		Timestamp: time.Now().Unix(),
	}

	// Save comment
	merkleHash, err := commentAddSave(client, c, encrypt)
	if err != nil {
		return nil, fmt.Errorf("commentSave: %v", err)
	}

	// Update index
	idx.Comments[c.CommentID] = commentIndex{
		Adds: map[uint32][]byte{
			1: merkleHash,
		},
		Del:   nil,
		Votes: make(map[string][]voteIndex),
	}

	// Save index
	err = indexSave(client, *idx)
	if err != nil {
		return nil, fmt.Errorf("indexSave: %v", err)
	}

	log.Debugf("Comment saved to record %v comment ID %v",
		c.Token, c.CommentID)

	return &comments.NewReply{
		CommentID: c.CommentID,
		Receipt:   c.Receipt,
		Timestamp: c.Timestamp,
	}, nil
}

func (p *commentsPlugin) cmdNew(payload string) (string, error) {
	log.Tracef("comments cmdNew: %v", payload)

	// Decode payload
	n, err := comments.DecodeNew([]byte(payload))
	if err != nil {
		return "", err
	}

	// Verify signature
	msg := n.Token + strconv.FormatUint(uint64(n.ParentID), 10) + n.Comment
	err = verifySignature(n.Signature, n.PublicKey, msg)
	if err != nil {
		return "", err
	}

	// Get plugin client
	token, err := hex.DecodeString(n.Token)
	if err != nil {
		return "", comments.UserError{
			ErrorCode: comments.ErrorStatusTokenInvalid,
		}
	}
	client, err := p.backend.PluginClient(token)
	if err != nil {
		if err == backend.ErrRecordNotFound {
			return "", comments.UserError{
				ErrorCode: comments.ErrorStatusRecordNotFound,
			}
		}
		return "", err
	}

	// The comments index must be pulled and updated. The record lock
	// must be held for the remainder of this function.
	m := p.mutex(n.Token)
	m.Lock()
	defer m.Unlock()

	// Save new comment
	var nr *comments.NewReply
	switch client.State {
	case tlogbe.RecordStateUnvetted:
		nr, err = p.new(client, *n, true)
		if err != nil {
			return "", err
		}
	case tlogbe.RecordStateVetted:
		nr, err = p.new(client, *n, false)
		if err != nil {
			return "", err
		}
	default:
		return "", fmt.Errorf("invalid record state %v", client.State)
	}

	// Prepare reply
	reply, err := comments.EncodeNewReply(*nr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// This function must be called WITH the record lock held.
func (p *commentsPlugin) edit(client *tlogbe.PluginClient, e comments.Edit, encrypt bool) (*comments.EditReply, error) {
	// Get the existing comment
	cs, idx, err := commentsLatest(client, []uint32{e.CommentID})
	if err != nil {
		return nil, fmt.Errorf("commentsLatest %v: %v", e.CommentID, err)
	}
	existing, ok := cs[e.CommentID]
	if !ok {
		return nil, comments.UserError{
			ErrorCode: comments.ErrorStatusCommentNotFound,
		}
	}

	// Validate the comment edit. The parent ID must remain the same.
	// The comment text must be different.
	if e.ParentID != existing.ParentID {
		e := fmt.Sprintf("parent id cannot change; got %v, want %v",
			e.ParentID, existing.ParentID)
		return nil, comments.UserError{
			ErrorCode:    comments.ErrorStatusParentIDInvalid,
			ErrorContext: []string{e},
		}
	}
	if e.Comment == existing.Comment {
		return nil, comments.UserError{
			ErrorCode: comments.ErrorStatusNoCommentChanges,
		}
	}

	// Create a new comment version
	receipt := p.id.SignMessage([]byte(e.Signature))
	c := commentAdd{
		Token:     e.Token,
		ParentID:  e.ParentID,
		Comment:   e.Comment,
		PublicKey: e.PublicKey,
		Signature: e.Signature,
		CommentID: e.CommentID,
		Version:   existing.Version + 1,
		Receipt:   hex.EncodeToString(receipt[:]),
		Timestamp: time.Now().Unix(),
	}

	// Save comment
	merkleHash, err := commentAddSave(client, c, encrypt)
	if err != nil {
		return nil, fmt.Errorf("commentSave: %v", err)
	}

	// Update index
	idx.Comments[c.CommentID].Adds[c.Version] = merkleHash

	// Save index
	err = indexSave(client, *idx)
	if err != nil {
		return nil, fmt.Errorf("indexSave: %v", err)
	}

	log.Debugf("Comment edited on record %v comment ID %v",
		c.Token, c.CommentID)

	return &comments.EditReply{
		Version:   c.Version,
		Receipt:   c.Receipt,
		Timestamp: c.Timestamp,
	}, nil
}

func (p *commentsPlugin) cmdEdit(payload string) (string, error) {
	log.Tracef("comments cmdEdit: %v", payload)

	// Decode payload
	e, err := comments.DecodeEdit([]byte(payload))
	if err != nil {
		return "", err
	}

	// Verify signature
	msg := e.Token + strconv.FormatUint(uint64(e.ParentID), 10) + e.Comment
	err = verifySignature(e.Signature, e.PublicKey, msg)
	if err != nil {
		return "", err
	}

	// Get plugin client
	token, err := hex.DecodeString(e.Token)
	if err != nil {
		return "", comments.UserError{
			ErrorCode: comments.ErrorStatusTokenInvalid,
		}
	}
	client, err := p.backend.PluginClient(token)
	if err != nil {
		if err == backend.ErrRecordNotFound {
			return "", comments.UserError{
				ErrorCode: comments.ErrorStatusRecordNotFound,
			}
		}
		return "", err
	}

	// The existing comment must be pulled to validate the edit. The
	// record lock must be held for the remainder of this function.
	m := p.mutex(e.Token)
	m.Lock()
	defer m.Unlock()

	// Edit comment
	var er *comments.EditReply
	switch client.State {
	case tlogbe.RecordStateUnvetted:
		er, err = p.edit(client, *e, true)
		if err != nil {
			return "", err
		}
	case tlogbe.RecordStateVetted:
		er, err = p.edit(client, *e, false)
		if err != nil {
			return "", err
		}
	default:
		return "", fmt.Errorf("invalid record state %v", client.State)
	}

	// Prepare reply
	reply, err := comments.EncodeEditReply(*er)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// This function must be called WITH the record lock held.
func (p *commentsPlugin) del(client *tlogbe.PluginClient, d comments.Del) (*comments.DelReply, error) {
	// Get comments index
	idx, err := indexLatest(client)
	if err != nil {
		return nil, err
	}

	// Ensure comment exists
	cidx, ok := idx.Comments[d.CommentID]
	if !ok {
		return nil, comments.UserError{
			ErrorCode: comments.ErrorStatusCommentNotFound,
		}
	}

	// Save delete record
	receipt := p.id.SignMessage([]byte(d.Signature))
	cd := commentDel{
		Token:     d.Token,
		CommentID: d.CommentID,
		Reason:    d.Reason,
		PublicKey: d.PublicKey,
		Signature: d.Signature,
		Receipt:   hex.EncodeToString(receipt[:]),
		Timestamp: time.Now().Unix(),
	}
	merkleHash, err := commentDelSave(client, cd)
	if err != nil {
		return nil, fmt.Errorf("commentDelSave: %v", err)
	}

	// Update index
	cidx.Del = merkleHash
	idx.Comments[d.CommentID] = cidx

	// Save index
	err = indexSave(client, *idx)
	if err != nil {
		return nil, fmt.Errorf("indexSave: %v", err)
	}

	// Delete all comment versions
	merkles := make([][]byte, 0, len(cidx.Adds))
	for _, v := range cidx.Adds {
		merkles = append(merkles, v)
	}
	err = client.BlobsDel(merkles)
	if err != nil {
		return nil, fmt.Errorf("BlobsDel: %v", err)
	}

	return &comments.DelReply{
		Receipt:   cd.Receipt,
		Timestamp: cd.Timestamp,
	}, nil
}

func (p *commentsPlugin) cmdDel(payload string) (string, error) {
	log.Tracef("comments cmdDel: %v", payload)

	// Decode payload
	d, err := comments.DecodeDel([]byte(payload))
	if err != nil {
		return "", err
	}

	// Verify signature
	msg := d.Token + strconv.FormatUint(uint64(d.CommentID), 10) + d.Reason
	err = verifySignature(d.Signature, d.PublicKey, msg)
	if err != nil {
		return "", err
	}

	// Get plugin client
	token, err := hex.DecodeString(d.Token)
	if err != nil {
		return "", comments.UserError{
			ErrorCode: comments.ErrorStatusTokenInvalid,
		}
	}
	client, err := p.backend.PluginClient(token)
	if err != nil {
		if err == backend.ErrRecordNotFound {
			return "", comments.UserError{
				ErrorCode: comments.ErrorStatusRecordNotFound,
			}
		}
		return "", err
	}

	// The comments index must be pulled and updated. The record lock
	// must be held for the remainder of this function.
	m := p.mutex(d.Token)
	m.Lock()
	defer m.Unlock()

	// Delete comment
	cr, err := p.del(client, *d)
	if err != nil {
		return "", err
	}

	// Prepare reply
	reply, err := comments.EncodeDelReply(*cr)
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

	// Get plugin client
	token, err := hex.DecodeString(g.Token)
	if err != nil {
		return "", comments.UserError{
			ErrorCode: comments.ErrorStatusTokenInvalid,
		}
	}
	client, err := p.backend.PluginClient(token)
	if err != nil {
		if err == backend.ErrRecordNotFound {
			return "", comments.UserError{
				ErrorCode: comments.ErrorStatusRecordNotFound,
			}
		}
		return "", err
	}

	// Get comments
	cs, _, err := commentsLatest(client, g.CommentIDs)
	if err != nil {
		return "", fmt.Errorf("commentsLatest: %v", err)
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

	// Get plugin client
	token, err := hex.DecodeString(ga.Token)
	if err != nil {
		return "", comments.UserError{
			ErrorCode: comments.ErrorStatusTokenInvalid,
		}
	}
	client, err := p.backend.PluginClient(token)
	if err != nil {
		if err == backend.ErrRecordNotFound {
			return "", comments.UserError{
				ErrorCode: comments.ErrorStatusRecordNotFound,
			}
		}
		return "", err
	}

	// Get comments index
	idx, err := indexLatest(client)
	if err != nil {
		return "", fmt.Errorf("indexLatest: %v", err)
	}

	// Aggregate merkle hashes of the comment add records that need to
	// be looked up. If the comment has been deleted then there is
	// nothing to look up.
	var (
		merkles = make([][]byte, 0, len(idx.Comments))
		dels    = make([]uint32, 0, len(idx.Comments))
	)
	for k, v := range idx.Comments {
		if v.Del != nil {
			// Comment has been deleted
			dels = append(dels, k)
			continue
		}

		// Save the merkle hash for the latest version
		version := commentVersionLatest(v)
		merkles = append(merkles, v.Adds[version])
	}

	// Get comment add records
	adds, err := commentAdds(client, merkles)
	if err != nil {
		return "", fmt.Errorf("commentAdds: %v", err)
	}
	if len(adds) != len(merkles) {
		return "", fmt.Errorf("wrong comment adds count; got %v, want %v",
			len(adds), len(merkles))
	}

	// Prepare comments
	cs := make([]comments.Comment, 0, len(idx.Comments))
	for _, v := range adds {
		c := convertCommentFromCommentAdd(v)
		c.Score = idx.Comments[c.CommentID].Score
		cs = append(cs, c)
	}
	for _, commentID := range dels {
		score := idx.Comments[commentID].Score
		cs = append(cs, comments.Comment{
			Token:     hex.EncodeToString(client.Token),
			CommentID: commentID,
			Score:     score,
			Deleted:   true,
		})
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

	// Get plugin client
	token, err := hex.DecodeString(gv.Token)
	if err != nil {
		return "", comments.UserError{
			ErrorCode: comments.ErrorStatusTokenInvalid,
		}
	}
	client, err := p.backend.PluginClient(token)
	if err != nil {
		if err == backend.ErrRecordNotFound {
			return "", comments.UserError{
				ErrorCode: comments.ErrorStatusRecordNotFound,
			}
		}
		return "", err
	}

	// Get comments index
	idx, err := indexLatest(client)
	if err != nil {
		return "", fmt.Errorf("indexLatest: %v", err)
	}

	// Ensure comment exists
	cidx, ok := idx.Comments[gv.CommentID]
	if !ok {
		return "", comments.UserError{
			ErrorCode: comments.ErrorStatusCommentNotFound,
		}
	}
	merkleHash, ok := cidx.Adds[gv.Version]
	if !ok {
		e := fmt.Sprintf("comment %v does not have version %v",
			gv.CommentID, gv.Version)
		return "", comments.UserError{
			ErrorCode:    comments.ErrorStatusCommentNotFound,
			ErrorContext: []string{e},
		}
	}

	// Get comment add record
	adds, err := commentAdds(client, [][]byte{merkleHash})
	if err != nil {
		return "", fmt.Errorf("commentAdds: %v", err)
	}
	if len(adds) != 1 {
		return "", fmt.Errorf("wrong comment adds count; got %v, want 1",
			len(adds))
	}

	// Convert to a comment
	c := convertCommentFromCommentAdd(adds[0])
	c.Score = cidx.Score

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

	// Get plugin client
	token, err := hex.DecodeString(c.Token)
	if err != nil {
		return "", comments.UserError{
			ErrorCode: comments.ErrorStatusTokenInvalid,
		}
	}
	client, err := p.backend.PluginClient(token)
	if err != nil {
		if err == backend.ErrRecordNotFound {
			return "", comments.UserError{
				ErrorCode: comments.ErrorStatusRecordNotFound,
			}
		}
		return "", err
	}

	// Get comments index
	idx, err := indexLatest(client)
	if err != nil {
		return "", fmt.Errorf("indexLatest: %v", err)
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

// indexAddCommentVote adds the provided comment vote to the index and
// calculates the new vote score. The updated index is returned. The effect of
// a new vote on a comment depends on the previous vote from that uuid.
// Example, a user upvotes a comment that they have already upvoted, the
// resulting vote score is 0 due to the second upvote removing the original
// upvote.
func indexAddCommentVote(idx index, cv commentVote, merkleHash []byte) index {
	// Get the existing votes for this uuid
	cidx := idx.Comments[cv.CommentID]
	votes, ok := cidx.Votes[cv.UUID]
	if !ok {
		// This uuid has not cast any votes
		votes = make([]voteIndex, 0, 1)
	}

	// Get the previous vote that this uuid made
	var votePrev comments.VoteT
	if len(votes) != 0 {
		prev = votes[len(votes)-1].Vote
	}

	// Update index vote score
	voteNew := comments.VoteT(cv.Vote)
	switch {
	case votePrev == 0:
		// No previous vote. Add the new vote to the score.
		cidx.Score += int64(voteNew)

	case voteNew == votePrev:
		// New vote is the same as the previous vote. Remove the previous
		// vote from the score.
		cidx.Score -= int64(votePrev)

	case voteNew != votePrev:
		// New vote is different than the previous vote. Remove the
		// previous vote from the score and add the new vote to the
		// score.
		cidx.Score -= int64(votePrev)
		cidx.Score += int64(voteNew)
	}

	// Update the index
	votes = append(votes, voteIndex{
		Vote:       comments.VoteT(cv.Vote),
		MerkleHash: merkleHash,
	})
	cidx.Votes[cv.UUID] = votes
	idx.Comments[cv.CommentID] = cidx

	return idx
}

func (p *commentsPlugin) cmdVote(payload string) (string, error) {
	log.Tracef("comments cmdVote: %v", payload)

	// Decode payload
	v, err := comments.DecodeVote([]byte(payload))
	if err != nil {
		return "", err
	}

	// Validate vote
	switch v.Vote {
	case comments.VoteDownvote:
		// This is allowed
	case comments.VoteUpvote:
		// This is allowed
	default:
		return "", comments.UserError{
			ErrorCode: comments.ErrorStatusVoteInvalid,
		}
	}

	// Validate signature
	msg := v.Token + strconv.FormatUint(uint64(v.CommentID), 10) +
		strconv.FormatInt(int64(v.Vote), 10)
	err = verifySignature(v.Signature, v.PublicKey, msg)
	if err != nil {
		return "", err
	}

	// Get plugin client
	token, err := hex.DecodeString(v.Token)
	if err != nil {
		return "", comments.UserError{
			ErrorCode: comments.ErrorStatusTokenInvalid,
		}
	}
	client, err := p.backend.PluginClient(token)
	if err != nil {
		if err == backend.ErrRecordNotFound {
			return "", comments.UserError{
				ErrorCode: comments.ErrorStatusRecordNotFound,
			}
		}
		return "", err
	}

	// The comments index must be pulled and updated. The record lock
	// must be held for the remainder of this function.
	m := p.mutex(v.Token)
	m.Lock()
	defer m.Unlock()

	// Get comments index
	idx, err := indexLatest(client)
	if err != nil {
		return "", fmt.Errorf("indexLatest: %v", err)
	}

	// Ensure comment exists
	cidx, ok := idx.Comments[v.CommentID]
	if !ok {
		return "", comments.UserError{
			ErrorCode: comments.ErrorStatusCommentNotFound,
		}
	}

	// Ensure user has not exceeded max allowed vote changes
	uvotes, ok := cidx.Votes[v.UUID]
	if !ok {
		uvotes = make([]voteIndex, 0)
	}
	if len(uvotes) > comments.PolicyMaxVoteChanges {
		return "", comments.UserError{
			ErrorCode: comments.ErrorStatusMaxVoteChanges,
		}
	}

	// Prepare comment vote
	receipt := p.id.SignMessage([]byte(v.Signature))
	cv := commentVote{
		UUID:      v.UUID,
		Token:     v.Token,
		CommentID: v.CommentID,
		Vote:      int64(v.Vote),
		PublicKey: v.PublicKey,
		Signature: v.Signature,
		Receipt:   hex.EncodeToString(receipt[:]),
		Timestamp: time.Now().Unix(),
	}

	// Save comment vote
	merkleHash, err := commentVoteSave(client, cv)
	if err != nil {
		return "", fmt.Errorf("commentVoteSave: %v", err)
	}

	// Update index
	updatedIdx := indexAddCommentVote(*idx, cv, merkleHash)

	// Save index
	err = indexSave(client, updatedIdx)
	if err != nil {
		return "", fmt.Errorf("indexSave: %v", err)
	}

	// Prepare reply
	vr := comments.VoteReply{
		Receipt:   cv.Receipt,
		Timestamp: cv.Timestamp,
		Score:     updatedIdx.Comments[cv.CommentID].Score,
	}
	reply, err := comments.EncodeVoteReply(vr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

func (p *commentsPlugin) cmdProofs(payload string) (string, error) {
	log.Tracef("comments cmdProof: %v", payload)
	return "", nil
}

// Cmd executes a plugin command.
func (p *commentsPlugin) Cmd(cmd, payload string) (string, error) {
	log.Tracef("comments Cmd: %v", cmd)

	switch cmd {
	case comments.CmdNew:
		return p.cmdNew(payload)
	case comments.CmdEdit:
		return p.cmdEdit(payload)
	case comments.CmdDel:
		return p.cmdDel(payload)
	case comments.CmdGet:
		return p.cmdGet(payload)
	case comments.CmdGetAll:
		return p.cmdGetAll(payload)
	case comments.CmdGetVersion:
		return p.cmdGetVersion(payload)
	case comments.CmdCount:
		return p.cmdCount(payload)
	case comments.CmdVote:
		return p.cmdVote(payload)
	case comments.CmdProofs:
		return p.cmdProofs(payload)
	}

	return "", plugin.ErrInvalidPluginCmd
}

// Hook executes a plugin hook.
func (p *commentsPlugin) Hook(h plugin.HookT, payload string) error {
	log.Tracef("comments: Hook: %v", plugin.Hook[h])
	return nil
}

// Fsck performs a plugin filesystem check.
func (p *commentsPlugin) Fsck() error {
	log.Tracef("comments: Fsck")

	// Make sure commentDel blobs were actually deleted

	return nil
}

// Setup performs any plugin setup work that needs to be done.
func (p *commentsPlugin) Setup() error {
	log.Tracef("comments: Setup")
	return nil
}

// New returns a new comments plugin.
func New(id *identity.FullIdentity, backend *tlogbe.Tlogbe) (*commentsPlugin, error) {
	return &commentsPlugin{
		id:      id,
		backend: backend,
		mutexes: make(map[string]*sync.Mutex),
	}, nil
}
