// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package plugins

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/decred/politeia/plugins/comments"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe"
	"github.com/decred/politeia/politeiad/backend/tlogbe/store"
	"github.com/decred/politeia/util"
)

// TODO don't save data to the file system. Save it to the kv store and save
// the key to the file system. This will allow the data to be backed up.

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
	_ tlogbe.Plugin = (*commentsPlugin)(nil)
)

// commentsPlugin satisfies the Plugin interface.
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

func convertCommentsErrFromSignatureErr(err error) comments.UserError {
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
	return comments.UserError{
		ErrorCode:    s,
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
	be := store.BlobEntryNew(hint, data)
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
	be := store.BlobEntryNew(hint, data)
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

func convertCommentFromCommentAdd(ca comments.CommentAdd) comments.Comment {
	// Score needs to be filled in seperately
	return comments.Comment{
		Token:     ca.Token,
		ParentID:  ca.ParentID,
		Comment:   ca.Comment,
		PublicKey: ca.PublicKey,
		Signature: ca.Signature,
		CommentID: ca.CommentID,
		Version:   ca.Version,
		Timestamp: ca.Timestamp,
		Receipt:   ca.Receipt,
		Score:     0,
		Deleted:   false,
		Reason:    "",
	}
}

func convertCommentFromCommentDel(cd comments.CommentDel) comments.Comment {
	// Score needs to be filled in seperately
	return comments.Comment{
		Token:     cd.Token,
		ParentID:  cd.ParentID,
		Comment:   "",
		PublicKey: cd.AuthorPublicKey,
		Signature: "",
		CommentID: cd.CommentID,
		Version:   0,
		Timestamp: cd.Timestamp,
		Receipt:   "",
		Score:     0,
		Deleted:   true,
		Reason:    cd.Reason,
	}
}

func commentAddSave(client *tlogbe.RecordClient, c comments.CommentAdd, encrypt bool) ([]byte, error) {
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
	merkles, err := client.Save(keyPrefixCommentAdd,
		[][]byte{b}, [][]byte{h}, encrypt)
	if err != nil {
		return nil, fmt.Errorf("Save: %v", err)
	}
	if len(merkles) != 1 {
		return nil, fmt.Errorf("invalid merkle leaf hash count; got %v, want 1",
			len(merkles))
	}

	return merkles[0], nil
}

func commentAdds(client *tlogbe.RecordClient, merkleHashes [][]byte) ([]comments.CommentAdd, error) {
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

func commentDelSave(client *tlogbe.RecordClient, c comments.CommentDel) ([]byte, error) {
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
	merkles, err := client.Save(keyPrefixCommentDel,
		[][]byte{b}, [][]byte{h}, false)
	if err != nil {
		return nil, fmt.Errorf("Save: %v", err)
	}
	if len(merkles) != 1 {
		return nil, fmt.Errorf("invalid merkle leaf hash count; got %v, want 1",
			len(merkles))
	}

	return merkles[0], nil
}

func commentDels(client *tlogbe.RecordClient, merkleHashes [][]byte) ([]comments.CommentDel, error) {
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

func commentVoteSave(client *tlogbe.RecordClient, c comments.CommentVote) ([]byte, error) {
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
	merkles, err := client.Save(keyPrefixCommentAdd,
		[][]byte{b}, [][]byte{h}, false)
	if err != nil {
		return nil, fmt.Errorf("Save: %v", err)
	}
	if len(merkles) != 1 {
		return nil, fmt.Errorf("invalid merkle leaf hash count; got %v, want 1",
			len(merkles))
	}

	return merkles[0], nil
}

func indexSave(client *tlogbe.RecordClient, idx index) error {
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
	merkles, err := client.Save(keyPrefixCommentsIndex,
		[][]byte{b}, [][]byte{h}, false)
	if err != nil {
		return fmt.Errorf("Save: %v", err)
	}
	if len(merkles) != 1 {
		return fmt.Errorf("invalid merkle leaf hash count; got %v, want 1",
			len(merkles))
	}

	return nil
}

// indexAddCommentVote adds the provided comment vote to the index and
// calculates the new vote score. The updated index is returned. The effect of
// a new vote on a comment depends on the previous vote from that uuid.
// Example, a user upvotes a comment that they have already upvoted, the
// resulting vote score is 0 due to the second upvote removing the original
// upvote.
func indexAddCommentVote(idx index, cv comments.CommentVote, merkleHash []byte) index {
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
		votePrev = votes[len(votes)-1].Vote
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

func indexLatest(client *tlogbe.RecordClient) (*index, error) {
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
func commentsLatest(client *tlogbe.RecordClient, idx index, commentIDs []uint32) (map[uint32]comments.Comment, error) {
	// Aggregate the merkle hashes for all records that need to be
	// looked up. If a comment has been deleted then the only record
	// that will still exist is the comment del record. If the comment
	// has not been deleted then the comment add record will need to be
	// retrieved for the latest version of the comment.
	var (
		merklesAdd = make([][]byte, 0, len(commentIDs))
		merklesDel = make([][]byte, 0, len(commentIDs))
	)
	for _, v := range commentIDs {
		cidx, ok := idx.Comments[v]
		if !ok {
			// Comment does not exist
			continue
		}

		// Comment del record
		if cidx.Del != nil {
			merklesDel = append(merklesDel, cidx.Del)
			continue
		}

		// Comment add record
		version := commentVersionLatest(cidx)
		merklesAdd = append(merklesAdd, cidx.Adds[version])
	}

	// Get comment add records
	adds, err := commentAdds(client, merklesAdd)
	if err != nil {
		return nil, fmt.Errorf("commentAdds: %v", err)
	}
	if len(adds) != len(merklesAdd) {
		return nil, fmt.Errorf("wrong comment adds count; got %v, want %v",
			len(adds), len(merklesAdd))
	}

	// Get comment del records
	dels, err := commentDels(client, merklesDel)
	if err != nil {
		return nil, fmt.Errorf("commentDels: %v", err)
	}
	if len(dels) != len(merklesDel) {
		return nil, fmt.Errorf("wrong comment dels count; got %v, want %v",
			len(dels), len(merklesDel))
	}

	// Prepare comments
	cs := make(map[uint32]comments.Comment, len(commentIDs))
	for _, v := range adds {
		c := convertCommentFromCommentAdd(v)
		c.Score = idx.Comments[c.CommentID].Score
		cs[v.CommentID] = c
	}
	for _, v := range dels {
		c := convertCommentFromCommentDel(v)
		cs[v.CommentID] = c
	}

	return cs, nil
}

// This function must be called WITH the record lock held.
func (p *commentsPlugin) new(client *tlogbe.RecordClient, n comments.New, encrypt bool) (*comments.NewReply, error) {
	// Pull comments index
	idx, err := indexLatest(client)
	if err != nil {
		return nil, err
	}

	// Verify parent comment exists if set. A parent ID of 0 means that
	// this is a base level comment, not a reply to another comment.
	if n.ParentID > 0 && !commentExists(*idx, n.ParentID) {
		return nil, comments.UserError{
			ErrorCode:    comments.ErrorStatusParentIDInvalid,
			ErrorContext: []string{"comment not found"},
		}
	}

	// Setup comment
	receipt := p.id.SignMessage([]byte(n.Signature))
	c := comments.CommentAdd{
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
		Timestamp: c.Timestamp,
		Receipt:   c.Receipt,
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
	err = util.VerifySignature(n.Signature, n.PublicKey, msg)
	if err != nil {
		return "", convertCommentsErrFromSignatureErr(err)
	}

	// Get record client
	token, err := hex.DecodeString(n.Token)
	if err != nil {
		return "", comments.UserError{
			ErrorCode: comments.ErrorStatusTokenInvalid,
		}
	}
	client, err := p.backend.RecordClient(token)
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
func (p *commentsPlugin) edit(client *tlogbe.RecordClient, e comments.Edit, encrypt bool) (*comments.EditReply, error) {
	// Get comments index
	idx, err := indexLatest(client)
	if err != nil {
		return nil, fmt.Errorf("indexLatest: %v", err)
	}

	// Get the existing comment
	cs, err := commentsLatest(client, *idx, []uint32{e.CommentID})
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
	c := comments.CommentAdd{
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
		Timestamp: c.Timestamp,
		Receipt:   c.Receipt,
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
	err = util.VerifySignature(e.Signature, e.PublicKey, msg)
	if err != nil {
		return "", convertCommentsErrFromSignatureErr(err)
	}

	// Get record client
	token, err := hex.DecodeString(e.Token)
	if err != nil {
		return "", comments.UserError{
			ErrorCode: comments.ErrorStatusTokenInvalid,
		}
	}
	client, err := p.backend.RecordClient(token)
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
func (p *commentsPlugin) del(client *tlogbe.RecordClient, d comments.Del) (*comments.DelReply, error) {
	// Get comments index
	idx, err := indexLatest(client)
	if err != nil {
		return nil, fmt.Errorf("indexLatest: %v", err)
	}

	// Get comment
	cs, err := commentsLatest(client, *idx, []uint32{d.CommentID})
	if err != nil {
		return nil, fmt.Errorf("commentsLatest %v: %v", d.CommentID, err)
	}
	comment, ok := cs[d.CommentID]
	if !ok {
		return nil, comments.UserError{
			ErrorCode: comments.ErrorStatusCommentNotFound,
		}
	}

	// Save delete record
	receipt := p.id.SignMessage([]byte(d.Signature))
	cd := comments.CommentDel{
		Token:           d.Token,
		CommentID:       d.CommentID,
		Reason:          d.Reason,
		PublicKey:       d.PublicKey,
		Signature:       d.Signature,
		ParentID:        comment.ParentID,
		AuthorPublicKey: comment.PublicKey,
		Timestamp:       time.Now().Unix(),
		Receipt:         hex.EncodeToString(receipt[:]),
	}
	merkleHash, err := commentDelSave(client, cd)
	if err != nil {
		return nil, fmt.Errorf("commentDelSave: %v", err)
	}

	// Update index
	cidx, ok := idx.Comments[d.CommentID]
	if !ok {
		return nil, fmt.Errorf("comment not found in index: %v", d.CommentID)
	}
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
	err = client.Del(merkles)
	if err != nil {
		return nil, fmt.Errorf("BlobsDel: %v", err)
	}

	return &comments.DelReply{
		Timestamp: cd.Timestamp,
		Receipt:   cd.Receipt,
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
	err = util.VerifySignature(d.Signature, d.PublicKey, msg)
	if err != nil {
		return "", convertCommentsErrFromSignatureErr(err)
	}

	// Get record client
	token, err := hex.DecodeString(d.Token)
	if err != nil {
		return "", comments.UserError{
			ErrorCode: comments.ErrorStatusTokenInvalid,
		}
	}
	client, err := p.backend.RecordClient(token)
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

	// Get record client
	token, err := hex.DecodeString(g.Token)
	if err != nil {
		return "", comments.UserError{
			ErrorCode: comments.ErrorStatusTokenInvalid,
		}
	}
	client, err := p.backend.RecordClient(token)
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

	// Get comments
	cs, err := commentsLatest(client, *idx, g.CommentIDs)
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

	// Get record client
	token, err := hex.DecodeString(ga.Token)
	if err != nil {
		return "", comments.UserError{
			ErrorCode: comments.ErrorStatusTokenInvalid,
		}
	}
	client, err := p.backend.RecordClient(token)
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

	// Compile comment IDs
	commentIDs := make([]uint32, 0, len(idx.Comments))
	for k := range idx.Comments {
		commentIDs = append(commentIDs, k)
	}

	// Get comments
	c, err := commentsLatest(client, *idx, commentIDs)
	if err != nil {
		return "", fmt.Errorf("commentsLatest: %v", err)
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

	// Get record client
	token, err := hex.DecodeString(gv.Token)
	if err != nil {
		return "", comments.UserError{
			ErrorCode: comments.ErrorStatusTokenInvalid,
		}
	}
	client, err := p.backend.RecordClient(token)
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

	// Verify comment exists
	cidx, ok := idx.Comments[gv.CommentID]
	if !ok {
		return "", comments.UserError{
			ErrorCode: comments.ErrorStatusCommentNotFound,
		}
	}
	if cidx.Del != nil {
		return "", comments.UserError{
			ErrorCode:    comments.ErrorStatusCommentNotFound,
			ErrorContext: []string{"comment has been deleted"},
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

	// Get record client
	token, err := hex.DecodeString(c.Token)
	if err != nil {
		return "", comments.UserError{
			ErrorCode: comments.ErrorStatusTokenInvalid,
		}
	}
	client, err := p.backend.RecordClient(token)
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
	err = util.VerifySignature(v.Signature, v.PublicKey, msg)
	if err != nil {
		return "", convertCommentsErrFromSignatureErr(err)
	}

	// Get record client
	token, err := hex.DecodeString(v.Token)
	if err != nil {
		return "", comments.UserError{
			ErrorCode: comments.ErrorStatusTokenInvalid,
		}
	}
	client, err := p.backend.RecordClient(token)
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

	// Verify comment exists
	cidx, ok := idx.Comments[v.CommentID]
	if !ok {
		return "", comments.UserError{
			ErrorCode: comments.ErrorStatusCommentNotFound,
		}
	}

	// Verify user has not exceeded max allowed vote changes
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
	cv := comments.CommentVote{
		UUID:      v.UUID,
		Token:     v.Token,
		CommentID: v.CommentID,
		Vote:      int64(v.Vote),
		PublicKey: v.PublicKey,
		Signature: v.Signature,
		Timestamp: time.Now().Unix(),
		Receipt:   hex.EncodeToString(receipt[:]),
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
		Timestamp: cv.Timestamp,
		Receipt:   cv.Receipt,
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
//
// This function satisfies the Plugin interface.
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

	return "", backend.ErrPluginCmdInvalid
}

// Hook executes a plugin hook.
//
// This function satisfies the Plugin interface.
func (p *commentsPlugin) Hook(h tlogbe.HookT, payload string) error {
	log.Tracef("comments Hook: %v", tlogbe.Hooks[h])
	return nil
}

// Fsck performs a plugin filesystem check.
//
// This function satisfies the Plugin interface.
func (p *commentsPlugin) Fsck() error {
	log.Tracef("comments Fsck")

	// Make sure CommentDel blobs were actually deleted

	return nil
}

// Setup performs any plugin setup work that needs to be done.
//
// This function satisfies the Plugin interface.
func (p *commentsPlugin) Setup() error {
	log.Tracef("comments Setup")
	return nil
}

// NewCommentsPlugin returns a new comments plugin.
func NewCommentsPlugin(backend *tlogbe.Tlogbe, settings []backend.PluginSetting) *commentsPlugin {
	// TODO these should be passed in as plugin settings
	id := &identity.FullIdentity{}

	return &commentsPlugin{
		id:      id,
		backend: backend,
		mutexes: make(map[string]*sync.Mutex),
	}
}
