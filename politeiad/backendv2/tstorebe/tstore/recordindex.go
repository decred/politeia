// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tstore

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
	"github.com/decred/politeia/util"
	"github.com/google/trillian"
	"google.golang.org/grpc/codes"
)

// recordIndex contains the merkle leaf hashes of all the record content leaves
// for a specific record version and iteration. The record index can be used to
// lookup the trillian log leaves for the record content and the log leaves can
// be used to lookup the kv store blobs.
//
// A record is updated in three steps:
//
// 1. Record content is saved to the kv store.
//
// 2. A trillian leaf is created for each piece of record content. The kv store
//    key for each piece of content is stuffed into the LogLeaf.ExtraData
//    field. The leaves are appended onto the trillian tree.
//
// 3. If there are failures in steps 1 or 2 for any of the blobs then the
//    update will exit without completing. No unwinding is performed. Blobs
//    will be left in the kv store as orphaned blobs. The trillian tree is
//    append-only so once a leaf is appended, it's there permanently. If steps
//    1 and 2 are successful then a recordIndex is created, saved to the kv
//    store, and appended onto the trillian tree.
//
// Appending a recordIndex onto the trillian tree is the last operation that
// occurs during a record update. If a recordIndex exists in the tree then the
// update is considered successful. Any record content leaves that are not part
// of a recordIndex are considered to be orphaned and can be disregarded.
type recordIndex struct {
	State backend.StateT `json:"state"`

	// Version represents the version of the record. The version is
	// only incremented when the record files are updated. Metadata
	// only updates do no increment the version.
	Version uint32 `json:"version"`

	// Iteration represents the iteration of the record. The iteration is
	// incremented anytime any record content changes. This includes file
	// changes that bump the version, metadata stream only updates that
	// don't bump the version, and status changes.
	Iteration uint32 `json:"iteration"`

	// The following fields contain the merkle leaf hashes of the trillian
	// log leaves for the record content. The merkle leaf hash can be used
	// to lookup the log leaf. The log leaf ExtraData field contains the
	// key for the record content in the key-value store.
	RecordMetadata []byte            `json:"recordmetadata"`
	Files          map[string][]byte `json:"files"` // [filename]merkle

	// [pluginID][streamID]merkle
	Metadata map[string]map[uint32][]byte `json:"metadata"`

	// Frozen is used to indicate that the tree for this record has been
	// frozen. This happens as a result of certain record status changes.
	// The only thing that can be appended onto a frozen tree is one
	// additional anchor record. Once a frozen tree has been anchored, the
	// tstore fsck function will update the status of the tree to frozen in
	// trillian, at which point trillian will not allow any additional
	// leaves to be appended onto the tree.
	Frozen bool `json:"frozen,omitempty"`
}

// recordIndexSave saves a record index to tstore.
func (t *Tstore) recordIndexSave(treeID int64, idx recordIndex) error {
	// Only vetted data should be saved plain text
	var encrypt bool
	switch idx.State {
	case backend.StateUnvetted:
		encrypt = true
	case backend.StateVetted:
		// Save plain text
		encrypt = false
	default:
		// Something is wrong
		e := fmt.Sprintf("invalid record state %v %v",
			treeID, idx.State)
		panic(e)
	}

	log.Debugf("Saving record index")

	// Save record index to the store
	be, err := convertBlobEntryFromRecordIndex(idx)
	if err != nil {
		return err
	}
	b, err := store.Blobify(*be)
	if err != nil {
		return err
	}
	key := storeKeyNew(encrypt)
	kv := map[string][]byte{key: b}
	err = t.store.Put(kv, encrypt)
	if err != nil {
		return fmt.Errorf("store Put: %v", err)
	}

	// Append record index leaf to trillian tree
	d, err := hex.DecodeString(be.Digest)
	if err != nil {
		return err
	}
	extraData, err := extraDataEncode(key,
		dataDescriptorRecordIndex, idx.State)
	if err != nil {
		return err
	}
	leaves := []*trillian.LogLeaf{
		newLogLeaf(d, extraData),
	}
	queued, _, err := t.tlog.LeavesAppend(treeID, leaves)
	if err != nil {
		return fmt.Errorf("LeavesAppend: %v", err)
	}
	if len(queued) != 1 {
		return fmt.Errorf("wrong number of queud leaves: got %v, "+
			"want 1", len(queued))
	}
	failed := make([]string, 0, len(queued))
	for _, v := range queued {
		c := codes.Code(v.QueuedLeaf.GetStatus().GetCode())
		if c != codes.OK {
			failed = append(failed, fmt.Sprintf("%v", c))
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("append leaves failed: %v", failed)
	}

	return nil
}

// recordIndexes returns all record indexes found in the provided trillian
// leaves.
func (t *Tstore) recordIndexes(leaves []*trillian.LogLeaf) ([]recordIndex, error) {
	// Walk the leaves and compile the keys for all record indexes.  Once a
	// record is made vetted the record history is considered to restart.
	// If any vetted indexes exist, ignore all unvetted indexes.
	var (
		keysUnvetted = make([]string, 0, 256)
		keysVetted   = make([]string, 0, 256)
	)
	for _, v := range leaves {
		ed, err := extraDataDecode(v.ExtraData)
		if err != nil {
			return nil, err
		}
		if ed.Desc != dataDescriptorRecordIndex {
			continue
		}
		// This is a record index leaf
		switch ed.State {
		case backend.StateUnvetted:
			keysUnvetted = append(keysUnvetted, ed.storeKey())
		case backend.StateVetted:
			keysVetted = append(keysVetted, ed.storeKey())
		default:
			// Should not happen
			return nil, fmt.Errorf("invalid extra data state: "+
				"%v %v", v.LeafIndex, ed.State)
		}
	}
	keys := keysUnvetted
	if len(keysVetted) > 0 {
		keys = keysVetted
	}
	if len(keys) == 0 {
		// No records have been added to this tree yet
		return nil, backend.ErrRecordNotFound
	}

	// Get record indexes from store
	blobs, err := t.store.Get(keys)
	if err != nil {
		return nil, fmt.Errorf("store Get: %v", err)
	}
	missing := make([]string, 0, len(keys))
	for _, v := range keys {
		if _, ok := blobs[v]; !ok {
			missing = append(missing, v)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("record index not found: %v", missing)
	}

	var (
		unvetted = make([]recordIndex, 0, len(blobs))
		vetted   = make([]recordIndex, 0, len(blobs))
	)
	for _, v := range blobs {
		be, err := store.Deblob(v)
		if err != nil {
			return nil, err
		}
		ri, err := convertRecordIndexFromBlobEntry(*be)
		if err != nil {
			return nil, err
		}
		switch ri.State {
		case backend.StateUnvetted:
			unvetted = append(unvetted, *ri)
		case backend.StateVetted:
			vetted = append(vetted, *ri)
		default:
			return nil, fmt.Errorf("invalid record index state: %v",
				ri.State)
		}
	}

	indexes := unvetted
	if len(vetted) > 0 {
		indexes = vetted
	}

	// Sort indexes by iteration, smallest to largets. The leaves ordering
	// was not preserved in the returned blobs map.
	sort.SliceStable(indexes, func(i, j int) bool {
		return indexes[i].Iteration < indexes[j].Iteration
	})

	// Sanity check. Index iterations should start with 1 and be
	// sequential. Index versions should start with 1 and also be
	// sequential, but duplicate versions can exist as long as the
	// iteration has been incremented.
	var versionPrev uint32
	var i uint32 = 1
	for _, v := range indexes {
		if v.Iteration != i {
			return nil, fmt.Errorf("invalid record index "+
				"iteration: got %v, want %v", v.Iteration, i)
		}
		diff := v.Version - versionPrev
		if diff != 0 && diff != 1 {
			return nil, fmt.Errorf("invalid record index version: "+
				"curr version %v, prev version %v",
				v.Version, versionPrev)
		}

		i++
		versionPrev = v.Version
	}

	return indexes, nil
}

// recordIndex returns the specified version of a record index for a slice of
// trillian leaves.
func (t *Tstore) recordIndex(leaves []*trillian.LogLeaf, version uint32) (*recordIndex, error) {
	indexes, err := t.recordIndexes(leaves)
	if err != nil {
		return nil, err
	}
	return parseRecordIndex(indexes, version)
}

// recordIndexLatest returns the most recent record index for a slice of
// trillian leaves.
func (t *Tstore) recordIndexLatest(leaves []*trillian.LogLeaf) (*recordIndex, error) {
	return t.recordIndex(leaves, 0)
}

// parseRecordIndex takes a list of record indexes and returns the most recent
// iteration of the specified version. A version of 0 indicates that the latest
// version should be returned. A backend.ErrRecordNotFound is returned if the
// provided version does not exist.
func parseRecordIndex(indexes []recordIndex, version uint32) (*recordIndex, error) {
	if len(indexes) == 0 {
		return nil, backend.ErrRecordNotFound
	}

	// This function should only be used on record indexes that share the
	// same record state. We would not want to accidentally return an
	// unvetted index if the record is vetted. It is the responsibility of
	// the caller to only provide a single state.
	state := indexes[0].State
	if state == backend.StateInvalid {
		return nil, fmt.Errorf("invalid record index state: %v", state)
	}
	for _, v := range indexes {
		if v.State != state {
			return nil, fmt.Errorf("multiple record index states "+
				"found: %v %v", v.State, state)
		}
	}

	// Return the record index for the specified version
	var ri *recordIndex
	if version == 0 {
		// A version of 0 indicates that the most recent version should
		// be returned.
		ri = &indexes[len(indexes)-1]
	} else {
		// Walk the indexes backwards so the most recent iteration of
		// the specified version is selected.
		for i := len(indexes) - 1; i >= 0; i-- {
			r := indexes[i]
			if r.Version == version {
				ri = &r
				break
			}
		}
	}
	if ri == nil {
		// The specified version does not exist
		return nil, backend.ErrRecordNotFound
	}

	return ri, nil
}

func convertBlobEntryFromRecordIndex(ri recordIndex) (*store.BlobEntry, error) {
	data, err := json.Marshal(ri)
	if err != nil {
		return nil, err
	}
	hint, err := json.Marshal(
		store.DataDescriptor{
			Type:       store.DataTypeStructure,
			Descriptor: dataDescriptorRecordIndex,
		})
	if err != nil {
		return nil, err
	}
	be := store.NewBlobEntry(hint, data)
	return &be, nil
}

func convertRecordIndexFromBlobEntry(be store.BlobEntry) (*recordIndex, error) {
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
	if dd.Descriptor != dataDescriptorRecordIndex {
		return nil, fmt.Errorf("unexpected data descriptor: got %v, "+
			"want %v", dd.Descriptor, dataDescriptorRecordIndex)
	}

	// Decode data
	b, err = base64.StdEncoding.DecodeString(be.Data)
	if err != nil {
		return nil, fmt.Errorf("decode Data: %v", err)
	}
	digest, err := hex.DecodeString(be.Digest)
	if err != nil {
		return nil, fmt.Errorf("decode digest: %v", err)
	}
	if !bytes.Equal(util.Digest(b), digest) {
		return nil, fmt.Errorf("data is not coherent; got %x, want %x",
			util.Digest(b), digest)
	}
	var ri recordIndex
	err = json.Unmarshal(b, &ri)
	if err != nil {
		return nil, fmt.Errorf("unmarshal recordIndex: %v", err)
	}

	return &ri, nil
}
