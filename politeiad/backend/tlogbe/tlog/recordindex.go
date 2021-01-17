// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlog

import (
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/decred/politeia/politeiad/backend"
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
// 1. Record content blobs are saved to the kv store.
//
// 2. A trillian leaf is created for each record content blob. The kv store
//    key for the blob is stuffed into the LogLeaf.ExtraData field. All leaves
//    are appended onto the trillian tree.
//
// 3. If there are failures in steps 1 or 2 for any of the blobs then the
//    update will exit without completing. No unwinding is performed. Blobs
//    will be left in the kv store as orphaned blobs. The trillian tree is
//    append only so once a leaf is appended, it's there permanently. If steps
//    1 and 2 are successful then a recordIndex will be created, saved to the
//    kv store, and appended onto the trillian tree.
//
// Appending a recordIndex onto the trillian tree is the last operation that
// occurs during a record update. If a recordIndex exists in the tree then the
// update is considered successful. Any record content leaves that are not part
// of a recordIndex are considered to be orphaned and can be disregarded.
type recordIndex struct {
	// Version represents the version of the record. The version is
	// only incremented when the record files are updated. Metadata
	// only updates do no increment the version.
	Version uint32 `json:"version"`

	// Iteration represents the iteration of the record. The iteration
	// is incremented anytime any record content changes. This includes
	// file changes that bump the version as well metadata stream and
	// record metadata changes that don't bump the version.
	//
	// Note, this field is not the same as the backend RecordMetadata
	// iteration field, which does not get incremented on metadata
	// updates.
	//
	// TODO maybe it should be the same. The original iteration field
	// was to track unvetted changes in gitbe since unvetted gitbe
	// records are not versioned. tlogbe unvetted records are versioned
	// so the original use for the iteration field isn't needed anymore.
	Iteration uint32 `json:"iteration"`

	// The following fields contain the merkle leaf hashes of the
	// trillian log leaves for the record content. The merkle leaf hash
	// can be used to lookup the log leaf. The log leaf ExtraData field
	// contains the key for the record content in the key-value store.
	RecordMetadata []byte            `json:"recordmetadata"`
	Metadata       map[uint64][]byte `json:"metadata"` // [metadataID]merkle
	Files          map[string][]byte `json:"files"`    // [filename]merkle

	// Frozen is used to indicate that the tree for this record has
	// been frozen. This happens as a result of certain record status
	// changes. The only thing that can be appended onto a frozen tree
	// is one additional anchor record. Once a frozen tree has been
	// anchored, the tlog fsck function will update the status of the
	// tree to frozen in trillian, at which point trillian will not
	// allow any additional leaves to be appended onto the tree.
	Frozen bool `json:"frozen,omitempty"`

	// TODO make this a generic ExtraData field
	// TreePointer is the tree ID of the tree that is the new location
	// of this record. A record can be copied to a new tree after
	// certain status changes, such as when a record is made public and
	// the record is copied from an unvetted tree to a vetted tree.
	// TreePointer should only be set if the tree has been frozen.
	TreePointer int64 `json:"treepointer,omitempty"`
}

// treePointerExists returns whether the provided record index has a tree
// pointer set.
func treePointerExists(r recordIndex) bool {
	// Sanity checks
	switch {
	case !r.Frozen && r.TreePointer > 0:
		// Tree pointer should only be set if the record is frozen
		e := fmt.Sprintf("tree pointer set without record being frozen %v",
			r.TreePointer)
		panic(e)
	case r.TreePointer < 0:
		// Tree pointer should never be negative. Trillian uses a int64
		// for the tree ID so we do too.
		e := fmt.Sprintf("tree pointer is < 0: %v", r.TreePointer)
		panic(e)
	}

	return r.TreePointer > 0
}

// parseRecordIndex takes a list of record indexes and returns the most recent
// iteration of the specified version. A version of 0 indicates that the latest
// version should be returned. A backend.ErrRecordNotFound is returned if the
// provided version does not exist.
func parseRecordIndex(indexes []recordIndex, version uint32) (*recordIndex, error) {
	// Return the record index for the specified version
	var ri *recordIndex
	if version == 0 {
		// A version of 0 indicates that the most recent version should
		// be returned.
		ri = &indexes[len(indexes)-1]
	} else {
		// Walk the indexes backwards so the most recent iteration of the
		// specified version is selected.
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

// recordIndexSave saves a record index to tlog.
func (t *Tlog) recordIndexSave(treeID int64, ri recordIndex) error {
	// Save record index to the store
	be, err := convertBlobEntryFromRecordIndex(ri)
	if err != nil {
		return err
	}
	b, err := t.blobify(*be)
	if err != nil {
		return err
	}
	keys, err := t.store.Put([][]byte{b})
	if err != nil {
		return fmt.Errorf("store Put: %v", err)
	}
	if len(keys) != 1 {
		return fmt.Errorf("wrong number of keys: got %v, want 1",
			len(keys))
	}

	// Append record index leaf to trillian tree
	d, err := hex.DecodeString(be.Digest)
	if err != nil {
		return err
	}
	extraData := leafExtraData(dataTypeRecordIndex, keys[0])
	leaves := []*trillian.LogLeaf{
		newLogLeaf(d, extraData),
	}
	queued, _, err := t.trillian.leavesAppend(treeID, leaves)
	if err != nil {
		return fmt.Errorf("leavesAppend: %v", err)
	}
	if len(queued) != 1 {
		return fmt.Errorf("wrong number of queud leaves: got %v, want 1",
			len(queued))
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
func (t *Tlog) recordIndexes(leaves []*trillian.LogLeaf) ([]recordIndex, error) {
	// Walk the leaves and compile the keys for all record indexes. It
	// is possible for multiple indexes to exist for the same record
	// version (they will have different iterations due to metadata
	// only updates) so we have to pull the index blobs from the store
	// in order to find the most recent iteration for the specified
	// version.
	keys := make([]string, 0, 64)
	for _, v := range leaves {
		if leafDataType(v) == dataTypeRecordIndex {
			// This is a record index leaf. Save the kv store key.
			keys = append(keys, extractKeyFromLeaf(v))
		}
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

	indexes := make([]recordIndex, 0, len(blobs))
	for _, v := range blobs {
		be, err := t.deblob(v)
		if err != nil {
			return nil, err
		}
		ri, err := convertRecordIndexFromBlobEntry(*be)
		if err != nil {
			return nil, err
		}
		indexes = append(indexes, *ri)
	}

	// Sort indexes by iteration, smallest to largets. The leaves
	// ordering was not preserved in the returned blobs map.
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
			return nil, fmt.Errorf("invalid record index iteration: "+
				"got %v, want %v", v.Iteration, i)
		}
		diff := v.Version - versionPrev
		if diff != 0 && diff != 1 {
			return nil, fmt.Errorf("invalid record index version: "+
				"curr version %v, prev version %v", v.Version, versionPrev)
		}

		i++
		versionPrev = v.Version
	}

	return indexes, nil
}

// recordIndex returns the specified version of a record index for a slice of
// trillian leaves.
func (t *Tlog) recordIndex(leaves []*trillian.LogLeaf, version uint32) (*recordIndex, error) {
	indexes, err := t.recordIndexes(leaves)
	if err != nil {
		return nil, err
	}
	return parseRecordIndex(indexes, version)
}

// recordIndexLatest returns the most recent record index for a slice of
// trillian leaves.
func (t *Tlog) recordIndexLatest(leaves []*trillian.LogLeaf) (*recordIndex, error) {
	return t.recordIndex(leaves, 0)
}
