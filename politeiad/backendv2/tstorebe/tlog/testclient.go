// Copyright (c) 2021-2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlog

import (
	"fmt"
	"math/rand"
	"sync"
	"testing"

	"github.com/google/trillian"
	"github.com/google/trillian/types"
	rstatus "google.golang.org/genproto/googleapis/rpc/status"
)

var (
	_ Client = (*testClient)(nil)
)

// testClient provides an implemenation of the Client interface that can be
// used for testing. No RPC connection is made to a trillian log and all data
// is stored in memory.
type testClient struct {
	sync.Mutex

	trees  map[int64]*trillian.Tree      // [treeID]Tree
	leaves map[int64][]*trillian.LogLeaf // [treeID][]LogLeaf
}

// NewTestClient returns a new testClient.
func NewTestClient(t *testing.T) *testClient {
	return &testClient{
		trees:  make(map[int64]*trillian.Tree),
		leaves: make(map[int64][]*trillian.LogLeaf),
	}
}

// Close closes the client connection. There is nothing to do for the test tlog
// client.
//
// This function satisfies the Client interface.
func (t *testClient) Close() {}

// TreeNew creates a new tree.
//
// This function satisfies the Client interface.
func (t *testClient) TreeNew() (*trillian.Tree, *trillian.SignedLogRoot, error) {
	t.Lock()
	defer t.Unlock()

	// Create trillian tree
	tree := trillian.Tree{
		TreeId:      rand.Int63(),
		TreeState:   trillian.TreeState_ACTIVE,
		TreeType:    trillian.TreeType_LOG,
		DisplayName: "",
		Description: "",
	}
	t.trees[tree.TreeId] = &tree

	// Initialize leaves
	t.leaves[tree.TreeId] = []*trillian.LogLeaf{}

	return &tree, nil, nil
}

// TreeFreeze sets the status of a tree to frozen and returns the updated tree.
//
// This function satisfies the Client interface.
func (t *testClient) TreeFreeze(treeID int64) (*trillian.Tree, error) {
	t.Lock()
	defer t.Unlock()

	tree, ok := t.trees[treeID]
	if !ok {
		return nil, fmt.Errorf("tree not found")
	}
	tree.TreeState = trillian.TreeState_FROZEN
	t.trees[treeID] = tree

	return tree, nil
}

// Tree returns a tree.
//
// This function satisfies the Client interface.
func (t *testClient) Tree(treeID int64) (*trillian.Tree, error) {
	t.Lock()
	defer t.Unlock()

	tree, ok := t.trees[treeID]
	if !ok {
		return nil, fmt.Errorf("tree not found")
	}

	return tree, nil
}

// TreesAll returns all trees in the trillian instance.
//
// This function satisfies the Client interface.
func (t *testClient) TreesAll() ([]*trillian.Tree, error) {
	t.Lock()
	defer t.Unlock()

	trees := make([]*trillian.Tree, len(t.trees))
	for _, v := range t.trees {
		trees = append(trees, &trillian.Tree{
			TreeId:      v.TreeId,
			TreeState:   v.TreeState,
			TreeType:    v.TreeType,
			DisplayName: v.DisplayName,
			Description: v.Description,
		})
	}

	return trees, nil
}

// LeavesAppend appends leaves onto a tree.
//
// This function satisfies the Client interface.
func (t *testClient) LeavesAppend(treeID int64, leavesAppend []*trillian.LogLeaf) ([]QueuedLeafProof, *types.LogRootV1, error) {
	t.Lock()
	defer t.Unlock()

	leaves, ok := t.leaves[treeID]
	if !ok {
		leaves = make([]*trillian.LogLeaf, 0, len(leavesAppend))
	}

	// Get last leaf index
	var index int64
	if len(leaves) > 0 {
		index = int64(len(leaves)) - 1
	}

	// Append leaves
	queued := make([]QueuedLeafProof, 0, len(leavesAppend))
	for _, v := range leavesAppend {
		// Append to leaves
		v.MerkleLeafHash = MerkleLeafHash(v.LeafValue)
		v.LeafIndex = index + 1
		leaves = append(leaves, v)
		index++

		// Append to reply
		queued = append(queued, QueuedLeafProof{
			QueuedLeaf: &trillian.QueuedLogLeaf{
				Leaf: v,
				Status: &rstatus.Status{
					Code: 0, // 0 indicates OK
				},
			},
		})
	}

	// Save updated leaves
	t.leaves[treeID] = leaves

	return queued, nil, nil
}

// LeavesAll returns all leaves of a tree.
//
// This function satisfies the Client interface.
func (t *testClient) LeavesAll(treeID int64) ([]*trillian.LogLeaf, error) {
	t.Lock()
	defer t.Unlock()

	// Verify tree exists
	_, ok := t.trees[treeID]
	if !ok {
		return nil, fmt.Errorf("tree not found")
	}

	// Get leaves
	leaves, ok := t.leaves[treeID]
	if !ok {
		leaves = make([]*trillian.LogLeaf, 0)
	}

	// Copy leaves
	leavesCopy := make([]*trillian.LogLeaf, 0, len(leaves))
	for _, v := range leaves {
		var (
			leafValue []byte
			extraData []byte
		)
		copy(leafValue, v.LeafValue)
		copy(extraData, v.ExtraData)
		leavesCopy = append(leavesCopy, &trillian.LogLeaf{
			MerkleLeafHash: MerkleLeafHash(leafValue),
			LeafValue:      leafValue,
			ExtraData:      extraData,
			LeafIndex:      v.LeafIndex,
		})
	}

	return leavesCopy, nil
}

// SignedLogRoot has not been implemented yet.
//
// This function satisfies the Client interface.
func (t *testClient) SignedLogRoot(tree *trillian.Tree) (*trillian.SignedLogRoot, *types.LogRootV1, error) {
	return nil, nil, fmt.Errorf("not implemented")
}

// InclusionProof has not been implement yet.
//
// This function satisfies the Client interface.
func (t *testClient) InclusionProof(treeID int64, merkleLeafHash []byte, lr *types.LogRootV1) (*trillian.Proof, error) {
	return nil, fmt.Errorf("not implemented")
}
