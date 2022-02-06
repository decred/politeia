// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tstore

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/google/trillian"
	"github.com/google/trillian/client"
	"github.com/google/trillian/merkle/rfc6962"
	"github.com/google/trillian/types"
	rstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/genproto/protobuf/field_mask"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/status"
)

var (
	// hasher contains the log hasher that trillian uses to compute the
	// merkle leaf hash for a log leaf. It can be used by tstore to
	// compute the merkle leaf hash for a given leaf value.
	hasher = rfc6962.DefaultHasher
)

const (
	// waitForInclusionTimeout is the amount of time that we wait for
	// a queued leaf to be appended onto a tlog tree before timing out.
	waitForInclusionTimeout = 120 * time.Second
)

// queuedLeafProof contains the results of a leaf append command, i.e. the
// QueuedLeaf, and the inclusion proof for that leaf. If the leaf append
// command fails the QueuedLeaf will contain an error code from the failure and
// the Proof will not be present.
type queuedLeafProof struct {
	QueuedLeaf *trillian.QueuedLogLeaf
	Proof      *trillian.Proof
}

// tlogClient provides an interface for interacting with a trillian log. It
// creates an abstraction over the trillian provided TrillianLogClient and
// TrillianAdminClient, creating a simplified API for the backend to use and
// allowing us to create a implementation that can be used for testing.
type tlogClient interface {
	// TreeNew creates a new tree.
	TreeNew() (*trillian.Tree, *trillian.SignedLogRoot, error)

	// TreeFreeze sets the status of a tree to frozen and returns the
	// updated tree.
	TreeFreeze(treeID int64) (*trillian.Tree, error)

	// Tree returns a tree.
	Tree(treeID int64) (*trillian.Tree, error)

	// TreesAll returns all trees in the trillian instance.
	TreesAll() ([]*trillian.Tree, error)

	// LeavesAppend appends leaves onto a tree.
	LeavesAppend(treeID int64, leaves []*trillian.LogLeaf) ([]queuedLeafProof,
		*types.LogRootV1, error)

	// LeavesAll returns all leaves of a tree.
	LeavesAll(treeID int64) ([]*trillian.LogLeaf, error)

	// SignedLogRoot returns the signed log root for a tree.
	SignedLogRoot(tree *trillian.Tree) (*trillian.SignedLogRoot,
		*types.LogRootV1, error)

	// InclusionProof returns a proof for the inclusion of a merkle
	// leaf hash in a log root.
	InclusionProof(treeID int64, merkleLeafHashe []byte,
		lrv1 *types.LogRootV1) (*trillian.Proof, error)

	// Close closes the client connection.
	Close()
}

var (
	_ tlogClient = (*tclient)(nil)
)

// tclient implements the tlogClient interface using the trillian provided
// TrillianLogClient and TrillianAdminClient.
type tclient struct {
	host  string
	grpc  *grpc.ClientConn
	log   trillian.TrillianLogClient
	admin trillian.TrillianAdminClient
	ctx   context.Context
}

// TreeNew returns a new trillian tree and verifies that the signatures are
// correct. It returns the tree and the signed log root which can be externally
// verified.
//
// This function satisfies the tlogClient interface.
func (t *tclient) TreeNew() (*trillian.Tree, *trillian.SignedLogRoot, error) {
	log.Tracef("trillian TreeNew")

	// Create new trillian tree
	tree, err := t.admin.CreateTree(t.ctx, &trillian.CreateTreeRequest{
		Tree: &trillian.Tree{
			TreeState:       trillian.TreeState_ACTIVE,
			TreeType:        trillian.TreeType_LOG,
			DisplayName:     "",
			Description:     "",
			MaxRootDuration: ptypes.DurationProto(0),
		},
	})
	if err != nil {
		return nil, nil, err
	}

	// Init tree or signer goes bananas
	ilr, err := t.log.InitLog(t.ctx, &trillian.InitLogRequest{
		LogId: tree.TreeId,
	})
	if err != nil {
		return nil, nil, err
	}

	// Check trillian errors
	switch code := status.Code(err); code {
	case codes.Unavailable:
		err = fmt.Errorf("log server unavailable: %v", err)
	case codes.AlreadyExists:
		err = fmt.Errorf("just-created Log (%v) is already initialised: %v",
			tree.TreeId, err)
	case codes.OK:
		log.Debugf("Initialised Log: %v", tree.TreeId)
	default:
		err = fmt.Errorf("failed to InitLog (unknown error)")
	}
	if err != nil {
		return nil, nil, err
	}

	return tree, ilr.Created, nil
}

// TreeFreeze sets the status of a tree to frozen and returns the updated tree.
//
// This function satisfies the tlogClient interface.
func (t *tclient) TreeFreeze(treeID int64) (*trillian.Tree, error) {
	log.Tracef("trillian TreeFreeze: %v", treeID)

	// Get the current tree
	tree, err := t.Tree(treeID)
	if err != nil {
		return nil, fmt.Errorf("tree: %v", err)
	}

	// Update the tree state
	tree.TreeState = trillian.TreeState_FROZEN

	// Apply update
	updated, err := t.admin.UpdateTree(t.ctx, &trillian.UpdateTreeRequest{
		Tree: tree,
		UpdateMask: &field_mask.FieldMask{
			Paths: []string{"tree_state"},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("UpdateTree: %v", err)
	}

	return updated, nil
}

// Tree returns a trillian tree.
//
// This function satisfies the tlogClient interface.
func (t *tclient) Tree(treeID int64) (*trillian.Tree, error) {
	log.Tracef("trillian tree: %v", treeID)

	tree, err := t.admin.GetTree(t.ctx, &trillian.GetTreeRequest{
		TreeId: treeID,
	})
	if err != nil {
		return nil, err
	}
	if tree.TreeId != treeID {
		// Sanity check
		return nil, fmt.Errorf("wrong tree returned; got %v, want %v",
			tree.TreeId, treeID)
	}

	return tree, nil
}

// TreesAll returns all trees in the trillian instance.
//
// This function satisfies the tlogClient interface
func (t *tclient) TreesAll() ([]*trillian.Tree, error) {
	log.Tracef("trillian TreesAll")

	ltr, err := t.admin.ListTrees(t.ctx, &trillian.ListTreesRequest{})
	if err != nil {
		return nil, err
	}

	return ltr.Tree, nil
}

// InclusionProof returns a proof for the inclusion of a merkle leaf hash in a
// log root.
//
// This function satisfies the tlogClient interface
func (t *tclient) InclusionProof(treeID int64, merkleLeafHash []byte, lrv1 *types.LogRootV1) (*trillian.Proof, error) {
	log.Tracef("tillian InclusionProof: %v %x", treeID, merkleLeafHash)

	resp, err := t.log.GetInclusionProofByHash(t.ctx,
		&trillian.GetInclusionProofByHashRequest{
			LogId:    treeID,
			LeafHash: merkleLeafHash,
			TreeSize: int64(lrv1.TreeSize),
		})
	if err != nil {
		return nil, fmt.Errorf("GetInclusionProof: %v", err)
	}
	if len(resp.Proof) != 1 {
		return nil, fmt.Errorf("invalid number of proofs: got %v, want 1",
			len(resp.Proof))
	}
	proof := resp.Proof[0]

	// Verify inclusion proof
	verifier := client.NewLogVerifier(rfc6962.DefaultHasher)
	err = verifier.VerifyInclusionByHash(lrv1, merkleLeafHash, proof)
	if err != nil {
		return nil, fmt.Errorf("VerifyInclusionByHash: %v", err)
	}

	return proof, nil
}

// SignedLogRoot returns the signed log root of a trillian tree.
//
// This function satisfies the tlogClient interface.
func (t *tclient) SignedLogRoot(tree *trillian.Tree) (*trillian.SignedLogRoot, *types.LogRootV1, error) {
	// Get the signed log root for the current tree height
	resp, err := t.log.GetLatestSignedLogRoot(t.ctx,
		&trillian.GetLatestSignedLogRootRequest{LogId: tree.TreeId})
	if err != nil {
		return nil, nil, err
	}

	var lrv1 types.LogRootV1
	if err := lrv1.UnmarshalBinary(resp.SignedLogRoot.GetLogRoot()); err != nil {
		return nil, nil, err
	}

	return resp.SignedLogRoot, &lrv1, nil
}

// LeavesAppend appends leaves onto a tlog tree. The queued leaf and the leaf
// inclusion proof are returned. If a leaf was not successfully appended, the
// queued leaf will still be returned and the error will be in the queued leaf.
// Inclusion proofs will not exist for leaves that fail to be appended. Note
// leaves that are duplicates will fail and it is the callers responsibility to
// determine how they should be handled.
//
// Trillian DOES NOT guarantee that the leaves of a queued leaves batch are
// appended in the order in which they were received. Trillian is also not
// consistent about the order that leaves are appended in. At the time of
// writing this I have not looked into why this is or if there are other
// methods that can be used. DO NOT rely on the leaves being in a specific
// order.
//
// This function satisfies the tlogClient interface.
func (t *tclient) LeavesAppend(treeID int64, leaves []*trillian.LogLeaf) ([]queuedLeafProof, *types.LogRootV1, error) {
	log.Tracef("trillian LeavesAppend: %v %v", treeID, len(leaves))

	// Get the latest signed log root
	tree, err := t.Tree(treeID)
	if err != nil {
		return nil, nil, err
	}
	slr, _, err := t.SignedLogRoot(tree)
	if err != nil {
		return nil, nil, fmt.Errorf("SignedLogRoot pre update: %v", err)
	}
	if tree.TreeState == trillian.TreeState_FROZEN {
		return nil, nil, fmt.Errorf("tree is frozen")
	}

	// Append leaves
	queuedLeaves := make([]*trillian.QueuedLogLeaf, 0, len(leaves))
	for _, l := range leaves {
		qlr, err := t.log.QueueLeaf(t.ctx,
			&trillian.QueueLeafRequest{
				LogId: treeID,
				Leaf:  l,
			})
		if err != nil {
			return nil, nil, fmt.Errorf("QueueLeaf: %v", err)
		}
		queuedLeaves = append(queuedLeaves, qlr.QueuedLeaf)
	}

	// Wait for inclusion of all queued leaves in the root. We must
	// check for inclusion instead of simply waiting for a root update
	// because a root update doesn't necessarily mean the queued leaves
	// from this request were added yet. The root will be updated as
	// soon as the first leaf in the queue is added, which can lead to
	// errors when the queue contains multiple leaves and we try to
	// fetch the inclusion proof in the code below for leaves that are
	// still in the process of being taken out of the queue.
	var n int
	for _, ql := range queuedLeaves {
		c := codes.Code(ql.GetStatus().GetCode())
		if c != codes.OK {
			n++
		}
	}

	log.Tracef("Queued/Ignored leaves: %v/%v", len(leaves)-n, n)
	log.Tracef("Waiting for inclusion of queued leaves...")

	var logRoot types.LogRootV1
	err = logRoot.UnmarshalBinary(slr.LogRoot)
	if err != nil {
		return nil, nil, err
	}
	c, err := client.NewFromTree(t.log, tree, logRoot)
	if err != nil {
		return nil, nil, err
	}
	for _, v := range queuedLeaves {
		ctx, cancel := context.WithTimeout(context.Background(),
			waitForInclusionTimeout)
		defer cancel()
		err = c.WaitForInclusion(ctx, v.Leaf.LeafValue)
		if err != nil {
			return nil, nil, fmt.Errorf("WaitForInclusion: %v", err)
		}
	}

	// Get the latest signed log root
	_, lr, err := t.SignedLogRoot(tree)
	if err != nil {
		return nil, nil, fmt.Errorf("SignedLogRoot post update: %v", err)
	}

	// Get inclusion proofs
	proofs := make([]queuedLeafProof, 0, len(queuedLeaves))
	var failed int
	for _, v := range queuedLeaves {
		qlp := queuedLeafProof{
			QueuedLeaf: v,
		}

		// Only retrieve the inclusion proof if the leaf was successfully
		// appended. Leaves that were not successfully appended will be
		// returned without an inclusion proof and the caller can decide
		// what to do with them. Note this includes leaves that were not
		// appended because they were a duplicate.
		c := codes.Code(v.GetStatus().GetCode())
		if c == codes.OK {
			// Verify that the merkle leaf hash is using the expected
			// hashing algorithm.
			m := merkleLeafHash(v.Leaf.LeafValue)
			if !bytes.Equal(m, v.Leaf.MerkleLeafHash) {
				e := fmt.Sprintf("unknown merkle leaf hash: got %x, want %x",
					m, v.Leaf.MerkleLeafHash)
				panic(e)
			}

			// The LeafIndex of a QueuedLogLeaf will not be set. Get the
			// inclusion proof by MerkleLeafHash.
			qlp.Proof, err = t.InclusionProof(treeID, v.Leaf.MerkleLeafHash, lr)
			if err != nil {
				return nil, nil, fmt.Errorf("InclusionProof %v %x: %v",
					treeID, v.Leaf.MerkleLeafHash, err)
			}
		} else {
			// Leaf contains an error
			failed++
		}

		proofs = append(proofs, qlp)
	}

	// Sanity check
	if len(proofs) != len(leaves) {
		return nil, nil, fmt.Errorf("got %v queued leaves, want %v",
			len(proofs), len(leaves))
	}

	log.Debugf("Appended leaves (%v/%v) to tree %v",
		len(leaves)-failed, len(leaves), treeID)

	return proofs, lr, nil
}

// leavesByRange returns the log leaves of a trillian tree by the range provided
// by the user.
//
// This function satisfies the tlogClient interface.
func (t *tclient) leavesByRange(treeID int64, startIndex, count int64) ([]*trillian.LogLeaf, error) {
	log.Tracef("trillian leavesByRange: %v %v %v", treeID, startIndex, count)

	glbrr, err := t.log.GetLeavesByRange(t.ctx,
		&trillian.GetLeavesByRangeRequest{
			LogId:      treeID,
			StartIndex: startIndex,
			Count:      count,
		})
	if err != nil {
		return nil, err
	}

	return glbrr.Leaves, nil
}

// LeavesAll returns all of the leaves for the provided treeID.
//
// This function satisfies the tlogClient interface.
func (t *tclient) LeavesAll(treeID int64) ([]*trillian.LogLeaf, error) {
	log.Tracef("trillian LeavesAll: %v", treeID)

	// Get tree
	tree, err := t.Tree(treeID)
	if err != nil {
		return nil, err
	}

	// Get signed log root
	_, lr, err := t.SignedLogRoot(tree)
	if err != nil {
		return nil, fmt.Errorf("SignedLogRoot: %v", err)
	}
	if lr.TreeSize == 0 {
		return []*trillian.LogLeaf{}, nil
	}

	// Get all leaves
	leaves, err := t.leavesByRange(treeID, 0, int64(lr.TreeSize))
	if err != nil {
		return nil, fmt.Errorf("leavesByRange: %v", err)
	}

	return leaves, nil
}

// Close closes the trillian grpc connection.
//
// This function satisfies the tlogClient interface.
func (t *tclient) Close() {
	log.Tracef("trillian Close %v", t.host)

	t.grpc.Close()
}

// merkleLeafHash returns the merkle leaf hash for the provided leaf value.
// This is the same merkle leaf hash that is calculated by trillian.
func merkleLeafHash(leafValue []byte) []byte {
	return hasher.HashLeaf(leafValue)
}

func newLogLeaf(leafValue []byte, extraData []byte) *trillian.LogLeaf {
	return &trillian.LogLeaf{
		LeafValue: leafValue,
		ExtraData: extraData,
	}
}

// newTClient returns a new tclient.
func newTClient(host string) (*tclient, error) {
	// Default gprc max message size is ~4MB (4194304 bytes). This is
	// not large enough for trees with tens of thousands of leaves.
	// Increase it to 20MB.
	maxMsgSize := grpc.WithMaxMsgSize(20 * 1024 * 1024)

	// Setup trillian connection
	g, err := grpc.Dial(host, grpc.WithInsecure(), maxMsgSize)
	if err != nil {
		return nil, fmt.Errorf("grpc dial: %v", err)
	}

	t := tclient{
		grpc:  g,
		log:   trillian.NewTrillianLogClient(g),
		admin: trillian.NewTrillianAdminClient(g),
		ctx:   context.Background(),
	}

	// The grpc dial requires a little time to connect
	time.Sleep(time.Second)

	// Ensure trillian is up and running
	for t.grpc.GetState() != connectivity.Ready {
		wait := 15 * time.Second
		log.Infof("Cannot connect to trillian at %v; retry in %v ", host, wait)
		time.Sleep(wait)
	}

	return &t, nil
}

var (
	_ tlogClient = (*testTClient)(nil)
)

// testTClient implements the tlogClient interface and is used for testing.
type testTClient struct {
	sync.Mutex

	trees  map[int64]*trillian.Tree      // [treeID]Tree
	leaves map[int64][]*trillian.LogLeaf // [treeID][]LogLeaf
}

// TreeNew creates a new tree.
//
// This function satisfies the tlogClient interface.
func (t *testTClient) TreeNew() (*trillian.Tree, *trillian.SignedLogRoot, error) {
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
// This function satisfies the tlogClient interface.
func (t *testTClient) TreeFreeze(treeID int64) (*trillian.Tree, error) {
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
// This function satisfies the tlogClient interface.
func (t *testTClient) Tree(treeID int64) (*trillian.Tree, error) {
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
// This function satisfies the tlogClient interface.
func (t *testTClient) TreesAll() ([]*trillian.Tree, error) {
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
// This function satisfies the tlogClient interface.
func (t *testTClient) LeavesAppend(treeID int64, leavesAppend []*trillian.LogLeaf) ([]queuedLeafProof, *types.LogRootV1, error) {
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
	queued := make([]queuedLeafProof, 0, len(leavesAppend))
	for _, v := range leavesAppend {
		// Append to leaves
		v.MerkleLeafHash = merkleLeafHash(v.LeafValue)
		v.LeafIndex = index + 1
		leaves = append(leaves, v)
		index++

		// Append to reply
		queued = append(queued, queuedLeafProof{
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
// This function satisfies the tlogClient interface.
func (t *testTClient) LeavesAll(treeID int64) ([]*trillian.LogLeaf, error) {
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
			MerkleLeafHash: merkleLeafHash(leafValue),
			LeafValue:      leafValue,
			ExtraData:      extraData,
			LeafIndex:      v.LeafIndex,
		})
	}

	return leavesCopy, nil
}

// SignedLogRoot has not been implemented yet.
//
// This function satisfies the tlogClient interface.
func (t *testTClient) SignedLogRoot(tree *trillian.Tree) (*trillian.SignedLogRoot, *types.LogRootV1, error) {
	return nil, nil, fmt.Errorf("not implemented")
}

// InclusionProof has not been implement yet.
//
// This function satisfies the tlogClient interface.
func (t *testTClient) InclusionProof(treeID int64, merkleLeafHash []byte, lr *types.LogRootV1) (*trillian.Proof, error) {
	return nil, fmt.Errorf("not implemented")
}

// Close closes the client connection. There is nothing to do for the test tlog
// client.
//
// This function satisfies the tlogClient interface.
func (t *testTClient) Close() {}

// newTestTClient returns a new testTClient.
func newTestTClient(t *testing.T) *testTClient {
	return &testTClient{
		trees:  make(map[int64]*trillian.Tree),
		leaves: make(map[int64][]*trillian.LogLeaf),
	}
}
