// Copyright (c) 2021-2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlog

import (
	"github.com/google/trillian"
	"github.com/google/trillian/merkle/rfc6962"
	"github.com/google/trillian/types"
)

// Client provides an interface for interacting with a trillian log (tlog). It
// creates an abstraction over the trillian provided TrillianLogClient and
// TrillianAdminClient, providing a simplified client API and allowing for the
// creation of an implementation that can be used during testing.
type Client interface {
	// Close closes the client connection.
	Close()

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
	LeavesAppend(treeID int64, leaves []*trillian.LogLeaf) ([]QueuedLeafProof,
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
}

// QueuedLeafProof contains the results of a leaf append command, i.e. the
// QueuedLeaf and the inclusion proof for that leaf. If the append leaf command
// fails the QueuedLeaf will contain an error code from the failure and the
// Proof will not be present.
type QueuedLeafProof struct {
	QueuedLeaf *trillian.QueuedLogLeaf
	Proof      *trillian.Proof
}

// NewLogLeaf returns a new trillian LogLeaf.
func NewLogLeaf(leafValue []byte, extraData []byte) *trillian.LogLeaf {
	return &trillian.LogLeaf{
		LeafValue: leafValue,
		ExtraData: extraData,
	}
}

var (
	// hasher contains the log hasher that trillian uses to compute the merkle
	// leaf hash for a log leaf.
	hasher = rfc6962.DefaultHasher
)

// MerkleLeafHash returns the merkle leaf hash for the provided leaf value.
// This is the same merkle leaf hash that is calculated by trillian.
func MerkleLeafHash(leafValue []byte) []byte {
	return hasher.HashLeaf(leafValue)
}
