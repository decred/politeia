// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlogbe

import (
	"crypto"
	"crypto/sha256"
	"fmt"

	"github.com/golang/protobuf/ptypes"
	"github.com/google/trillian"
	"github.com/google/trillian/client"
	tcrypto "github.com/google/trillian/crypto"
	"github.com/google/trillian/crypto/sigpb"
	"github.com/google/trillian/merkle/hashers"
	"github.com/google/trillian/merkle/rfc6962"
	"github.com/google/trillian/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type queuedLeafProof struct {
	QueuedLeaf *trillian.QueuedLogLeaf
	Proof      *trillian.Proof
}

// merkleLeafHash returns the LogLeaf.MerkleLeafHash for the provided
// LogLeaf.LeafData.
func mekleLeafHash(leafValue []byte) []byte {
	h := sha256.New()
	h.Write([]byte{rfc6962.RFC6962LeafHashPrefix})
	h.Write(leafValue)
	return h.Sum(nil)
}

func logLeafNew(value []byte) *trillian.LogLeaf {
	return &trillian.LogLeaf{
		LeafValue: value,
	}
}

func (t *tlogbe) signedLogRoot(tree *trillian.Tree) (*trillian.SignedLogRoot, *types.LogRootV1, error) {
	// Get latest signed root
	resp, err := t.client.GetLatestSignedLogRoot(t.ctx,
		&trillian.GetLatestSignedLogRootRequest{LogId: tree.TreeId})
	if err != nil {
		return nil, nil, err
	}

	// Verify root
	verifier, err := client.NewLogVerifierFromTree(tree)
	if err != nil {
		return nil, nil, err
	}
	lrv1, err := tcrypto.VerifySignedLogRoot(verifier.PubKey,
		crypto.SHA256, resp.SignedLogRoot)
	if err != nil {
		return nil, nil, err
	}

	return resp.SignedLogRoot, lrv1, nil
}

// waitForRootUpdate waits until the trillian root is updated.
func (t *tlogbe) waitForRootUpdate(tree *trillian.Tree, root *trillian.SignedLogRoot) error {
	// Wait for update
	var logRoot types.LogRootV1
	err := logRoot.UnmarshalBinary(root.LogRoot)
	if err != nil {
		return err
	}
	c, err := client.NewFromTree(t.client, tree, logRoot)
	if err != nil {
		return err
	}
	_, err = c.WaitForRootUpdate(t.ctx)
	if err != nil {
		return err
	}
	return nil
}

func (t *tlogbe) inclusionProof(treeID int64, leafHash []byte, lrv1 *types.LogRootV1) (*trillian.Proof, error) {
	resp, err := t.client.GetInclusionProofByHash(t.ctx,
		&trillian.GetInclusionProofByHashRequest{
			LogId:    treeID,
			LeafHash: leafHash,
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
	lh, err := hashers.NewLogHasher(trillian.HashStrategy_RFC6962_SHA256)
	if err != nil {
		return nil, err
	}
	verifier := client.NewLogVerifier(lh, t.publicKey, crypto.SHA256)
	err = verifier.VerifyInclusionByHash(lrv1, leafHash, proof)
	if err != nil {
		return nil, fmt.Errorf("VerifyInclusionByHash: %v", err)
	}

	return proof, nil
}

func (t *tlogbe) leavesAppend(treeID int64, leaves []*trillian.LogLeaf) ([]queuedLeafProof, *trillian.SignedLogRoot, error) {
	// Get the tree
	tree, err := t.admin.GetTree(t.ctx, &trillian.GetTreeRequest{
		TreeId: treeID,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("GetTree: %v", err)
	}
	if tree.TreeId != treeID {
		// Sanity check
		return nil, nil, fmt.Errorf("invalid treeID; got %v, want %v",
			tree.TreeId, treeID)
	}

	// Get the latest signed log root
	slr, _, err := t.signedLogRoot(tree)
	if err != nil {
		return nil, nil, fmt.Errorf("signedLogRoot pre update: %v", err)
	}

	// Append leaves to log
	qlr, err := t.client.QueueLeaves(t.ctx, &trillian.QueueLeavesRequest{
		LogId:  treeID,
		Leaves: leaves,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("QueuedLeaves: %v", err)
	}

	// Only wait if we actually updated the tree
	var n int
	for k := range qlr.QueuedLeaves {
		c := codes.Code(qlr.QueuedLeaves[k].GetStatus().GetCode())
		if c != codes.OK {
			n++
		}
	}
	if len(leaves)-n != 0 {
		// Wait for update
		log.Debugf("Waiting for update: %v", treeID)
		err = t.waitForRootUpdate(tree, slr)
		if err != nil {
			return nil, nil, fmt.Errorf("waitForRootUpdate: %v", err)
		}
	}

	log.Debugf("Stored/Ignored leaves: %v/%v %v", len(leaves)-n, n, treeID)

	// TODO Mark tree as dirty

	// Get the latest signed log root
	slr, lrv1, err := t.signedLogRoot(tree)
	if err != nil {
		return nil, nil, fmt.Errorf("signedLogRoot post update: %v", err)
	}

	// Get inclusion proofs
	proofs := make([]queuedLeafProof, 0, len(qlr.QueuedLeaves))
	for _, v := range qlr.QueuedLeaves {
		qlp := queuedLeafProof{
			QueuedLeaf: v,
		}
		// Only retrieve the inclusion proof if the leaf was successfully
		// added. A leaf might not have been added if it was a duplicate.
		// This is ok. All other errors are not ok.
		c := codes.Code(v.GetStatus().GetCode())
		if c == codes.OK || c == codes.AlreadyExists {
			// The LeafIndex of a QueuedLogLeaf will not be set yet. Get the
			// inclusion proof by MerkleLeafHash.
			qlp.Proof, err = t.inclusionProof(treeID, v.Leaf.MerkleLeafHash, lrv1)
			if err != nil {
				return nil, nil, fmt.Errorf("inclusionProof %v %x: %v",
					treeID, v.Leaf.MerkleLeafHash, err)
			}
		}
		proofs = append(proofs, qlp)
	}

	return proofs, slr, nil
}

// treeNew returns a new trillian tree and verifies that the signatures are
// correct. It returns the tree and the signed log root which can be externally
// verified.
func (t *tlogbe) treeNew() (*trillian.Tree, *trillian.SignedLogRoot, error) {
	pk, err := ptypes.MarshalAny(t.privateKey)
	if err != nil {
		return nil, nil, err
	}

	// Create new trillian tree
	tree, err := t.admin.CreateTree(t.ctx, &trillian.CreateTreeRequest{
		Tree: &trillian.Tree{
			TreeState:          trillian.TreeState_ACTIVE,
			TreeType:           trillian.TreeType_LOG,
			HashStrategy:       trillian.HashStrategy_RFC6962_SHA256,
			HashAlgorithm:      sigpb.DigitallySigned_SHA256,
			SignatureAlgorithm: sigpb.DigitallySigned_ECDSA,
			// TODO SignatureAlgorithm: sigpb.DigitallySigned_ED25519,
			DisplayName:     "",
			Description:     "",
			MaxRootDuration: ptypes.DurationProto(0),
			PrivateKey:      pk,
		},
	})
	if err != nil {
		return nil, nil, err
	}

	// Init tree or signer goes bananas
	ilr, err := t.client.InitLog(t.ctx, &trillian.InitLogRequest{
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

	// Verify root signature
	verifier, err := client.NewLogVerifierFromTree(tree)
	if err != nil {
		return nil, nil, err
	}
	_, err = tcrypto.VerifySignedLogRoot(verifier.PubKey,
		crypto.SHA256, ilr.Created)
	if err != nil {
		return nil, nil, err
	}

	return tree, ilr.Created, nil
}
