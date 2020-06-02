// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlogbe

import (
	"bytes"
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

// leafProof contains a log leaf and the inclusion proof for the log leaf.
type leafProof struct {
	Leaf  *trillian.LogLeaf
	Proof *trillian.Proof
}

// queuedLeafProof contains the results of a leaf append command, i.e. the
// QueuedLeaf, and the inclusion proof for that leaf. The inclusion proof will
// not be present if the leaf append command failed and the QueuedLeaf will
// contain the error code from the failure.
type queuedLeafProof struct {
	QueuedLeaf *trillian.QueuedLogLeaf
	Proof      *trillian.Proof
}

// merkleLeafHash returns the merkle leaf hash for the provided leaf value.
// This is the same merkle leaf hash that is calculated by trillian.
func merkleLeafHash(leafValue []byte) []byte {
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

func (t *tlogbe) tree(treeID int64) (*trillian.Tree, error) {
	log.Tracef("tree: %v", treeID)

	tree, err := t.admin.GetTree(t.ctx, &trillian.GetTreeRequest{
		TreeId: treeID,
	})
	if err != nil {
		return nil, fmt.Errorf("GetTree: %v", err)
	}
	if tree.TreeId != treeID {
		// Sanity check
		return nil, fmt.Errorf("wrong tree returned; got %v, want %v",
			tree.TreeId, treeID)
	}

	return tree, nil
}

// treeNew returns a new trillian tree and verifies that the signatures are
// correct. It returns the tree and the signed log root which can be externally
// verified.
func (t *tlogbe) treeNew() (*trillian.Tree, *trillian.SignedLogRoot, error) {
	log.Tracef("treeNew")

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

func (t *tlogbe) signedLogRoot(tree *trillian.Tree) (*trillian.SignedLogRoot, *types.LogRootV1, error) {
	log.Tracef("signedLogRoot: %v", tree.TreeId)

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

func (t *tlogbe) inclusionProof(treeID int64, merkleLeafHash []byte, lrv1 *types.LogRootV1) (*trillian.Proof, error) {
	log.Tracef("inclusionProof: %v %x", treeID, merkleLeafHash)

	resp, err := t.client.GetInclusionProofByHash(t.ctx,
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
	lh, err := hashers.NewLogHasher(trillian.HashStrategy_RFC6962_SHA256)
	if err != nil {
		return nil, err
	}
	verifier := client.NewLogVerifier(lh, t.publicKey, crypto.SHA256)
	err = verifier.VerifyInclusionByHash(lrv1, merkleLeafHash, proof)
	if err != nil {
		return nil, fmt.Errorf("VerifyInclusionByHash: %v", err)
	}

	return proof, nil
}

func (t *tlogbe) leavesByHash(treeID int64, merkleLeafHashes [][]byte) ([]*trillian.LogLeaf, error) {
	log.Tracef("leavesByHash: %v %x", treeID, merkleLeafHashes)

	res, err := t.client.GetLeavesByHash(t.ctx,
		&trillian.GetLeavesByHashRequest{
			LogId:    treeID,
			LeafHash: merkleLeafHashes,
		})
	if err != nil {
		return nil, fmt.Errorf("GetLeavesByHashRequest: %v", err)
	}

	return res.Leaves, nil
}

// leavesAppend appends the provided leaves onto the provided tree. The leaf
// and the inclusion proof for the leaf are returned. If a leaf was not
// successfully appended, the leaf will be returned without an inclusion proof.
// The error status code can be found in the returned leaf. Note leaves that
// are duplicates will fail and it is the callers responsibility to determine
// how they should be handled.
func (t *tlogbe) leavesAppend(treeID int64, leaves []*trillian.LogLeaf) ([]queuedLeafProof, *types.LogRootV1, error) {
	log.Tracef("leavesAppend: %v", treeID)

	// Get the latest signed log root
	tree, err := t.tree(treeID)
	if err != nil {
		return nil, nil, err
	}
	slr, _, err := t.signedLogRoot(tree)
	if err != nil {
		return nil, nil, fmt.Errorf("signedLogRoot pre update: %v", err)
	}

	log.Debugf("Appending %v leaves to tree id %v", len(leaves), treeID)

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
		// Wait for root update
		log.Debugf("Waiting for root update")

		var logRoot types.LogRootV1
		err := logRoot.UnmarshalBinary(slr.LogRoot)
		if err != nil {
			return nil, nil, err
		}
		c, err := client.NewFromTree(t.client, tree, logRoot)
		if err != nil {
			return nil, nil, err
		}
		_, err = c.WaitForRootUpdate(t.ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("WaitForRootUpdate: %v", err)
		}
	}

	log.Debugf("Stored/Ignored leaves: %v/%v", len(leaves)-n, n)

	// Get the latest signed log root
	slr, lrv1, err := t.signedLogRoot(tree)
	if err != nil {
		return nil, nil, fmt.Errorf("signedLogRoot post update: %v", err)
	}

	// The tree is now dirty
	t.dirtyAdd(treeID, lrv1.TreeSize)

	// Get inclusion proofs
	proofs := make([]queuedLeafProof, 0, len(qlr.QueuedLeaves))
	for _, v := range qlr.QueuedLeaves {
		qlp := queuedLeafProof{
			QueuedLeaf: v,
		}

		// Only retrieve the inclusion proof if the leaf was successfully
		// appended. Leaves that were not successfully appended will be
		// returned without an inclusion proof and the caller can decide
		// what to do. Note this includes leaves that were not appended
		// becuase they were a duplicate.
		c := codes.Code(v.GetStatus().GetCode())
		if c == codes.OK {
			// Validate merkle leaf hash. We compute the merkle leaf hash in
			// other parts of tlogbe manually so we need to ensure that the
			// returned merkle leaf hashes are what we expect.
			m := merkleLeafHash(v.Leaf.LeafValue)
			if !bytes.Equal(m, v.Leaf.MerkleLeafHash) {
				e := fmt.Sprintf("unknown merkle leaf hash: got %x, want %x",
					m, v.Leaf.MerkleLeafHash)
				panic(e)
			}

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

	return proofs, lrv1, nil
}

func (t *tlogbe) leafProofs(treeID int64, merkleLeafHashes [][]byte, lr *types.LogRootV1) ([]leafProof, error) {
	// Retrieve leaves
	leaves, err := t.leavesByHash(treeID, merkleLeafHashes)
	if err != nil {
		return nil, err
	}

	// Retrieve proofs
	proofs := make([]leafProof, 0, len(leaves))
	for _, v := range leaves {
		p, err := t.inclusionProof(treeID, v.MerkleLeafHash, lr)
		if err != nil {
			return nil, fmt.Errorf("inclusionProof %x: %v", v.MerkleLeafHash, err)
		}
		proofs = append(proofs, leafProof{
			Leaf:  v,
			Proof: p,
		})
	}

	return proofs, nil
}
