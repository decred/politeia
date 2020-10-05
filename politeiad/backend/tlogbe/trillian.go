// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlogbe

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/decred/politeia/util"
	"github.com/golang/protobuf/ptypes"
	"github.com/google/trillian"
	"github.com/google/trillian/client"
	tcrypto "github.com/google/trillian/crypto"
	"github.com/google/trillian/crypto/keys"
	"github.com/google/trillian/crypto/keys/der"
	"github.com/google/trillian/crypto/keyspb"
	"github.com/google/trillian/crypto/sigpb"
	"github.com/google/trillian/merkle/hashers"
	"github.com/google/trillian/merkle/rfc6962"
	"github.com/google/trillian/types"
	"google.golang.org/genproto/protobuf/field_mask"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/status"
)

// trillianClient provides a client that abstracts over the existing
// TrillianLogClient and TrillianAdminClient. This provides a simplified API
// for the backend to use and ensures that proper verification of all trillian
// responses is performed.
type trillianClient struct {
	host       string
	grpc       *grpc.ClientConn
	client     trillian.TrillianLogClient
	admin      trillian.TrillianAdminClient
	ctx        context.Context
	privateKey *keyspb.PrivateKey // Trillian signing key
	publicKey  crypto.PublicKey   // Trillian public key
}

// leafProof contains a log leaf and the inclusion proof for the log leaf.
type leafProof struct {
	Leaf  *trillian.LogLeaf
	Proof *trillian.Proof
}

// queuedLeafProof contains the results of a leaf append command, i.e. the
// QueuedLeaf, and the inclusion proof for that leaf. The inclusion proof will
// not be present if the leaf append command failed. The QueuedLeaf will
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

func logLeafNew(value []byte, extraData []byte) *trillian.LogLeaf {
	return &trillian.LogLeaf{
		LeafValue: value,
		ExtraData: extraData,
	}
}

// treeNew returns a new trillian tree and verifies that the signatures are
// correct. It returns the tree and the signed log root which can be externally
// verified.
func (t *trillianClient) treeNew() (*trillian.Tree, *trillian.SignedLogRoot, error) {
	log.Tracef("trillian treeNew")

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

func (t *trillianClient) treeFreeze(treeID int64) (*trillian.Tree, error) {
	log.Tracef("trillian treeFreeze: %v", treeID)

	// Get the current tree
	tree, err := t.tree(treeID)
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

func (t *trillianClient) tree(treeID int64) (*trillian.Tree, error) {
	log.Tracef("trillian tree: %v", treeID)

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

func (t *trillianClient) treesAll() ([]*trillian.Tree, error) {
	log.Tracef("trillian treesAll")

	ltr, err := t.admin.ListTrees(t.ctx, &trillian.ListTreesRequest{})
	if err != nil {
		return nil, err
	}

	return ltr.Tree, nil
}

func (t *trillianClient) inclusionProof(treeID int64, merkleLeafHash []byte, lrv1 *types.LogRootV1) (*trillian.Proof, error) {
	log.Tracef("tillian inclusionProof: %v %x", treeID, merkleLeafHash)

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

func (t *trillianClient) signedLogRootForTree(tree *trillian.Tree) (*trillian.SignedLogRoot, *types.LogRootV1, error) {
	// Get the signed log root for the current tree height
	resp, err := t.client.GetLatestSignedLogRoot(t.ctx,
		&trillian.GetLatestSignedLogRootRequest{LogId: tree.TreeId})
	if err != nil {
		return nil, nil, err
	}

	// Verify the log root
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

// signedLogRoot returns the signed log root for the provided tree ID at its
// current height. The log root is structure is decoded an returned as well.
func (t *trillianClient) signedLogRoot(treeID int64) (*trillian.SignedLogRoot, *types.LogRootV1, error) {
	log.Tracef("trillian signedLogRoot: %v", treeID)

	tree, err := t.tree(treeID)
	if err != nil {
		return nil, nil, fmt.Errorf("tree: %v", err)
	}
	slr, lr, err := t.signedLogRootForTree(tree)
	if err != nil {
		return nil, nil, fmt.Errorf("signedLogRoot: %v", err)
	}

	return slr, lr, nil
}

// leavesAppend appends the provided leaves onto the provided tree. The queued
// leaf and the leaf inclusion proof are returned. If a leaf was not
// successfully appended, the queued leaf will still be returned and the error
// will be in the queued leaf. Inclusion proofs will not exist for leaves that
// fail to be appended. Note leaves that are duplicates will fail and it is the
// callers responsibility to determine how they should be handled.
func (t *trillianClient) leavesAppend(treeID int64, leaves []*trillian.LogLeaf) ([]queuedLeafProof, *types.LogRootV1, error) {
	log.Tracef("trillian leavesAppend: %v", treeID)

	// Get the latest signed log root
	tree, err := t.tree(treeID)
	if err != nil {
		return nil, nil, err
	}
	slr, _, err := t.signedLogRootForTree(tree)
	if err != nil {
		return nil, nil, fmt.Errorf("signedLogRootForTree pre update: %v", err)
	}

	// Ensure the tree is not frozen
	if tree.TreeState == trillian.TreeState_FROZEN {
		return nil, nil, fmt.Errorf("tree is frozen")
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
	slr, lrv1, err := t.signedLogRootForTree(tree)
	if err != nil {
		return nil, nil, fmt.Errorf("signedLogRootForTree post update: %v", err)
	}

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
		// because they were a duplicate.
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

func (t *trillianClient) leavesByRange(treeID int64, startIndex, count int64) ([]*trillian.LogLeaf, error) {
	log.Tracef("trillian leavesByRange: %v %v %v", treeID, startIndex, count)

	glbrr, err := t.client.GetLeavesByRange(t.ctx,
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

// leavesAll returns all of the leaves for the provided treeID.
func (t *trillianClient) leavesAll(treeID int64) ([]*trillian.LogLeaf, error) {
	log.Tracef("trillian leavesAll: %v", treeID)

	// Get log root
	_, lr, err := t.signedLogRoot(treeID)
	if err != nil {
		return nil, fmt.Errorf("SignedLogRoot: %v", err)
	}
	if lr.TreeSize == 0 {
		return []*trillian.LogLeaf{}, nil
	}

	// Default gprc max message size is 4MB (4194304 bytes). We need to
	// increase this when fetching all leaves.
	// maxMsgSize := grpc.MaxCallSendMsgSize(6000000)

	// Get all leaves
	return t.leavesByRange(treeID, 0, int64(lr.TreeSize))
}

// leafProofs returns the leafProofs for the provided treeID and merkle leaf
// hashes. The inclusion proof returned in the leafProof is for the tree height
// specified by the provided LogRootV1.
func (t *trillianClient) leafProofs(treeID int64, merkleLeafHashes [][]byte, lr *types.LogRootV1) ([]leafProof, error) {
	log.Tracef("trillian leafProofs: %v %v %x",
		treeID, lr.TreeSize, merkleLeafHashes)

	// Retrieve leaves
	r, err := t.client.GetLeavesByHash(t.ctx,
		&trillian.GetLeavesByHashRequest{
			LogId:    treeID,
			LeafHash: merkleLeafHashes,
		})
	if err != nil {
		return nil, fmt.Errorf("GetLeavesByHashRequest: %v", err)
	}

	// Retrieve proofs
	proofs := make([]leafProof, 0, len(r.Leaves))
	for _, v := range r.Leaves {
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

// close closes the trillian grpc connection.
func (t *trillianClient) close() {
	log.Tracef("trillian close %v", t.host)

	t.grpc.Close()
}

func newTrillianClient(host, keyFile string) (*trillianClient, error) {
	// Setup trillian key file
	if !util.FileExists(keyFile) {
		// Trillian key file does not exist. Create one.
		log.Infof("Generating trillian private key")
		key, err := keys.NewFromSpec(&keyspb.Specification{
			// TODO Params: &keyspb.Specification_Ed25519Params{},
			Params: &keyspb.Specification_EcdsaParams{},
		})
		if err != nil {
			return nil, err
		}
		b, err := der.MarshalPrivateKey(key)
		if err != nil {
			return nil, err
		}
		err = ioutil.WriteFile(keyFile, b, 0400)
		if err != nil {
			return nil, err
		}
		log.Infof("Trillian private key created: %v", keyFile)
	}

	// Default gprc max message size is ~4MB (4194304 bytes). This is
	// not large enough for trees with tens of thousands of leaves.
	// Increase it to 20MB.
	maxMsgSize := grpc.WithMaxMsgSize(20000000)

	// Setup trillian connection
	// TODO should this be WithInsecure?
	g, err := grpc.Dial(host, grpc.WithInsecure(), maxMsgSize)
	if err != nil {
		return nil, fmt.Errorf("grpc dial: %v", err)
	}

	// Load trillian key pair
	var privateKey = &keyspb.PrivateKey{}
	privateKey.Der, err = ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	signer, err := der.UnmarshalPrivateKey(privateKey.Der)
	if err != nil {
		return nil, err
	}

	t := trillianClient{
		grpc:       g,
		client:     trillian.NewTrillianLogClient(g),
		admin:      trillian.NewTrillianAdminClient(g),
		ctx:        context.Background(),
		privateKey: privateKey,
		publicKey:  signer.Public(),
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
