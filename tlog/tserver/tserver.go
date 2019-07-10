package main

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	v1 "github.com/decred/politeia/tlog/api/v1"
	"github.com/decred/politeia/util"
	"github.com/decred/politeia/util/version"
	"github.com/golang/protobuf/ptypes"
	"github.com/google/trillian"
	"github.com/google/trillian/client"
	tcrypto "github.com/google/trillian/crypto"
	"github.com/google/trillian/crypto/keys"
	"github.com/google/trillian/crypto/keys/der"
	"github.com/google/trillian/crypto/keyspb"
	"github.com/google/trillian/crypto/sigpb"
	_ "github.com/google/trillian/merkle/rfc6962"
	"github.com/google/trillian/types"
	"github.com/gorilla/mux"
	"github.com/robfig/cron"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type tserver struct {
	sync.RWMutex

	// dirty keeps track of which tree is dirty at what height. At
	// start-of-day we scan all records and look for STH that have not been
	// anchored. Note that we only anchor the latest STH and do so
	// opportunistically. If the application is closed and restarted it
	// simply will drop a new anchor at the next interval; it will not try
	// to finish a prior outstanding anchor drop.
	dirty          map[int64]int64 // [treeid]height
	droppingAnchor bool            // anchor dropping is in progress

	s Blob // Storage interface

	cron *cron.Cron // Scheduler for periodic tasks

	cfg    *config
	router *mux.Router
	client trillian.TrillianLogClient
	admin  trillian.TrillianAdminClient
	ctx    context.Context

	signingKey    *keyspb.PrivateKey // trillian signing key
	publicKeyDER  []byte             // DER encoded public key
	encryptionKey [32]byte           // secretbox key for data at rest
}

//func convertTrillianDuration(p *durpb.Duration) int64 {
//	d, err := ptypes.Duration(p)
//	if err != nil {
//		panic(err)
//	}
//	return int64(d)
//}
//
//func convertTrillianTimestamp(ts *timestamp.Timestamp) int64 {
//	if ts == nil {
//		return 0
//	}
//	return time.Unix(ts.Seconds, int64(ts.Nanos)).Unix()
//}

func remoteAddr(r *http.Request) string {
	via := r.RemoteAddr
	xff := r.Header.Get(v1.Forward)
	if xff != "" {
		return fmt.Sprintf("%v via %v", xff, r.RemoteAddr)
	}
	return via
}

// closeBody closes the request body after the provided handler is called.
func closeBody(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f(w, r)
		r.Body.Close()
	}
}

func logging(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Trace incoming request
		log.Tracef("%v", newLogClosure(func() string {
			trace, err := httputil.DumpRequest(r, true)
			if err != nil {
				trace = []byte(fmt.Sprintf("logging: "+
					"DumpRequest %v", err))
			}
			return string(trace)
		}))

		// Log incoming connection
		log.Infof("%v %v %v %v", remoteAddr(r), r.Method, r.URL, r.Proto)
		f(w, r)
	}
}

// RespondWithError returns an HTTP error status to the client. If it's a user
// error, it returns a 4xx HTTP status and the specific user error code. If it's
// an internal server error, it returns 500 and an error code which is also
// outputted to the logs so that it can be correlated later if the user
// files a complaint.
func RespondWithError(w http.ResponseWriter, r *http.Request, userHttpCode int, format string, args ...interface{}) {
	// XXX this function needs to get an error in and a format + args
	// instead of what it is doing now.
	// So inError error, format string, args ...interface{}
	// if err == nil -> internal error using format + args
	// if err != nil -> if defined error -> return defined error + log.Errorf format+args
	// if err != nil -> if !defined error -> return + log.Errorf format+args
	if userErr, ok := args[0].(v1.UserError); ok {
		if userHttpCode == 0 {
			userHttpCode = http.StatusBadRequest
		}

		if len(userErr.ErrorContext) == 0 {
			log.Errorf("RespondWithError: %v %v %v",
				remoteAddr(r),
				int64(userErr.ErrorCode),
				v1.ErrorStatus[userErr.ErrorCode])
		} else {
			log.Errorf("RespondWithError: %v %v %v: %v",
				remoteAddr(r),
				int64(userErr.ErrorCode),
				v1.ErrorStatus[userErr.ErrorCode],
				strings.Join(userErr.ErrorContext, ", "))
		}

		util.RespondWithJSON(w, userHttpCode,
			v1.ErrorReply{
				ErrorCode:    int64(userErr.ErrorCode),
				ErrorContext: userErr.ErrorContext,
			})
		return
	}

	errorCode := time.Now().Unix()
	ec := fmt.Sprintf("%v %v %v %v Internal error %v: ", remoteAddr(r),
		r.Method, r.URL, r.Proto, errorCode)
	log.Errorf(ec+format, args...)
	log.Errorf("Stacktrace (NOT A REAL CRASH): %s", debug.Stack())

	util.RespondWithJSON(w, http.StatusInternalServerError,
		v1.ErrorReply{
			ErrorCode: errorCode,
		})
}

func (t *tserver) addRoute(method string, route string, handler http.HandlerFunc) {
	handler = closeBody(logging(handler))

	t.router.StrictSlash(true).HandleFunc(route, handler).Methods(method)
}

func (t *tserver) getTree(treeId int64) (*trillian.Tree, error) {
	// Verify tree exists
	tree, err := t.admin.GetTree(t.ctx, &trillian.GetTreeRequest{
		TreeId: treeId,
	})
	if err != nil {
		return nil, err
	}
	if tree.TreeId != treeId {
		// XXX really shouldn't happen
		return nil, fmt.Errorf("invalid tree returned got %v wanted %v",
			tree.TreeId, treeId)
	}
	return tree, nil
}

func (t *tserver) list(w http.ResponseWriter, r *http.Request) {
	// Ignore structure since it is empty
	ltr, err := t.admin.ListTrees(t.ctx, &trillian.ListTreesRequest{})
	if err != nil {
		RespondWithError(w, r, 0, "list: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, v1.ListReply{Trees: ltr.Tree})
}

// getLatestSignedLogRoot retrieves the latest signed root and verifies the
// signatures.
func (t *tserver) getLatestSignedLogRoot(tree *trillian.Tree) (*trillian.SignedLogRoot, *types.LogRootV1, error) {
	// get latest signed root
	resp, err := t.client.GetLatestSignedLogRoot(t.ctx,
		&trillian.GetLatestSignedLogRootRequest{LogId: tree.TreeId})
	if err != nil {
		return nil, nil, err
	}

	// verify root
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

// createTree creates a new trillian tree and verifies that the signatures are
// correct. It returns the tree and the signed log root which can be externally
// verified.
func (t *tserver) createTree() (*trillian.Tree, *trillian.SignedLogRoot, error) {
	k, err := ptypes.MarshalAny(t.signingKey)
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
			//SignatureAlgorithm: sigpb.DigitallySigned_ED25519,
			DisplayName:     "",
			Description:     "",
			MaxRootDuration: ptypes.DurationProto(0),
			PrivateKey:      k,
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

// waitForRootUpdate waits until the trillian root is updated. This code is
// clunky because we need a trillian.client context which we have to construct
// from known information. We probably should create our own client structure
// that does this with a saner API.
func (t *tserver) waitForRootUpdate(tree *trillian.Tree, root *trillian.SignedLogRoot) error {
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

func (t *tserver) countErrors(qlr *trillian.QueueLeavesResponse) int {
	var n int
	for k := range qlr.QueuedLeaves {
		c := codes.Code(qlr.QueuedLeaves[k].GetStatus().GetCode())
		if c != codes.OK {
			n++
		}
	}
	return n
}

// getEntry returns the record entry proof for the provided leaf.
// XXX we need to not return internal errors
func (t *tserver) getEntry(id int64, leaf *trillian.LogLeaf) (re v1.RecordEntryProof) {
	// Retrieve record entry
	payload, err := t.s.Get(leaf.ExtraData)
	if err != nil {
		re.Error = fmt.Sprintf("Get: %v", err)
		return
	}
	entry, err := deblob(payload)
	if err != nil {
		re.Error = fmt.Sprintf("deblob: %v", err)
		return
	}

	// Retrieve anchor
	da, err := t.findLeafAnchor(id, leaf)
	if err != nil {
		re.Error = fmt.Sprintf("findLeafAnchor: %v", err)
		return
	}
	if da == nil {
		// Entry hasn't been anchored yet. No need to continue.
		re.RecordEntry = entry
		re.Leaf = leaf
		return
	}
	var lrv1 types.LogRootV1
	err = lrv1.UnmarshalBinary(da.STH.LogRoot)
	if err != nil {
		re.Error = fmt.Sprintf("unmarshal LogRootV1: %v", err)
		return
	}

	// Retrieve inclusion proof for anchored LogRoot
	gipr, err := t.client.GetInclusionProof(t.ctx,
		&trillian.GetInclusionProofRequest{
			LogId:     id,
			LeafIndex: leaf.LeafIndex,
			TreeSize:  int64(lrv1.TreeSize), // tree size when anchor was dropped
		})
	if err != nil {
		re.Error = fmt.Sprintf("GetInclusionProof: %v", err)
		return
	}

	// Fill record out
	re.RecordEntry = entry
	re.Leaf = leaf
	re.STH = &da.STH
	re.Proof = gipr.Proof
	re.Anchor = &da.VerifyDigest.ChainInformation

	return
}

// getEntries returns the record entry proofs for the provided leaf hashes.
// XXX we need to not return internal errors
func (t *tserver) getEntries(id int64, leafHashes [][]byte) ([]v1.RecordEntryProof, error) {
	// Retrieve leaves
	glbhr, err := t.client.GetLeavesByHash(t.ctx,
		&trillian.GetLeavesByHashRequest{
			LogId:    id,
			LeafHash: leafHashes,
		})
	if err != nil {
		return nil, fmt.Errorf("GetLeavesByHashRequest: %v", err)
	}
	if len(glbhr.Leaves) != len(leafHashes) {
		return nil, fmt.Errorf("leaf not found")
	}

	// Retrieve record entry proofs
	rep := make([]v1.RecordEntryProof, 0, len(glbhr.Leaves))
	for _, v := range glbhr.Leaves {
		rep = append(rep, t.getEntry(id, v))
	}

	return rep, nil
}

// unwindBlobs deletes the passed in blobs from the backend. This function
// panics if anything goes wrong.
func (t *tserver) unwindBlobs(blobIDs map[string]struct{}) {
	var failed bool
	for id, _ := range blobIDs {
		log.Debugf("Unwinding blob %s", id)
		err := t.s.Del([]byte(id))
		if err != nil {
			log.Critical("del blob %s: %v", id, err)
			failed = true
		}
	}
	if failed {
		// We are in trouble!
		panic("could not unwind blobs")
	}
}

// appendRecord stores pointers to record entries into trillian and data into a
// backend.
func (t *tserver) appendRecord(tree *trillian.Tree, root *trillian.SignedLogRoot, re []v1.RecordEntry) ([]v1.QueuedLeafProof, *trillian.SignedLogRoot, error) {
	ll := make([]*trillian.LogLeaf, 0, len(re))
	blobIDs := make(map[string]struct{}, len(re)) // [blobID]struct{}
	for _, v := range re {
		blob, err := blobify(v)
		if err != nil {
			t.unwindBlobs(blobIDs)
			return nil, nil, fmt.Errorf("appendRecord blobify: %v",
				err)
		}
		id, err := t.s.Put(blob)
		if err != nil {
			t.unwindBlobs(blobIDs)
			return nil, nil, fmt.Errorf("appendRecord Put: %v", err)
		}
		blobIDs[string(id)] = struct{}{}

		h, err := hex.DecodeString(v.Hash)
		if err != nil {
			// Shouldn't happen, really should be a panic
			t.unwindBlobs(blobIDs)
			return nil, nil, fmt.Errorf("appendRecord DecodeString: %v",
				err)
		}

		ll = append(ll, &trillian.LogLeaf{
			LeafValue: h, // use hash data so that we can collide dups
			ExtraData: id,
		})
	}
	log.Debugf("Stored record entries: %v %v", len(ll), tree.TreeId)

	// Store all records as leafs
	qlr, err := t.client.QueueLeaves(t.ctx, &trillian.QueueLeavesRequest{
		LogId:  tree.TreeId,
		Leaves: ll,
	})
	if err != nil {
		t.unwindBlobs(blobIDs)
		return nil, nil, fmt.Errorf("appendRecord QueueLeaves: %v", err)
	}

	// Count errors to see if we need to wait
	n := t.countErrors(qlr)
	log.Debugf("Stored/Ignored leaves: %v/%v %v", len(ll)-n, n, tree.TreeId)

	// Unwind blobs of ignored leaves
	if n != 0 {
		ignored := make(map[string]struct{})
		for _, v := range qlr.QueuedLeaves {
			c := codes.Code(v.GetStatus().GetCode())
			if c != codes.OK {
				// Blob ID is stored in Leaf.ExtraData
				ignored[string(v.Leaf.ExtraData)] = struct{}{}
				delete(blobIDs, string(v.Leaf.ExtraData))
			}
		}
		t.unwindBlobs(ignored)
	}

	// Only wait if we actually updated the tree
	if len(ll)-n != 0 {
		// Wait for update
		log.Debugf("Waiting for update: %v", tree.TreeId)
		err = t.waitForRootUpdate(tree, root)
		if err != nil {
			t.unwindBlobs(blobIDs)
			return nil, nil, fmt.Errorf("appendRecord "+
				"waitForRootUpdate: %v", err)
		}
	}

	// Get latest signed tree head
	sth, lrv1, err := t.getLatestSignedLogRoot(tree)
	if err != nil {
		t.unwindBlobs(blobIDs)
		return nil, nil, fmt.Errorf("appendRecord "+
			"getLatestSignedLogRoot: %v", err)
	}

	// Get inclusion proofs
	proofs := make([]v1.QueuedLeafProof, 0, len(qlr.QueuedLeaves))
	for _, v := range qlr.QueuedLeaves {
		qllp := v1.QueuedLeafProof{
			QueuedLeaf: *v,
		}
		c := codes.Code(v.GetStatus().GetCode())
		if c == codes.OK {
			// LeafIndex of a QueuedLogLeaf will not be set so
			// get the inclusion proof by hash.
			resp, err := t.client.GetInclusionProofByHash(t.ctx,
				&trillian.GetInclusionProofByHashRequest{
					LogId:    tree.TreeId,
					LeafHash: v.Leaf.MerkleLeafHash,
					TreeSize: int64(lrv1.TreeSize),
				})
			if err != nil {
				t.unwindBlobs(blobIDs)
				return nil, nil, fmt.Errorf("appendRecord "+
					"GetInclusionProof: %v", err)
			}
			if len(resp.Proof) != 1 {
				t.unwindBlobs(blobIDs)
				return nil, nil, fmt.Errorf("appendRecord "+
					"%v proofs != 1", v.Leaf.MerkleLeafHash)
			}
			qllp.Proof = resp.Proof[0]
		}
		proofs = append(proofs, qllp)
	}

	// Mark dirty
	t.Lock()
	t.dirty[tree.TreeId] = int64(lrv1.TreeSize)
	t.Unlock()

	return proofs, sth, nil
}

// publicKey returns the public key to the caller.
func (t *tserver) publicKey(w http.ResponseWriter, r *http.Request) {
	log.Tracef("publicKey")

	util.RespondWithJSON(w, http.StatusOK, v1.PublicKeyReply{
		SigningKey: base64.StdEncoding.EncodeToString(t.publicKeyDER),
	})
}

// recordNew creates a new record that consists of various entries.
func (t *tserver) recordNew(w http.ResponseWriter, r *http.Request) {
	log.Tracef("recordNew")

	// Decode incoming record
	var rn v1.RecordNew
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&rn); err != nil {
		RespondWithError(w, r, 0, "recordNew: Unmarshal",
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidInput,
			})
		return
	}

	// Verify individual record entries
	for k := range rn.RecordEntries {
		err := util.RecordEntryVerify(rn.RecordEntries[k])
		if err != nil {
			// Abort entire thing if any RecordEntry is invalid
			e := fmt.Sprintf("recordNew RecordEntryVerify(%v): %v",
				k, err)
			RespondWithError(w, r, 0, "",
				v1.UserError{
					ErrorCode:    v1.ErrorStatusInvalidInput,
					ErrorContext: []string{e},
				})
			return
		}
	}

	// Create tree to hold record
	tree, root, err := t.createTree()
	if err != nil {
		RespondWithError(w, r, 0, "recordNew createTree: %v", err)
		return
	}
	log.Debugf("Created tree: %v", tree.TreeId)

	// Append record entries and data
	proofs, sth, err := t.appendRecord(tree, root, rn.RecordEntries)
	if err != nil {
		RespondWithError(w, r, 0, "recordNew appendRecord: %v", err)
		return
	}

	// Return the good news
	util.RespondWithJSON(w, http.StatusOK, v1.RecordNewReply{
		Tree:        *tree,
		InitialRoot: *root,
		STH:         *sth,
		Proofs:      proofs,
	})
}

// recordAppend appends record entries to a specified tree.
func (t *tserver) recordAppend(w http.ResponseWriter, r *http.Request) {
	log.Tracef("recordAppend")

	// Decode incoming record
	var ra v1.RecordAppend
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&ra); err != nil {
		RespondWithError(w, r, 0, "recordAppend: Unmarshal",
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidInput,
			})
		return
	}

	// Verify individual record entries
	for k := range ra.RecordEntries {
		err := util.RecordEntryVerify(ra.RecordEntries[k])
		if err != nil {
			// Abort entire thing if any RecordEntry is invalid
			e := fmt.Sprintf("recordAppend RecordEntryVerify(%v): %v",
				k, err)
			RespondWithError(w, r, 0, "",
				v1.UserError{
					ErrorCode:    v1.ErrorStatusInvalidInput,
					ErrorContext: []string{e},
				})
			return
		}
	}

	// Retrieve tree
	tree, err := t.getTree(ra.Id)
	if err != nil {
		e := fmt.Sprintf("invalid record id: %v", ra.Id)
		RespondWithError(w, r, 0, "recordAppend: getTree",
			v1.UserError{
				ErrorCode:    v1.ErrorStatusInvalidInput,
				ErrorContext: []string{e},
			})
		return
	}

	// Retrieve STH
	root, _, err := t.getLatestSignedLogRoot(tree)
	if err != nil {
		RespondWithError(w, r, 0, "recordAppend "+
			"getLatestSignedLogRoot: %v",
			err)
		return
	}
	// Append record entries and data
	proofs, sth, err := t.appendRecord(tree, root, ra.RecordEntries)
	if err != nil {
		RespondWithError(w, r, 0, "recordAppend appendRecord: %v", err)
		return
	}

	// Return the good news
	util.RespondWithJSON(w, http.StatusOK, v1.RecordAppendReply{
		STH:    *sth,
		Proofs: proofs,
	})
}

// recordGet returns the entire trillian tree and corresponding data.
func (t *tserver) recordGet(w http.ResponseWriter, r *http.Request) {
	// Decode incoming record
	var rg v1.RecordGet
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&rg); err != nil {
		RespondWithError(w, r, 0, "recordGet: Unmarshal",
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidInput,
			})
		return
	}

	// Retrieve tree
	tree, err := t.getTree(rg.Id)
	if err != nil {
		e := fmt.Sprintf("invalid record id: %v", rg.Id)
		RespondWithError(w, r, 0, "recordGet: getTree",
			v1.UserError{
				ErrorCode:    v1.ErrorStatusInvalidInput,
				ErrorContext: []string{e},
			})
		return
	}

	// Retrieve STH
	sth, lrv1, err := t.getLatestSignedLogRoot(tree)
	if err != nil {
		RespondWithError(w, r, 0, "recordGet getLatestSignedLogRoot: %v",
			err)
		return
	}

	// Get leaves
	glbrr, err := t.client.GetLeavesByRange(t.ctx,
		&trillian.GetLeavesByRangeRequest{
			LogId:      tree.TreeId,
			StartIndex: 0,
			Count:      int64(lrv1.TreeSize),
		})
	if err != nil {
		e := fmt.Sprintf("GetLeavesByRange: %v", err)
		RespondWithError(w, r, 0, "recordGet: getTree",
			v1.UserError{
				ErrorCode:    v1.ErrorStatusInvalidInput,
				ErrorContext: []string{e},
			})
		return
	}

	// Retrieve record entry proofs
	rep := make([]v1.RecordEntryProof, 0, len(glbrr.Leaves))
	for _, v := range glbrr.Leaves {
		rep = append(rep, t.getEntry(tree.TreeId, v))
	}

	// Return the good news
	util.RespondWithJSON(w, http.StatusOK, v1.RecordGetReply{
		STH:    *sth,
		Proofs: rep,
	})
}

// recordEntriesGet returns batched record entries and their proofs.
func (t *tserver) recordEntriesGet(w http.ResponseWriter, r *http.Request) {
	// Decode incoming record
	var reg v1.RecordEntriesGet
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&reg); err != nil {
		RespondWithError(w, r, 0, "recordEntriesGet: Unmarshal",
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidInput,
			})
		return
	}

	// Coalesce requests
	trees := make(map[int64][][]byte) // [treeId]merkleHashes
	for _, v := range reg.Entries {
		_, ok := trees[v.Id]
		if !ok {
			trees[v.Id] = make([][]byte, 0, len(reg.Entries))
		}
		h, err := hex.DecodeString(v.MerkleHash)
		if err != nil {
			// XXX we need to not return internal errors
			RespondWithError(w, r, 0, "decode merkle hash: %v", err)
			return
		}
		trees[v.Id] = append(trees[v.Id], h)
	}

	// Retrieve record entries
	rep := make([]v1.RecordEntryProof, 0, len(reg.Entries))
	for id, hashes := range trees {
		log.Debugf("recordEntriesGet: %v %x", id, hashes)
		entries, err := t.getEntries(id, hashes)
		if err != nil {
			RespondWithError(w, r, 0, "getEntries: %v", err)
			return
		}
		rep = append(rep, entries...)
	}

	util.RespondWithJSON(w, http.StatusOK, v1.RecordEntriesGetReply{
		Proofs: rep,
	})
}

// recordFsck run fsck on a record.
func (t *tserver) recordFsck(w http.ResponseWriter, r *http.Request) {
	// Decode incoming record
	var rf v1.RecordFsck
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&rf); err != nil {
		RespondWithError(w, r, 0, "recordFsck: Unmarshal",
			v1.UserError{
				ErrorCode: v1.ErrorStatusInvalidInput,
			})
		return
	}

	err := t.fsck(rf)
	if err != nil {
		RespondWithError(w, r, 0, "fsck: %v", err)
		return
	}

	util.RespondWithJSON(w, http.StatusOK, v1.RecordFsckReply{})
}

func _main() error {
	// Load configuration and parse command line.  This function also
	// initializes logging and configures it accordingly.
	loadedCfg, _, err := loadConfig()
	if err != nil {
		return fmt.Errorf("Could not load configuration file: %v", err)
	}
	defer func() {
		if logRotator != nil {
			logRotator.Close()
		}
	}()

	log.Infof("Version : %v", version.String())
	log.Infof("Network : %v", activeNetParams.Params.Name)
	log.Infof("Home dir: %v", loadedCfg.HomeDir)

	// Create the data directory in case it does not exist.
	err = os.MkdirAll(loadedCfg.DataDir, 0700)
	if err != nil {
		return err
	}

	// Generate the TLS cert and key file if both don't already
	// exist.
	if !util.FileExists(loadedCfg.HTTPSKey) &&
		!util.FileExists(loadedCfg.HTTPSCert) {
		log.Infof("Generating HTTPS keypair...")

		err := util.GenCertPair(elliptic.P521(), "tserver",
			loadedCfg.HTTPSCert, loadedCfg.HTTPSKey)
		if err != nil {
			return fmt.Errorf("unable to create https keypair: %v",
				err)
		}

		log.Infof("HTTPS keypair created...")
	}

	// Create new signing key
	if !util.FileExists(loadedCfg.SigningKey) {
		log.Infof("Generating signing key...")
		signingKey, err := keys.NewFromSpec(&keyspb.Specification{
			//Params: &keyspb.Specification_Ed25519Params{},
			Params: &keyspb.Specification_EcdsaParams{},
		})
		if err != nil {
			return err
		}
		b, err := der.MarshalPrivateKey(signingKey)
		if err != nil {
			return err
		}
		err = ioutil.WriteFile(loadedCfg.SigningKey, b, 0400)
		if err != nil {
			return err
		}

		log.Infof("Signing Key created...")
	}

	// Create new encryption key
	if !util.FileExists(loadedCfg.EncryptionKey) {
		log.Infof("Generating encryption key...")
		key, err := NewKey()
		if err != nil {
			return err
		}
		err = ioutil.WriteFile(loadedCfg.EncryptionKey, key[:], 0400)
		if err != nil {
			return err
		}

		log.Infof("EncryptionKey Key created...")
	}

	// Connect to trillian
	log.Infof("Trillian log server: %v", loadedCfg.TrillianHost)
	g, err := grpc.Dial(loadedCfg.TrillianHost, grpc.WithInsecure())
	if err != nil {
		return err
	}
	defer g.Close()

	// Dcrtime host
	log.Infof("Anchor host: %v", loadedCfg.DcrtimeHost)

	// Setup application context.
	t := &tserver{
		cfg:        loadedCfg,
		cron:       cron.New(),
		client:     trillian.NewTrillianLogClient(g),
		admin:      trillian.NewTrillianAdminClient(g),
		ctx:        context.Background(),
		signingKey: &keyspb.PrivateKey{},
		dirty:      make(map[int64]int64),
	}

	// Load certs, if there.  If they aren't there assume OS is used to
	// resolve cert validity.
	if len(loadedCfg.DcrtimeCert) != 0 {
		var certPool *x509.CertPool
		if !util.FileExists(loadedCfg.DcrtimeCert) {
			return fmt.Errorf("unable to find dcrtime cert %v",
				loadedCfg.DcrtimeCert)
		}
		dcrtimeCert, err := ioutil.ReadFile(loadedCfg.DcrtimeCert)
		if err != nil {
			return fmt.Errorf("unable to read dcrtime cert %v: %v",
				loadedCfg.DcrtimeCert, err)
		}
		certPool = x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(dcrtimeCert) {
			return fmt.Errorf("unable to load cert")
		}
	}

	// Load signing key
	t.signingKey.Der, err = ioutil.ReadFile(loadedCfg.SigningKey)
	if err != nil {
		return err
	}
	// Verify that it is DER encoded and extract public key DER
	privKey, err := der.UnmarshalPrivateKey(t.signingKey.Der)
	if err != nil {
		return err
	}
	t.publicKeyDER, err = der.MarshalPublicKey(privKey.Public())
	if err != nil {
		return err
	}

	// Load encryption key
	f, err := os.Open(loadedCfg.EncryptionKey)
	if err != nil {
		return err
	}
	n, err := f.Read(t.encryptionKey[:])
	if n != len(t.encryptionKey) {
		return fmt.Errorf("invalid key length")
	}
	if err != nil {
		return err
	}
	f.Close()

	// Setup storage
	t.s, err = BlobFilesystemNew(&t.encryptionKey, t.cfg.DataDir)
	if err != nil {
		return err
	}

	// Scan for unanchored records
	log.Infof("Scanning for unanchored records")
	err = t.scanAllRecords()
	if err != nil {
		return err
	}

	// Launch cron.
	err = t.cron.AddFunc(anchorSchedule, func() {
		t.anchorRecords()
	})
	if err != nil {
		return err
	}
	t.cron.Start()

	// XXX remove, this is for test only
	t.anchorRecords()

	// Setup mux
	t.router = mux.NewRouter()

	// Unprivileged routes
	t.addRoute(http.MethodPost, v1.RouteList, t.list)
	t.addRoute(http.MethodPost, v1.RoutePublicKey, t.publicKey)
	t.addRoute(http.MethodPost, v1.RouteRecordNew, t.recordNew)
	t.addRoute(http.MethodPost, v1.RouteRecordGet, t.recordGet)
	t.addRoute(http.MethodPost, v1.RouteRecordEntriesGet, t.recordEntriesGet)
	t.addRoute(http.MethodPost, v1.RouteRecordAppend, t.recordAppend)
	t.addRoute(http.MethodPost, v1.RouteRecordFsck, t.recordFsck)

	// Bind to a port and pass our router in
	listenC := make(chan error)
	for _, listener := range loadedCfg.Listeners {
		listen := listener
		go func() {
			log.Infof("Listen: %v", listen)
			listenC <- http.ListenAndServeTLS(listen,
				loadedCfg.HTTPSCert, loadedCfg.HTTPSKey,
				t.router)
		}()
	}

	// Tell user we are ready to go.
	log.Infof("Start of day")

	// Setup OS signals
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGINT)
	for {
		select {
		case sig := <-sigs:
			log.Infof("Terminating with %v", sig)
			goto done
		case err := <-listenC:
			log.Errorf("%v", err)
			goto done
		}
	}
done:
	log.Infof("Exiting")

	return nil
}

func main() {
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
