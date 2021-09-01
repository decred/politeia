// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tstore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	dcrtime "github.com/decred/dcrtime/api/v2"
	"github.com/decred/dcrtime/merkle"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
	"github.com/decred/politeia/util"
	"github.com/google/trillian"
	"github.com/google/trillian/types"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
)

// TODO verify anchor process works and can handle edge cases like politeiad
// exiting in the middle of an anchor drop.

const (
	// Blob entry data descriptors
	dataDescriptorAnchor         = "pd-anchor-v1"
	dataDescriptorDroppingAnchor = "pd-droppinganchor-v1"
)

var (
	// TODO I don't think I need this anymore. Use the store error.
	// errNotFound is returned when a record is not found in the
	// key-value store.
	errNotFound = errors.New("not found")
)

const (
	// anchorSchedule determines how often we anchor records. dcrtime
	// currently drops an anchor on the hour mark so we submit new
	// anchors a few minutes prior to that.
	//
	// The anchoring process is concurrency safe.
	//
	// Seconds Minutes Hours Days Months DayOfWeek
	anchorSchedule = "0 56 * * * *" // At minute 56 of every hour

	// anchorID is included in the dcrtime timestamp and verify
	// requests as the unique identifier.
	anchorID = "tstorebe"
)

// startAnchorProcess performs all required setup for the tstore anchoring
// process and starts the anchoring cron job.
func (t *Tstore) startAnchorProcess() error {
	log.Infof("Starting anchor process")

	// Setup a database transaction
	tx, cancel, err := t.Tx()
	if err != nil {
		return err
	}
	defer cancel()

	// Verify that a dropping anchor record exists
	_, err = getDroppingAnchor(tx)
	if err == errNotFound {
		// A dropping anchor record has not been created yet.
		// Create one and save it to the key-value store.
		d := newDroppingAnchor(false)
		err = d.save(tx)
		if err != nil {
			return err
		}
		log.Infof("Dropping anchor record initialized")
	} else if err != nil {
		return err
	}

	// Commit the database transaction
	err = tx.Commit()
	if err != nil {
		return err
	}

	// Launch anchor cron job
	return t.cron.AddFunc(anchorSchedule, func() {
		err := t.anchorTrees()
		if err != nil {
			log.Errorf("anchorTrees: %v", err)
		}
	})
}

const (
	// droppingAnchorKey is the key-value store key for the dropping
	// anchor record.
	droppingAnchorKey = "tstore-dropping-anchor"

	// droppingAnchorTimeout is used to manually timeout the previous
	// anchor drop. The anchor dropping process is too long to use a
	// database transaction so we must manually timeout and reset the
	// droppingAnchor record if an unexpected error occurs (ex. the
	// politeiad instance that is dropping the anchor crashes while
	// waiting for dcrtime to include the anchor in a DCR transaction).
	//
	// A DCR mainnet block has a 99.75% chance of being found within
	// 30 minutes. dcrtime does not return the timestamp transaction
	// information until the transaction has 6 confirmations. We can
	// safely assume that something went wrong with the anchor drop
	// and it needs to be timed out if 3 hours (30 minutes x 6 confs)
	// has passed.
	droppingAnchorTimeout int64 = 60 * 60 * 3 // 3 hours in seconds
)

// droppingAnchor is the record that is saved to the key-value store to make
// the anchor dropping process concurrency safe when multiple politeiad
// instances are being run. The first politeiad instance to pull this record
// from the key-value store is responsible for dropping the anchor for that
// specific anchor period.
//
// If the dropping anchor timeout is reached, any politeiad instance can reset
// the dropping anchor record and start a new anchor drop. This is used as a
// fail safe against unexpected errors and concurrency edge cases.
type droppingAnchor struct {
	InProgress bool  `json:"inprogress"` // Anchor drop is in progress
	Timestamp  int64 `json:"timestamp"`  // Unix timestamp of last update
}

// newDroppingAnchor returns a new droppingAnchor.
func newDroppingAnchor(inProgress bool) *droppingAnchor {
	return &droppingAnchor{
		InProgress: inProgress,
		Timestamp:  time.Now().Unix(),
	}
}

// encode encodes the droppingAnchor into a BlobEntry then encodes the BlobEnty
// into a gzipped byte slice.
func (d *droppingAnchor) encode() ([]byte, error) {
	data, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	dd := store.DataDescriptor{
		Type:       store.DataTypeStructure,
		Descriptor: dataDescriptorDroppingAnchor,
	}
	be, err := store.NewBlobEntry(dd, data)
	if err != nil {
		return nil, err
	}
	return store.Blobify(*be)
}

// save saves the droppingAnchor record to the key-value store using the
// provided database transaction.
//
// The transaction must be committed by the caller.
func (d *droppingAnchor) save(tx store.Tx) error {
	b, err := d.encode()
	if err != nil {
		return err
	}
	return tx.Put(map[string][]byte{
		droppingAnchorKey: b,
	}, false)
}

// decodeAnchor decodes a gzipped byte slice into a BlobEntry then decodes the
// BlobEntry into a droppingAnchor.
func decodeDroppingAnchor(gb []byte) (*droppingAnchor, error) {
	be, err := store.Deblob(gb)
	if err != nil {
		return nil, err
	}
	b, err := store.Decode(*be, dataDescriptorDroppingAnchor)
	if err != nil {
		return nil, err
	}
	var da droppingAnchor
	err = json.Unmarshal(b, &da)
	if err != nil {
		return nil, err
	}
	return &da, nil
}

// getDroppingAnchor retrieves the droppingAnchor record from the key-value
// store.
func getDroppingAnchor(s store.Getter) (*droppingAnchor, error) {
	blobs, err := s.GetBatch([]string{droppingAnchorKey})
	if err != nil {
		return nil, err
	}
	b, ok := blobs[droppingAnchorKey]
	if !ok {
		return nil, errNotFound
	}
	return decodeDroppingAnchor(b)
}

var (
	// errAlreadyInProgress is returned when a thread attempts to
	// update the dropping anchor record to in-progress while it's
	// already in-progress.
	errAlreadyInProgress = errors.New("dropping anchor in progress")
)

// droppingAnchorInProgress updates the droppingAnchor record in the key-value
// store to reflect that an anchor drop is in-progress.
//
// An errAlreadyInProgress error is returned if this function is called while
// an anchor drop is already in-progress.
func (t *Tstore) droppingAnchorInProgress() error {
	// Setup a database transaction
	tx, cancel, err := t.Tx()
	if err != nil {
		return err
	}
	defer cancel()

	// Get the dropping anchor record
	d, err := getDroppingAnchor(tx)
	if err != nil {
		return err
	}
	if d.InProgress {
		// Anchor drop is already in progress. Verify that the timeout
		// has not been reached.
		if time.Now().Unix() < (d.Timestamp + droppingAnchorTimeout) {
			// Timeout has not been reached yet
			return errAlreadyInProgress
		}

		// Something went wrong and the timeout has been reached.
		// Continue to the code below so that the dropping anchor
		// record is reset.
		log.Errorf("Anchor drop has timed out after %v seconds; "+
			"resetting the anchor drop record", droppingAnchorTimeout)
	}

	// Set the dropping anchor record to in-progress
	d = newDroppingAnchor(true)
	err = d.save(tx)
	if err != nil {
		return err
	}
	err = tx.Commit()
	if err != nil {
		return err
	}

	log.Debugf("Dropping anchor record set to in-progress")

	return nil
}

// droppingAnchorReset resets the dropping anchor record by setting the
// in-progress field to false and saving the updated record to the key-value
// store.
func (t *Tstore) droppingAnchorReset() error {
	// Setup a database transaction
	tx, cancel, err := t.Tx()
	if err != nil {
		return err
	}
	defer cancel()

	// Reset the dropping anchor record
	d := newDroppingAnchor(false)
	err = d.save(tx)
	if err != nil {
		return err
	}

	// Commit the database transaction
	err = tx.Commit()
	if err != nil {
		return err
	}

	log.Debugf("Dropping anchor record reset")

	return nil
}

// anchor represents an anchor, i.e. timestamp, of a trillian tree at a
// specific tree size.
//
// The LogRootV1.RootHash is the merkle root hash of a trillian tree. This root
// hash is submitted to dcrtime to be anchored and will be the digest that is
// returned in the VerifyDigest. Only the root hash is anchored, but the full
// LogRootV1 struct is saved as part of an anchor record so that it can be used
// to retrieve inclusion proofs for any leaves that are included in the root
// hash.
type anchor struct {
	TreeID       int64                 `json:"treeid"`
	LogRoot      *types.LogRootV1      `json:"logroot"`
	VerifyDigest *dcrtime.VerifyDigest `json:"verifydigest"`
}

// newAnchor returns a new anchor.
func newAnchor(treeID int64, lr *types.LogRootV1, vd *dcrtime.VerifyDigest) *anchor {
	return &anchor{
		TreeID:       treeID,
		LogRoot:      lr,
		VerifyDigest: vd,
	}
}

// sha256 returns the SHA256 digest of the JSON encoded anchor.
func (a *anchor) sha256() ([]byte, error) {
	b, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	return util.Digest(b), nil
}

// encode encodes the anchor into a BlobEntry then encodes the BlobEnty into a
// gzipped byte slice.
func (a *anchor) encode() ([]byte, error) {
	data, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	dd := store.DataDescriptor{
		Type:       store.DataTypeStructure,
		Descriptor: dataDescriptorAnchor,
	}
	be, err := store.NewBlobEntry(dd, data)
	if err != nil {
		return nil, err
	}
	return store.Blobify(*be)
}

// save saves the anchor to the key-value store then appends an anchor log leaf
// to the anchor's trillian tree.
func (a *anchor) save(kv store.BlobKV, tlog tlogClient) error {
	// Sanity checks
	switch {
	case a.TreeID == 0:
		return errors.Errorf("invalid tree id of 0")
	case a.LogRoot == nil:
		return errors.Errorf("log root not found")
	case a.VerifyDigest == nil:
		return errors.Errorf("verify digest not found")
	}

	// Save anchor record to the kv store
	b, err := a.encode()
	if err != nil {
		return err
	}
	key := newStoreKey(false)
	err = kv.Put(map[string][]byte{key: b}, false)
	if err != nil {
		return err
	}

	// Append a leaf to the tlog tree for the anchor. The anchor's
	// digest is saved as the leaf value. The kv store key for the
	// anchor record is saved as part of the leaf extra data.
	digest, err := a.sha256()
	if err != nil {
		return err
	}
	ed := newExtraData(key, dataDescriptorAnchor, 0)
	extraData, err := ed.encode()
	if err != nil {
		return err
	}
	leaves := []*trillian.LogLeaf{
		newLogLeaf(digest, extraData),
	}
	queued, _, err := tlog.LeavesAppend(a.TreeID, leaves)
	if err != nil {
		return err
	}
	if len(queued) != 1 {
		return errors.Errorf("wrong number of queud leaves: got %v, want 1",
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
		return errors.Errorf("append leaves failed: %v", failed)
	}

	log.Debugf("Anchor saved for tree %v at height %v",
		a.TreeID, a.LogRoot.TreeSize)

	return nil
}

// decodeAnchor decodes a gzipped byte slice into a BlobEntry then decodes the
// BlobEntry into a anchor.
func decodeAnchor(gb []byte) (*anchor, error) {
	be, err := store.Deblob(gb)
	if err != nil {
		return nil, err
	}
	b, err := store.Decode(*be, dataDescriptorAnchor)
	if err != nil {
		return nil, err
	}
	var a anchor
	err = json.Unmarshal(b, &a)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// getAnchor returns the anchor for a specific merkle leaf hash.
func getAnchor(kv store.BlobKV, treeID int64, merkleLeafHash []byte, leaves []*trillian.LogLeaf) (*anchor, error) {
	// Find the leaf for the provided merkle leaf hash
	var l *trillian.LogLeaf
	for i, v := range leaves {
		if bytes.Equal(v.MerkleLeafHash, merkleLeafHash) {
			l = v
			// Sanity check
			if l.LeafIndex != int64(i) {
				return nil, errors.Errorf("unexpected leaf index: got %v, want %v",
					l.LeafIndex, i)
			}
			break
		}
	}
	if l == nil {
		return nil, errors.Errorf("leaf not found")
	}

	// Find the first two anchor that occurs after the leaf. If the
	// leaf was added in the middle of an anchor drop then it will not
	// be part of the first anchor. It will be part of the second
	// anchor.
	keys := make([]string, 0, 2)
	for i := int(l.LeafIndex); i < len(leaves); i++ {
		l := leaves[i]
		ed, err := decodeExtraData(l.ExtraData)
		if err != nil {
			return nil, err
		}
		if ed.Desc == dataDescriptorAnchor {
			keys = append(keys, ed.key())
			if len(keys) == 2 {
				break
			}
		}
	}
	if len(keys) == 0 {
		// This leaf has not been anchored yet
		return nil, errNotFound
	}

	// Get the anchor records
	blobs, err := kv.GetBatch(keys)
	if err != nil {
		return nil, err
	}
	if len(blobs) != len(keys) {
		return nil, errors.Errorf("unexpected blobs count: got %v, want %v",
			len(blobs), len(keys))
	}

	// Find the correct anchor for the leaf
	var leafAnchor *anchor
	for _, v := range keys {
		b, ok := blobs[v]
		if !ok {
			return nil, errors.Errorf("blob not found %v", v)
		}
		a, err := decodeAnchor(b)
		if err != nil {
			return nil, err
		}
		if uint64(l.LeafIndex) < a.LogRoot.TreeSize {
			// The leaf is included in this anchor. We're done.
			leafAnchor = a
			break
		}
	}
	if leafAnchor == nil {
		// This leaf has not been anchored yet
		return nil, errNotFound
	}

	return leafAnchor, nil
}

// getAnchorLatest returns the most recent anchor for the provided tree. A
// errNotFound is returned if no anchor is found.
func getAnchorLatest(kv store.BlobKV, tlog tlogClient, treeID int64) (*anchor, error) {
	// Get tree leaves
	leavesAll, err := tlog.LeavesAll(treeID)
	if err != nil {
		return nil, err
	}

	// Find the most recent anchor leaf
	var key string
	for i := len(leavesAll) - 1; i >= 0; i-- {
		ed, err := decodeExtraData(leavesAll[i].ExtraData)
		if err != nil {
			return nil, err
		}
		if ed.Desc == dataDescriptorAnchor {
			key = ed.key()
			break
		}
	}
	if key == "" {
		return nil, errNotFound
	}

	// Pull blob from key-value store
	blobs, err := kv.GetBatch([]string{key})
	if err != nil {
		return nil, err
	}
	if len(blobs) != 1 {
		return nil, errors.Errorf("unexpected blobs count: got %v, want 1",
			len(blobs))
	}
	b, ok := blobs[key]
	if !ok {
		return nil, errors.Errorf("blob not found %v", key)
	}
	a, err := decodeAnchor(b)
	if err != nil {
		return nil, err
	}

	return a, nil
}

// anchorTrees drops an anchor for any trees that have unanchored leaves at the
// time of invocation. A SHA256 digest of the tree's log root at its current
// height is timestamped onto the decred blockchain using the dcrtime service.
// The anchor data is saved to the key-value store and the tlog tree is updated
// with an anchor leaf.
func (t *Tstore) anchorTrees() error {
	log.Infof("Checking for unanchored trees")

	// Update the dropping anchor record to in-progress. This prevents
	// concurrent anchor drops.
	err := t.droppingAnchorInProgress()
	if errors.Is(err, errAlreadyInProgress) {
		// An anchor drop is already in progress. There are two scenerios
		// where this can happen.
		//
		// 1. A different politeiad instance already started the anchor
		//    drop for this anchor period.
		//
		// 2. The previous anchor period has not completed yet. An anchor
		//    is not considered dropped until dcrtime returns the
		//    ChainTimestamp in the VerifyReply. dcrtime does not do this
		//    until the anchor tx has 6 confirmations, therefor, this
		//    code path can be hit if 6 blocks are not mined within the
		//    period specified by the anchor schedule. Though rare, the
		//    probability of this happening is not zero and should not be
		//    considered an error. We simply exit and will drop a new
		//    anchor at the next anchor period.
		//
		// The appropriate behavior is to exit gracefully.
		log.Infof("Anchor drop is already in progress; waiting for next drop")
		return nil

	} else if err != nil {
		// All other errors
		return err
	}

	// No matter what happens in this function we must reset the
	// dropping anchor record on exit.
	defer func() {
		err := t.droppingAnchorReset()
		if err != nil {
			log.Errorf("droppingAnchorReset: %v", err)
		}
	}()

	// Get all trees from tlog
	trees, err := t.tlog.TreesAll()
	if err != nil {
		return err
	}

	// digests contains the SHA256 digests of the LogRootV1.RootHash
	// for all trees that need to be anchored. These will be submitted
	// to dcrtime to be included in a dcrtime timestamp.
	digests := make([]string, 0, len(trees))

	// anchors contains an anchor structure for each tree that is being
	// anchored. Once the dcrtime timestamp is successful, these
	// anchors will be updated with the timestamp data and saved to the
	// key-value store.
	anchors := make([]*anchor, 0, len(trees))

	// Find the trees that need to be anchored. This is done by pulling
	// the most recent anchor from the tree and checking the anchored
	// tree height against the current tree height. We cannot rely on
	// the anchored being the last leaf in the tree since new leaves
	// can be added while the anchor is waiting to be dropped.
	for _, v := range trees {
		// Get the latest anchor.
		a, err := getAnchorLatest(t.store, t.tlog, v.TreeId)
		switch {
		case errors.Is(err, errNotFound):
			// Tree has not been anchored yet. Verify that the tree has
			// leaves. A tree with no leaves does not need to be anchored.
			leavesAll, err := t.tlog.LeavesAll(v.TreeId)
			if err != nil {
				return err
			}
			if len(leavesAll) == 0 {
				// Tree does not have any leaves. Nothing to do.
				continue
			}

		case err != nil:
			// All other errors
			return err

		default:
			// Anchor record found. If the anchor height differs from the
			// current height then the tree needs to be anchored.
			_, lr, err := t.tlog.SignedLogRoot(v)
			if err != nil {
				return err
			}
			// Subtract one from the current height to account for the
			// anchor leaf.
			if a.LogRoot.TreeSize == lr.TreeSize-1 {
				// Tree has already been anchored at this height. Nothing to
				// do.
				continue
			}
		}

		// Tree has not been anchored at current height. Add it to the
		// list of anchors.
		_, lr, err := t.tlog.SignedLogRoot(v)
		if err != nil {
			return err
		}
		anchors = append(anchors, newAnchor(v.TreeId, lr, nil))

		// Collate the tree's root hash. This is what gets submitted to
		// dcrtime.
		digests = append(digests, hex.EncodeToString(lr.RootHash))

		log.Debugf("Anchoring tree %v at height %v",
			v.TreeId, lr.TreeSize)
	}
	if len(anchors) == 0 {
		log.Infof("No trees to to anchor")
		return nil
	}

	// Submit dcrtime anchor request
	log.Infof("Anchoring %v trees", len(anchors))

	tbr, err := t.dcrtime.timestampBatch(anchorID, digests)
	if err != nil {
		return err
	}
	var failed bool
	for i, v := range tbr.Results {
		switch v {
		case dcrtime.ResultOK:
			// We're good; continue
		case dcrtime.ResultExistsError:
			// This can happen if politeiad was shutdown in the middle of
			// an anchor process. This is ok. The anchor process will pick
			// up where it left off.
			log.Warnf("Digest already exists %v: %v (%v)",
				tbr.Digests[i], dcrtime.Result[v], v)
		default:
			// Something went wrong; exit
			log.Errorf("Digest failed %v: %v (%v)",
				tbr.Digests[i], dcrtime.Result[v], v)
			failed = true
		}
	}
	if failed {
		return errors.Errorf("dcrtime failed to timestamp digests")
	}

	// Now we wait for the anchor to drop. The anchor is not considered
	// dropped until dcrtime returns the ChainTimestamp in the reply.
	// dcrtime does not return the ChainTimestamp until the timestamp
	// transaction has 6 confirmations. Once the timestamp has been
	// dropped, the anchor record is saved to the tstore, which means
	// that an anchor leaf will be appended onto all trees that were
	// anchored and the anchor records saved to the kv store.
	log.Infof("Waiting for anchor to drop")

	// Continually check with dcrtime if the anchor has been dropped.
	var (
		// The max retry period is set to 180 minutes to ensure that
		// enough time is given for the anchor transaction to receive 6
		// confirmations. This is based on the fact that each block has
		// a 99.75% chance of being mined within 30 minutes.
		period  = 5 * time.Minute             // check every 5 minute
		retries = 180 / int(period.Minutes()) // for up to 180 minutes
		ticker  = time.NewTicker(period)
	)
	defer ticker.Stop()
	for try := 0; try < retries; try++ {
		<-ticker.C

		log.Debugf("Verify anchor attempt %v/%v", try+1, retries)

		vbr, err := t.dcrtime.verifyBatch(anchorID, digests)
		if err != nil {
			log.Errorf("dcrtime verify batch: %v", err)
			continue
		}

		// We must wait until all digests have been anchored. Under
		// normal circumstances this will happen during the same dcrtime
		// transaction, but its possible for some of the digests to have
		// already been anchored in previous transactions if politeiad
		// was shutdown in the middle of the anchoring process.
		//
		// Ex: politeiad submits a digest for treeA to dcrtime. politeiad
		// gets shutdown before an anchor record is added to treeA.
		// dcrtime timestamps the treeA digest into block 1000. politeiad
		// gets turned back on and a new record, treeB, is submitted
		// prior to an anchor drop attempt. On the next anchor drop,
		// politeiad will try to drop an anchor for both treeA and treeB
		// since treeA is still considered unachored, however, when this
		// part of the code gets hit dcrtime will immediately return a
		// valid timestamp for treeA since it was already timestamped
		// into block 1000. In this situation, the verify loop must also
		// wait for treeB to be timestamped by dcrtime before continuing.
		anchored := make(map[string]struct{}, len(digests))
		for _, v := range vbr.Digests {
			if v.Result != dcrtime.ResultOK {
				// Something is wrong. Log the error and retry.
				log.Errorf("Digest %v: %v (%v)",
					v.Digest, dcrtime.Result[v.Result], v.Result)
				break
			}

			// Transaction will be populated once the tx has been sent,
			// otherwise is will be a zeroed out SHA256 digest.
			b := make([]byte, sha256.Size)
			if v.ChainInformation.Transaction == hex.EncodeToString(b) {
				log.Debugf("Anchor tx not sent yet; retry in %v", period)
				break
			}

			// ChainTimestamp will be populated once the tx has 6
			// confirmations.
			if v.ChainInformation.ChainTimestamp == 0 {
				log.Debugf("Anchor tx %v not enough confirmations; retry in %v",
					v.ChainInformation.Transaction, period)
				break
			}

			// This digest has been anchored
			anchored[v.Digest] = struct{}{}
		}
		if len(anchored) != len(digests) {
			// There are still digests that are waiting to be anchored.
			// Retry again after the wait period.
			continue
		}

		// Save anchor records
		for i, a := range anchors {
			var (
				verifyDigest = vbr.Digests[i]
				digest       = verifyDigest.Digest
				merkleRoot   = verifyDigest.ChainInformation.MerkleRoot
				merklePath   = verifyDigest.ChainInformation.MerklePath
			)

			// Verify the anchored digest matches the root hash
			if digest != hex.EncodeToString(a.LogRoot.RootHash) {
				log.Errorf("anchorWait: digest mismatch: got %x, want %v",
					digest, a.LogRoot.RootHash)
				continue
			}

			// Verify merkle path
			mk, err := merkle.VerifyAuthPath(&merklePath)
			if err != nil {
				log.Errorf("anchorWait: VerifyAuthPath: %v", err)
				continue
			}
			if hex.EncodeToString(mk[:]) != merkleRoot {
				log.Errorf("anchorWait: merkle root invalid: got %x, want %v",
					mk[:], merkleRoot)
				continue
			}

			// Verify digest is in the merkle path
			var found bool
			for _, v := range merklePath.Hashes {
				if hex.EncodeToString(v[:]) == digest {
					found = true
					break
				}
			}
			if !found {
				log.Errorf("anchorWait: digest %v not found in merkle path", digest)
				continue
			}

			// Add VerifyDigest to the anchor record
			a.VerifyDigest = &verifyDigest

			// Save anchor
			err = a.save(t.store, t.tlog)
			if err != nil {
				log.Errorf("anchorWait: anchorSave %v: %v", a.TreeID, err)
				continue
			}
		}

		log.Infof("Anchor dropped for %v records", len(vbr.Digests))
		return nil
	}

	return errors.Errorf("anchor drop timeout; waited for %v minutes",
		int(period.Minutes())*retries)
}
