// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tstore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	dcrtime "github.com/decred/dcrtime/api/v2"
	"github.com/decred/dcrtime/merkle"
	"github.com/decred/politeia/politeiad/backend/tstorebe/store"
	"github.com/google/trillian"
	"github.com/google/trillian/types"
	"google.golang.org/grpc/codes"
)

// TODO handle reorgs. An anchor record may become invalid in the case of a
// reorg. We don't create the anchor record until the anchor tx has 6
// confirmations so the probability of this occurring on mainnet is low, but it
// still needs to be handled.

const (
	// anchorSchedule determines how often we anchor records. dcrtime
	// currently drops an anchor on the hour mark so we submit new
	// anchors a few minutes prior to that.
	// Seconds Minutes Hours Days Months DayOfWeek
	anchorSchedule = "0 56 * * * *" // At minute 56 of every hour

	// anchorID is included in the timestamp and verify requests as a
	// unique identifier.
	anchorID = "tstorebe"
)

// anchor represents an anchor, i.e. timestamp, of a trillian tree at a
// specific tree size. The LogRootV1.RootHash is the merkle root hash of a
// trillian tree. This root hash is submitted to dcrtime to be anchored and is
// the anchored digest in the VerifyDigest. Only the root hash is anchored, but
// the full LogRootV1 struct is saved as part of an anchor record so that it
// can be used to retrieve inclusion proofs for any leaves that were included
// in the root hash.
type anchor struct {
	TreeID       int64                 `json:"treeid"`
	LogRoot      *types.LogRootV1      `json:"logroot"`
	VerifyDigest *dcrtime.VerifyDigest `json:"verifydigest"`
}

func (t *Tstore) droppingAnchorGet() bool {
	t.Lock()
	defer t.Unlock()

	return t.droppingAnchor
}

func (t *Tstore) droppingAnchorSet(b bool) {
	t.Lock()
	defer t.Unlock()

	t.droppingAnchor = b
}

var (
	errAnchorNotFound = errors.New("anchor not found")
)

// anchorForLeaf returns the anchor for a specific merkle leaf hash.
func (t *Tstore) anchorForLeaf(treeID int64, merkleLeafHash []byte, leaves []*trillian.LogLeaf) (*anchor, error) {
	// Find the leaf for the provided merkle leaf hash
	var l *trillian.LogLeaf
	for i, v := range leaves {
		if bytes.Equal(v.MerkleLeafHash, merkleLeafHash) {
			l = v
			// Sanity check
			if l.LeafIndex != int64(i) {
				return nil, fmt.Errorf("unexpected leaf index: got %v, want %v",
					l.LeafIndex, i)
			}
			break
		}
	}
	if l == nil {
		return nil, fmt.Errorf("leaf not found")
	}

	// Find the first two anchor that occurs after the leaf. If the
	// leaf was added in the middle of an anchor drop then it will not
	// be part of the first anchor. It will be part of the second
	// anchor.
	keys := make([]string, 0, 2)
	for i := int(l.LeafIndex); i < len(leaves); i++ {
		l := leaves[i]
		ed, err := extraDataDecode(l.ExtraData)
		if err != nil {
			return nil, err
		}
		if ed.Desc == dataDescriptorAnchor {
			keys = append(keys, ed.Key)
			if len(keys) == 2 {
				break
			}
		}
	}
	if len(keys) == 0 {
		// This leaf has not been anchored yet
		return nil, errAnchorNotFound
	}

	// Get the anchor records
	blobs, err := t.store.Get(keys)
	if err != nil {
		return nil, fmt.Errorf("store Get: %v", err)
	}
	if len(blobs) != len(keys) {
		return nil, fmt.Errorf("unexpected blobs count: got %v, want %v",
			len(blobs), len(keys))
	}

	// Find the correct anchor for the leaf
	var leafAnchor *anchor
	for _, v := range keys {
		b, ok := blobs[v]
		if !ok {
			return nil, fmt.Errorf("blob not found %v", v)
		}
		be, err := store.Deblob(b)
		if err != nil {
			return nil, err
		}
		a, err := convertAnchorFromBlobEntry(*be)
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
		return nil, errAnchorNotFound
	}

	return leafAnchor, nil
}

// anchorLatest returns the most recent anchor for the provided tree. A
// errAnchorNotFound is returned if no anchor is found for the provided tree.
func (t *Tstore) anchorLatest(treeID int64) (*anchor, error) {
	// Get tree leaves
	leavesAll, err := t.trillian.leavesAll(treeID)
	if err != nil {
		return nil, fmt.Errorf("leavesAll: %v", err)
	}

	// Find the most recent anchor leaf
	var key string
	for i := len(leavesAll) - 1; i >= 0; i-- {
		ed, err := extraDataDecode(leavesAll[i].ExtraData)
		if err != nil {
			return nil, err
		}
		if ed.Desc == dataDescriptorAnchor {
			key = ed.Key
			break
		}
	}
	if key == "" {
		return nil, errAnchorNotFound
	}

	// Pull blob from key-value store
	blobs, err := t.store.Get([]string{key})
	if err != nil {
		return nil, fmt.Errorf("store Get: %v", err)
	}
	if len(blobs) != 1 {
		return nil, fmt.Errorf("unexpected blobs count: got %v, want 1",
			len(blobs))
	}
	b, ok := blobs[key]
	if !ok {
		return nil, fmt.Errorf("blob not found %v", key)
	}
	be, err := store.Deblob(b)
	if err != nil {
		return nil, err
	}
	a, err := convertAnchorFromBlobEntry(*be)
	if err != nil {
		return nil, err
	}

	return a, nil
}

// anchorSave saves an anchor to the key-value store and appends a log leaf
// to the trillian tree for the anchor.
func (t *Tstore) anchorSave(a anchor) error {
	// Sanity checks
	switch {
	case a.TreeID == 0:
		return fmt.Errorf("invalid tree id of 0")
	case a.LogRoot == nil:
		return fmt.Errorf("log root not found")
	case a.VerifyDigest == nil:
		return fmt.Errorf("verify digest not found")
	}

	// Save the anchor record to store
	be, err := convertBlobEntryFromAnchor(a)
	if err != nil {
		return err
	}
	b, err := store.Blobify(*be)
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

	// Append anchor leaf to trillian tree
	d, err := hex.DecodeString(be.Digest)
	if err != nil {
		return err
	}
	extraData, err := extraDataEncode(keys[0], dataDescriptorAnchor)
	if err != nil {
		return err
	}
	leaves := []*trillian.LogLeaf{
		newLogLeaf(d, extraData),
	}
	queued, _, err := t.trillian.leavesAppend(a.TreeID, leaves)
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

	log.Debugf("Saved %v anchor for tree %v at height %v",
		t.id, a.TreeID, a.LogRoot.TreeSize)

	return nil
}

// anchorWait waits for the anchor to drop. The anchor is not considered
// dropped until dcrtime returns the ChainTimestamp in the reply. dcrtime does
// not return the ChainTimestamp until the timestamp transaction has 6
// confirmations. Once the timestamp has been dropped, the anchor record is
// saved to the key-value store and the record histories of the corresponding
// timestamped trees are updated.
func (t *Tstore) anchorWait(anchors []anchor, digests []string) {
	// Verify we are not reentrant
	if t.droppingAnchorGet() {
		log.Errorf("waitForAchor: called reentrantly")
		return
	}

	// We are now condsidered to be dropping an anchor
	t.droppingAnchorSet(true)

	// Whatever happens in this function we must clear droppingAnchor
	var exitErr error
	defer func() {
		t.droppingAnchorSet(false)

		if exitErr != nil {
			log.Errorf("anchorWait: %v", exitErr)
		}
	}()

	// Wait for anchor to drop
	log.Infof("Waiting for %v anchor to drop", t.id)

	// Continually check with dcrtime if the anchor has been dropped.
	// The anchor is not considered dropped until the ChainTimestamp
	// field of the dcrtime reply has been populated. dcrtime only
	// populates the ChainTimestamp field once the dcr transaction has
	// 6 confirmations.
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

		log.Debugf("Verify %v anchor attempt %v/%v", t.id, try+1, retries)

		vbr, err := t.dcrtime.verifyBatch(anchorID, digests)
		if err != nil {
			exitErr = fmt.Errorf("verifyBatch: %v", err)
			return
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
		for k, v := range anchors {
			var (
				verifyDigest = vbr.Digests[k]
				digest       = verifyDigest.Digest
				merkleRoot   = verifyDigest.ChainInformation.MerkleRoot
				merklePath   = verifyDigest.ChainInformation.MerklePath
			)

			// Verify the anchored digest matches the root hash
			if digest != hex.EncodeToString(v.LogRoot.RootHash) {
				log.Errorf("anchorWait: digest mismatch: got %x, want %v",
					digest, v.LogRoot.RootHash)
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
			v.VerifyDigest = &verifyDigest

			// Save anchor
			err = t.anchorSave(v)
			if err != nil {
				log.Errorf("anchorWait: anchorSave %v: %v", v.TreeID, err)
				continue
			}
		}

		log.Infof("Anchor dropped for %v %v records", len(vbr.Digests), t.id)
		return
	}

	log.Errorf("Anchor drop timeout, waited for: %v",
		int(period.Minutes())*retries)
}

// anchorTrees drops an anchor for any trees that have unanchored leaves at the
// time of function invocation. A SHA256 digest of the tree's log root at its
// current height is timestamped onto the decred blockchain using the dcrtime
// service. The anchor data is saved to the key-value store.
func (t *Tstore) anchorTrees() error {
	log.Debugf("Start %v anchor process", t.id)

	// Ensure we are not reentrant
	if t.droppingAnchorGet() {
		// An anchor is not considered dropped until dcrtime returns the
		// ChainTimestamp in the VerifyReply. dcrtime does not do this
		// until the anchor tx has 6 confirmations, therefor, this code
		// path can be hit if 6 blocks are not mined within the period
		// specified by the anchor schedule. Though rare, the probability
		// of this happening is not zero and should not be considered an
		// error. We simply exit and will drop a new anchor at the next
		// anchor period.
		log.Infof("Attempting to drop an anchor while previous anchor " +
			"has not finished dropping; skipping current anchor period")
		return nil
	}

	trees, err := t.trillian.treesAll()
	if err != nil {
		return fmt.Errorf("treesAll: %v", err)
	}

	// digests contains the SHA256 digests of the LogRootV1.RootHash
	// for all trees that need to be anchored. These will be submitted
	// to dcrtime to be included in a dcrtime timestamp.
	digests := make([]string, 0, len(trees))

	// anchors contains an anchor structure for each tree that is being
	// anchored. Once the dcrtime timestamp is successful, these
	// anchors will be updated with the timestamp data and saved to the
	// key-value store.
	anchors := make([]anchor, 0, len(trees))

	// Find the trees that need to be anchored. This is done by pulling
	// the most recent anchor from the tree and checking the anchored
	// tree height against the current tree height. We cannot rely on
	// the anchored being the last leaf in the tree since new leaves
	// can be added while the anchor is waiting to be dropped.
	for _, v := range trees {
		// Get latest anchor
		a, err := t.anchorLatest(v.TreeId)
		switch {
		case errors.Is(err, errAnchorNotFound):
			// Tree has not been anchored yet. Verify that the tree has
			// leaves. A tree with no leaves does not need to be anchored.
			leavesAll, err := t.trillian.leavesAll(v.TreeId)
			if err != nil {
				return fmt.Errorf("leavesAll: %v", err)
			}
			if len(leavesAll) == 0 {
				// Tree does not have any leaves. Nothing to do.
				continue
			}

		case err != nil:
			// All other errors
			return fmt.Errorf("anchorLatest %v: %v", v.TreeId, err)

		default:
			// Anchor record found. If the anchor height differs from the
			// current height then the tree needs to be anchored.
			_, lr, err := t.trillian.signedLogRoot(v)
			if err != nil {
				return fmt.Errorf("signedLogRoot %v: %v", v.TreeId, err)
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
		_, lr, err := t.trillian.signedLogRoot(v)
		if err != nil {
			return fmt.Errorf("signedLogRoot %v: %v", v.TreeId, err)
		}
		anchors = append(anchors, anchor{
			TreeID:  v.TreeId,
			LogRoot: lr,
		})

		// Collate the tree's root hash. This is what gets submitted to
		// dcrtime.
		digests = append(digests, hex.EncodeToString(lr.RootHash))

		log.Debugf("Anchoring %v tree %v at height %v",
			t.id, v.TreeId, lr.TreeSize)
	}
	if len(anchors) == 0 {
		log.Infof("No %v trees to to anchor", t.id)
		return nil
	}

	// Submit dcrtime anchor request
	log.Infof("Anchoring %v %v trees", len(anchors), t.id)

	tbr, err := t.dcrtime.timestampBatch(anchorID, digests)
	if err != nil {
		return fmt.Errorf("timestampBatch: %v", err)
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
		return fmt.Errorf("dcrtime failed to timestamp digests")
	}

	// Launch go routine that polls dcrtime for the anchor tx
	go t.anchorWait(anchors, digests)

	return nil
}
