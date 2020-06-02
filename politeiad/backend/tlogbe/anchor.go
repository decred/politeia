// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlogbe

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/davecgh/go-spew/spew"
	dcrtime "github.com/decred/dcrtime/api/v1"
	"github.com/decred/politeia/util"
	"github.com/google/trillian/types"
)

// TODO handle reorgs. A anchor record may become invalid in the case
// of a reorg.

const (
	// anchorSchedule determines how often we anchor records. dcrtime
	// drops an anchor on the hour mark so we submit new anchors a few
	// minutes prior.
	// Seconds Minutes Hours Days Months DayOfWeek
	anchorSchedule = "0 56 * * * *" // At 56 minutes every hour

	// TODO does this need to be unique?
	anchorID = "tlogbe"
)

// anchor represents an anchor, i.e. timestamp, of a trillian tree at a
// specific tree size. The LogRoot is hashed and anchored using dcrtime. Once
// dcrtime drops an anchor, the anchor structure is updated and saved to the
// key-value store.
type anchor struct {
	TreeID       int64                 `json:"treeid"`
	LogRoot      *types.LogRootV1      `json:"logroot"`
	VerifyDigest *dcrtime.VerifyDigest `json:"verifydigest"`
}

// anchorSave saves the anchor to the key-value store and updates the record
// history of the record that corresponds to the anchor TreeID. This function
// should be called once the dcrtime anchor has been dropped.
//
// This function must be called WITHOUT the read/write lock held.
func (t *tlogbe) anchorSave(a anchor) error {
	log.Debugf("Saving anchor for tree %v at height %v",
		a.TreeID, a.LogRoot.TreeSize)

	// Sanity checks
	switch {
	case a.TreeID == 0:
		return fmt.Errorf("invalid tree id of 0")
	case a.LogRoot == nil:
		return fmt.Errorf("log root not found")
	case a.VerifyDigest == nil:
		return fmt.Errorf("verify digest not found")
	}

	// Compute the log root hash. This will be used as the key for the
	// anchor in the key-value store.
	b, err := a.LogRoot.MarshalBinary()
	if err != nil {
		return fmt.Errorf("MarshalBinary %v %x: %v",
			a.TreeID, a.LogRoot.RootHash, err)
	}
	logRootHash := util.Hash(b)

	// Get the record history for this tree and update the appropriate
	// record content with the anchor. The lock must be held during
	// this update.
	t.Lock()
	defer t.Unlock()

	token := tokenFromTreeID(a.TreeID)
	rh, err := t.recordHistory(token)
	if err != nil {
		return fmt.Errorf("recordHistory: %v", err)
	}

	// Aggregate all record content that does not currently have an
	// anchor.
	noAnchor := make([][]byte, 0, 256)
	for _, v := range rh.Versions {
		_, ok := rh.Anchors[hex.EncodeToString(v.RecordMetadata)]
		if !ok {
			noAnchor = append(noAnchor, v.RecordMetadata)
		}
		for _, merkle := range v.Metadata {
			_, ok := rh.Anchors[hex.EncodeToString(merkle)]
			if !ok {
				noAnchor = append(noAnchor, merkle)
			}
		}
		for _, merkle := range v.Files {
			_, ok := rh.Anchors[hex.EncodeToString(merkle)]
			if !ok {
				noAnchor = append(noAnchor, merkle)
			}
		}
	}
	if len(noAnchor) == 0 {
		// All record content has already been anchored. This should not
		// happen. A tree is only anchored when it has at least one
		// unanchored leaf.
		return fmt.Errorf("all record content is already anchored")
	}

	// Get the leaves for the record content that has not been anchored
	// yet. We'll use these to check if the leaf was included in the
	// current anchor.
	leaves, err := t.leavesByHash(a.TreeID, noAnchor)
	if err != nil {
		return fmt.Errorf("leavesByHash: %v", err)
	}

	var anchorCount int
	for _, v := range leaves {
		// Check leaf height
		if int64(a.LogRoot.TreeSize) < v.LeafIndex {
			// Leaf was not included in anchor
			continue
		}

		// Leaf was included in the anchor
		anchorCount++

		// Sanity check. Get the inclusion proof. This function will
		// throw an error if the leaf is not part of the log root.
		_, err = t.inclusionProof(a.TreeID, v.MerkleLeafHash, a.LogRoot)
		if err != nil {
			return fmt.Errorf("inclusionProof %x: %v", v.MerkleLeafHash, err)
		}

		// Update record history
		rh.Anchors[hex.EncodeToString(v.MerkleLeafHash)] = logRootHash[:]

		log.Debugf("Anchor added to leaf: %x", v.MerkleLeafHash)
	}
	if anchorCount == 0 {
		// This should not happen. If a tree was anchored then it should
		// have at least one leaf that was included in the anchor.
		return fmt.Errorf("no record content was included in the anchor")
	}

	// Save the updated record history
	be, err := convertBlobEntryFromRecordHistory(*rh)
	if err != nil {
		return err
	}
	b, err = blobify(*be)
	if err != nil {
		return err
	}
	err = t.store.Put(keyRecordHistory(rh.Token), b)
	if err != nil {
		return fmt.Errorf("store Put: %v", err)
	}

	log.Debugf("Record history updated")

	// Mark tree as clean if no additional leaves have been added while
	// we've been waiting for the anchor to drop.
	height, ok := t.dirtyHeight(a.TreeID)
	if !ok {
		return fmt.Errorf("dirty tree height not found")
	}

	log.Debugf("Tree anchored at height %v, current height %v",
		a.LogRoot.TreeSize, height)

	if height == a.LogRoot.TreeSize {
		// All tree leaves have been anchored. Remove tree from dirty
		// list.
		t.dirtyDel(a.TreeID)
		log.Debugf("Tree removed from dirty list")
	}

	return nil
}

// anchorWait waits for dcrtime to drop an anchor for the provided hashes.
func (t *tlogbe) anchorWait(anchors []anchor, hashes []string) {
	// Ensure we are not reentrant
	t.Lock()
	if t.droppingAnchor {
		log.Errorf("waitForAchor: called reentrantly")
		return
	}
	t.droppingAnchor = true
	t.Unlock()

	// Whatever happens in this function we must clear droppingAnchor.
	defer func() {
		t.Lock()
		t.droppingAnchor = false
		t.Unlock()
	}()

	// Wait for anchor to drop
	log.Infof("Waiting for anchor to drop")

	// Continually check with dcrtime if the anchor has been dropped.
	var (
		period  = time.Duration(1) * time.Minute // check every 1 minute
		retries = 30 / int(period)               // for up to 30 minutes
		ticker  = time.NewTicker(period)
	)
	defer ticker.Stop()
	for try := 0; try < retries; try++ {
	restart:
		<-ticker.C

		log.Debugf("Verify anchor attempt %v/%v", try+1, retries)

		vr, err := util.Verify(anchorID, t.dcrtimeHost, hashes)
		if err != nil {
			if _, ok := err.(util.ErrNotAnchored); ok {
				// Anchor not dropped, try again
				continue
			}
			log.Errorf("anchorWait exiting: %v", err)
			return
		}

		// Make sure we are actually anchored.
		for _, v := range vr.Digests {
			if v.ChainInformation.ChainTimestamp == 0 {
				log.Debugf("anchorRecords ChainTimestamp 0: %v", v.Digest)
				goto restart
			}
		}

		log.Debugf("%T %v", vr, spew.Sdump(vr))

		log.Infof("Anchor dropped")

		// Save anchor records
		for k, v := range anchors {
			// Sanity check
			verifyDigest := vr.Digests[k]
			b, err := v.LogRoot.MarshalBinary()
			if err != nil {
				log.Errorf("anchorWait: MarshalBinary %v %x: %v",
					v.TreeID, v.LogRoot.RootHash, err)
				continue
			}
			h := util.Hash(b)
			if hex.EncodeToString(h[:]) != verifyDigest.Digest {
				log.Errorf("anchorWait: digest mismatch: got %x, want %v",
					h[:], verifyDigest.Digest)
				continue
			}

			err = t.anchorSave(anchor{
				TreeID:       v.TreeID,
				LogRoot:      v.LogRoot,
				VerifyDigest: v.VerifyDigest,
			})
			if err != nil {
				log.Errorf("anchorWait: anchorSave %v: %v", v.TreeID, err)
				continue
			}
		}

		log.Info("Anchored records updated")
		return
	}

	log.Errorf("Anchor drop timeout, waited for: %v", period*time.Minute)
}

// anchor is a function that is periodically called to anchor dirty trees.
func (t *tlogbe) anchor() {
	log.Debugf("Start anchoring process")

	var exitError error // Set on exit if there is an error
	defer func() {
		if exitError != nil {
			log.Errorf("anchorRecords: %v", exitError)
		}
	}()

	// Get dirty trees
	dirty := t.dirtyCopy()
	anchors := make([]anchor, 0, len(dirty))
	for treeID := range dirty {
		anchors = append(anchors, anchor{
			TreeID: treeID,
		})
	}
	if len(anchors) == 0 {
		log.Infof("Nothing to anchor")
		return
	}

	// Aggregate the log root for each tree. A hash of the log root is
	// what we anchor.
	hashes := make([]*[sha256.Size]byte, len(anchors))
	for k, v := range anchors {
		log.Debugf("Obtaining anchoring data: %v", v.TreeID)

		tree, err := t.tree(v.TreeID)
		if err != nil {
			exitError = fmt.Errorf("tree %v: %v", v.TreeID, err)
			return
		}
		_, lr, err := t.signedLogRoot(tree)
		if err != nil {
			exitError = fmt.Errorf("signedLogRoot %v: %v", v.TreeID, err)
			return
		}

		anchors[k].LogRoot = lr
		lrb, err := lr.MarshalBinary()
		if err != nil {
			exitError = fmt.Errorf("MarshalBinary %v: %v", v.TreeID, err)
			return
		}
		hashes[k] = util.Hash(lrb)
	}

	// Ensure we are not reentrant
	t.Lock()
	if t.droppingAnchor {
		// This shouldn't happen so let's warn the user of something
		// misbehaving.
		t.Unlock()
		log.Errorf("Dropping anchor already in progress")
		return
	}
	t.Unlock()

	// Submit dcrtime anchor request
	log.Infof("Anchoring records: %v", len(anchors))

	err := util.Timestamp(anchorID, t.dcrtimeHost, hashes)
	if err != nil {
		exitError = err
		return
	}

	h := make([]string, 0, len(hashes))
	for _, v := range hashes {
		h = append(h, hex.EncodeToString(v[:]))
	}

	go t.anchorWait(anchors, h)
}
