// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlogbe

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	dcrtime "github.com/decred/dcrtime/api/v2"
	"github.com/decred/politeia/politeiad/backend/tlogbe/store"
	"github.com/decred/politeia/util"
	"github.com/google/trillian/types"
)

// TODO handle reorgs. A anchor record may become invalid in the case of a
// reorg. We don't create the anchor record until the anchor tx has 6
// confirmations so the probability of this occuring on mainnet is low, but it
// still needs to be handled.

const (
	// anchorSchedule determines how often we anchor records. dcrtime
	// currently drops an anchor on the hour mark so we submit new
	// anchors a few minutes prior to that.
	// Seconds Minutes Hours Days Months DayOfWeek
	anchorSchedule = "0 56 * * * *" // At 56 minutes every hour

	// anchorID is included in the timestamp and verify requests as a
	// unique identifier.
	anchorID = "tlogbe"
)

// anchor represents an anchor, i.e. timestamp, of a trillian tree at a
// specific tree size. A SHA256 digest of the LogRoot is timestamped using
// dcrtime.
type anchor struct {
	TreeID       int64                 `json:"treeid"`
	LogRoot      *types.LogRootV1      `json:"logroot"`
	VerifyDigest *dcrtime.VerifyDigest `json:"verifydigest"`
}

// anchorSave saves an anchor to the key-value store and appends a log leaf
// to the trillian tree for the anchor.
func (t *tlog) anchorSave(a anchor) error {
	// Sanity checks
	switch {
	case a.TreeID == 0:
		return fmt.Errorf("invalid tree id of 0")
	case a.LogRoot == nil:
		return fmt.Errorf("log root not found")
	case a.VerifyDigest == nil:
		return fmt.Errorf("verify digest not found")
	}

	// TODO
	// Save the anchor record to store
	be, err := convertBlobEntryFromAnchor(a)
	if err != nil {
		return err
	}
	b, err := store.Blobify(*be)
	if err != nil {
		return err
	}
	lrb, err := a.LogRoot.MarshalBinary()
	if err != nil {
		return err
	}
	logRootHash := util.Hash(lrb)[:]
	_ = logRootHash
	_ = b

	// Append anchor leaf to trillian tree

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
func (t *tlog) anchorWait(anchors []anchor, hashes []string) {
	// Ensure we are not reentrant
	t.Lock()
	if t.droppingAnchor {
		log.Errorf("waitForAchor: called reentrantly")
		return
	}
	t.droppingAnchor = true
	t.Unlock()

	// Whatever happens in this function we must clear droppingAnchor
	var exitErr error
	defer func() {
		t.Lock()
		t.droppingAnchor = false
		t.Unlock()

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
		// enough time is given for the anchor transaction to recieve 6
		// confirmations. This is based on the fact that each block has
		// a 99.75% chance of being mined within 30 minutes.
		//
		// TODO change period to 5 minutes when done testing
		period  = 1 * time.Minute             // check every 5 minute
		retries = 180 / int(period.Minutes()) // for up to 180 minutes
		ticker  = time.NewTicker(period)
	)
	defer ticker.Stop()
	for try := 0; try < retries; try++ {
		<-ticker.C

		log.Debugf("Verify %v anchor attempt %v/%v", t.id, try+1, retries)

		vbr, err := verifyBatch(t.dcrtimeHost, anchorID, hashes)
		if err != nil {
			exitErr = fmt.Errorf("verifyBatch: %v", err)
			return
		}

		// Make sure we're actually anchored
		var retry bool
		for _, v := range vbr.Digests {
			if v.Result != dcrtime.ResultOK {
				// Something is wrong. Log the error and retry.
				log.Errorf("Digest %v: %v (%v)",
					v.Digest, dcrtime.Result[v.Result], v.Result)
				retry = true
				break
			}
			// Transaction will be populated once the tx has been sent,
			// otherwise is will be a zeroed out SHA256 digest.
			b := make([]byte, sha256.Size)
			if v.ChainInformation.Transaction == hex.EncodeToString(b) {
				log.Debugf("Anchor tx not sent yet; retry in %v", period)
				retry = true
				break
			}
			// ChainTimestamp will be populated once the tx has 6
			// confirmations.
			if v.ChainInformation.ChainTimestamp == 0 {
				log.Debugf("Anchor tx %v not enough confirmations; retry in %v",
					v.ChainInformation.Transaction, period)
				retry = true
				break
			}
		}
		if retry {
			continue
		}

		// Save anchor records
		for k, v := range anchors {
			// Sanity checks. Anchor log root digest should match digest
			// that was anchored.
			b, err := v.LogRoot.MarshalBinary()
			if err != nil {
				log.Errorf("anchorWait: MarshalBinary %v %x: %v",
					v.TreeID, v.LogRoot.RootHash, err)
				continue
			}
			anchorDigest := hex.EncodeToString(util.Hash(b)[:])
			dcrtimeDigest := vbr.Digests[k].Digest
			if anchorDigest != dcrtimeDigest {
				log.Errorf("anchorWait: digest mismatch: got %x, want %v",
					dcrtimeDigest, anchorDigest)
				continue
			}

			// Add VerifyDigest to anchor before saving it
			v.VerifyDigest = &vbr.Digests[k]

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

// anchor drops an anchor for any trees that have unanchored leaves at the time
// of function invocation. A SHA256 digest of the tree's log root at its
// current height is timestamped onto the decred blockchain using the dcrtime
// service. The anchor data is saved to the key-value store.
func (t *tlog) anchor() {
	log.Debugf("Start %v anchor process", t.id)

	var exitErr error // Set on exit if there is an error
	defer func() {
		if exitErr != nil {
			log.Errorf("anchorTrees: %v", exitErr)
		}
	}()

	trees, err := t.trillian.treesAll()
	if err != nil {
		exitErr = fmt.Errorf("treesAll: %v", err)
		return
	}

	// digests contains the SHA256 digests of the log roots of the
	// trees that need to be anchored. These will be submitted to
	// dcrtime to be included in a dcrtime timestamp.
	digests := make([]string, 0, len(trees))

	// anchors contains an anchor structure for each tree that is being
	// anchored. Once the dcrtime timestamp is successful, these
	// anchors will be updated with the timestamp data and saved to the
	// key-value store.
	anchors := make([]anchor, 0, len(trees))

	// Find the trees that need to be anchored
	for _, v := range trees {
		// TODO this needs to pull the anchor record from the store and
		// check the anchor tree height against the current tree height

		// Check if the last leaf is an anchor record
		l, err := t.lastLeaf(v.TreeId)
		if err != nil {
			exitErr = fmt.Errorf("lastLeaf %v: %v", v.TreeId, err)
			return
		}
		if leafIsAnchorRecord(l) {
			// Tree has already been anchored at the current height. Check
			// the next one.
			continue
		}

		// Tree has not been anchored at current height. Add it to the
		// list of anchors.
		_, lr, err := t.trillian.signedLogRootForTree(v)
		if err != nil {
			exitErr = fmt.Errorf("signedLogRoot %v: %v", v.TreeId, err)
			return
		}
		anchors = append(anchors, anchor{
			TreeID:  v.TreeId,
			LogRoot: lr,
		})

		// Collate the log root digest. This is what gets submitted to
		// dcrtime.
		lrb, err := lr.MarshalBinary()
		if err != nil {
			exitErr = fmt.Errorf("MarshalBinary %v: %v", v.TreeId, err)
			return
		}
		d := hex.EncodeToString(util.Hash(lrb)[:])
		digests = append(digests, d)

		log.Debugf("Anchoring %v tree %v at height %v",
			t.id, v.TreeId, lr.TreeSize)
	}
	if len(anchors) == 0 {
		log.Infof("Nothing to anchor")
		return
	}

	// Ensure we are not reentrant
	t.Lock()
	if t.droppingAnchor {
		// An anchor is not considered dropped until dcrtime returns the
		// ChainTimestamp in the VerifyReply. dcrtime does not do this
		// until the anchor tx has 6 confirmations, therefor, this code
		// path can be hit if 6 blocks are not mined within the period
		// specified by the anchor schedule. Though rare, the probability
		// of this happening is not zero and should not be considered an
		// error. We simply exit and will drop a new anchor at the next
		// anchor period.
		t.Unlock()
		log.Infof("Attempting to drop an anchor while previous anchor " +
			"has not finished dropping; skipping current anchor period")
		return
	}
	t.Unlock()

	// Submit dcrtime anchor request
	log.Infof("Anchoring %v %v trees", len(anchors), t.id)

	tbr, err := timestampBatch(t.dcrtimeHost, anchorID, digests)
	if err != nil {
		exitErr = fmt.Errorf("timestampBatch: %v", err)
		return
	}
	var failed bool
	for i, v := range tbr.Results {
		switch v {
		case dcrtime.ResultOK:
			// We're good; continue
		case dcrtime.ResultExistsError:
			// I don't think this will ever happen, but it's ok if it does
			// since we'll still be able to retrieve the VerifyDigest from
			// dcrtime for this digest.
			//
			// Log a warning to bring it to our attention. Do not exit.
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
		exitErr = fmt.Errorf("dcrtime failed to timestamp digests")
		return
	}

	go t.anchorWait(anchors, digests)
}
