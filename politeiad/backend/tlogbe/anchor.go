// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlogbe

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	dcrtime "github.com/decred/dcrtime/api/v2"
	"github.com/decred/politeia/util"
	"github.com/google/trillian/types"
)

// TODO handle reorgs. A anchor record may become invalid in the case of a
// reorg. We don't create the anchor record until the anchor tx has 6
// confirmations so the probability of this occuring on mainnet is very low,
// but it should still be handled.

const (
	// anchorSchedule determines how often we anchor records. dcrtime
	// currently drops an anchor on the hour mark so we submit new
	// anchors a few minutes prior to that.
	// Seconds Minutes Hours Days Months DayOfWeek
	anchorSchedule = "0 56 * * * *" // At 56 minutes every hour

	// TODO does this need to be unique?
	anchorID = "tlogbe"
)

// anchor represents an anchor, i.e. timestamp, of a trillian tree at a
// specific tree size. The LogRoot is hashed and anchored using dcrtime. Once
// dcrtime timestamp is verified the anchor structure is updated and saved to
// the key-value store.
type anchor struct {
	TreeID       int64                 `json:"treeid"`
	LogRoot      *types.LogRootV1      `json:"logroot"`
	VerifyDigest *dcrtime.VerifyDigest `json:"verifydigest"`
}

func convertBlobEntryFromAnchor(a anchor) (*blobEntry, error) {
	data, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	hint, err := json.Marshal(
		dataDescriptor{
			Type:       dataTypeStructure,
			Descriptor: dataDescriptorAnchor,
		})
	if err != nil {
		return nil, err
	}
	be := blobEntryNew(hint, data)
	return &be, nil
}

// anchorSave saves an anchor to the key-value store and updates the record
// history of the record that corresponds to tree that was anchored.
//
// This function must be called WITHOUT the read/write lock held.
func (t *tlogbe) anchorSave(a anchor) error {

	// Sanity checks
	switch {
	case a.TreeID == 0:
		return fmt.Errorf("invalid tree id of 0")
	case a.LogRoot == nil:
		return fmt.Errorf("log root not found")
	case a.VerifyDigest == nil:
		return fmt.Errorf("verify digest not found")
	}

	// Save the anchor record
	be, err := convertBlobEntryFromAnchor(a)
	if err != nil {
		return err
	}
	b, err := blobify(*be)
	if err != nil {
		return err
	}
	lrb, err := a.LogRoot.MarshalBinary()
	if err != nil {
		return err
	}
	logRootHash := util.Hash(lrb)[:]
	err = t.store.Put(keyAnchor(logRootHash), b)
	if err != nil {
		return fmt.Errorf("Put: %v", err)
	}

	log.Debugf("Anchor saved for tree %v at height %v",
		a.TreeID, a.LogRoot.TreeSize)

	// Update the record history with the anchor. The lock must be held
	// during this update.
	t.Lock()
	defer t.Unlock()

	token := tokenFromTreeID(a.TreeID)
	rh, err := t.recordHistory(token)
	if err != nil {
		return fmt.Errorf("recordHistory: %v", err)
	}

	rh.Anchors[a.LogRoot.TreeSize] = logRootHash

	be, err = convertBlobEntryFromRecordHistory(*rh)
	if err != nil {
		return err
	}
	b, err = blobify(*be)
	if err != nil {
		return err
	}
	err = t.store.Put(keyRecordHistory(rh.Token), b)
	if err != nil {
		return fmt.Errorf("Put: %v", err)
	}

	log.Debugf("Anchor added to record history %x", token)

	return nil
}

// waitForAnchor waits for the anchor to drop. The anchor is not considered
// dropped until dcrtime returns the ChainTimestamp in the reply. dcrtime does
// not return the ChainTimestamp until the timestamp transaction has 6
// confirmations. Once the timestamp has been dropped, the anchor record is
// saved to the key-value store and the record histories of the corresponding
// timestamped trees are updated.
func (t *tlogbe) waitForAnchor(anchors []anchor, hashes []string) {
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
			log.Errorf("waitForAnchor: %v", exitErr)
		}
	}()

	// Wait for anchor to drop
	log.Infof("Waiting for anchor to drop")

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

		log.Debugf("Verify anchor attempt %v/%v", try+1, retries)

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
				log.Errorf("waitForAnchor: MarshalBinary %v %x: %v",
					v.TreeID, v.LogRoot.RootHash, err)
				continue
			}
			anchorDigest := hex.EncodeToString(util.Hash(b)[:])
			dcrtimeDigest := vbr.Digests[k].Digest
			if anchorDigest != dcrtimeDigest {
				log.Errorf("waitForAnchor: digest mismatch: got %x, want %v",
					dcrtimeDigest, anchorDigest)
				continue
			}

			// Add VerifyDigest to anchor before saving it
			v.VerifyDigest = &vbr.Digests[k]

			// Save anchor
			err = t.anchorSave(v)
			if err != nil {
				log.Errorf("waitForAnchor: anchorSave %v: %v", v.TreeID, err)
				continue
			}
		}

		log.Infof("Anchor dropped for %v records", len(vbr.Digests))
		return
	}

	log.Errorf("Anchor drop timeout, waited for: %v",
		int(period.Minutes())*retries)
}

// anchor drops an anchor for any trees that have unanchored leaves at the
// time of function invocation. A digest of the tree's log root at its current
// height is timestamped onto the decred blockchain using the dcrtime service.
// The anchor data is saved to the key-value store and the record history that
// corresponds to the anchored tree is updated with the anchor data.
func (t *tlogbe) anchorTrees() {
	log.Debugf("Start anchor process")

	var exitErr error // Set on exit if there is an error
	defer func() {
		if exitErr != nil {
			log.Errorf("anchorTrees: %v", exitErr)
		}
	}()

	trees, err := t.tlog.treesAll()
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
		// Check if this tree has unanchored leaves
		_, lr, err := t.tlog.signedLogRoot(v)
		if err != nil {
			exitErr = fmt.Errorf("signedLogRoot %v: %v", v.TreeId, err)
			return
		}
		token := tokenFromTreeID(v.TreeId)
		rh, err := t.recordHistory(token)
		if err != nil {
			exitErr = fmt.Errorf("recordHistory %x: %v", token, err)
		}
		_, ok := rh.Anchors[lr.TreeSize]
		if ok {
			// Tree has already been anchored at the current height. Check
			// the next one.
			continue
		}

		// Tree has not been anchored at current height. Anchor it.
		log.Debugf("Tree %v (%x) anchoring at height %v",
			v.TreeId, token, lr.TreeSize)

		// Setup anchor record
		anchors = append(anchors, anchor{
			TreeID:  v.TreeId,
			LogRoot: lr,
		})

		// Collate the log root digest
		lrb, err := lr.MarshalBinary()
		if err != nil {
			exitErr = fmt.Errorf("MarshalBinary %v: %v", v.TreeId, err)
			return
		}
		d := hex.EncodeToString(util.Hash(lrb)[:])
		digests = append(digests, d)
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
	log.Infof("Anchoring %v trees", len(anchors))

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
			// I can't think of any situations where this would happen, but
			// it's ok if it does since we'll still be able to retrieve the
			// VerifyDigest from dcrtime for this digest.
			//
			// Log this as a warning to bring it to our attention. Do not
			// exit.
			log.Warnf("Digest failed %v: %v (%v)",
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

	go t.waitForAnchor(anchors, digests)
}
