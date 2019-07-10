package main

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/davecgh/go-spew/spew"
	v1 "github.com/decred/politeia/tlog/api/v1"
	"github.com/decred/politeia/util"
	"github.com/google/trillian"
	"github.com/google/trillian/client"
	tcrypto "github.com/google/trillian/crypto"
	"github.com/google/trillian/types"
	"google.golang.org/grpc/codes"
)

const (
	// anchorSchedule determines how often we anchor records
	// Seconds Minutes Hours Days Months DayOfWeek
	anchorSchedule = "0 56 * * * *" // At 56 minutes every hour
)

// findLeafAnchor returns the DataAnchor for the provided leaf. If there is no
// anchor it returns nil.
func (t *tserver) findLeafAnchor(treeId int64, leaf *trillian.LogLeaf) (*v1.DataAnchor, error) {
	log.Tracef("findAnchorByLeafHash %v %x", treeId, leaf.MerkleLeafHash)

	// Retrieve STH
	reply, err := t.client.GetLatestSignedLogRoot(t.ctx,
		&trillian.GetLatestSignedLogRootRequest{
			LogId: treeId,
		})
	if err != nil {
		return nil, err
	}
	var lrv1 types.LogRootV1
	err = lrv1.UnmarshalBinary(reply.SignedLogRoot.LogRoot)
	if err != nil {
		return nil, err
	}

	// Start at the provided leaf and scan the tree for
	// an anchor. We request a page of leaves at a time.
	var (
		anchor     *v1.DataAnchor
		pageSize   int64 = 10
		startIndex int64 = leaf.LeafIndex + 1
	)
	for anchor == nil && startIndex < int64(lrv1.TreeSize) {
		// Retrieve a page of leaves
		glbrr, err := t.client.GetLeavesByRange(t.ctx,
			&trillian.GetLeavesByRangeRequest{
				LogId:      treeId,
				StartIndex: startIndex,
				Count:      pageSize,
			})
		if err != nil {
			return nil, err
		}

		// Scan leaves for an anchor
		for _, v := range glbrr.Leaves {
			// Retrieve leaf payload from backend
			payload, err := t.s.Get(v.ExtraData)
			if err != nil {
				return nil, err
			}
			re, err := deblob(payload)
			if err != nil {
				return nil, err
			}

			// Investigate data hint
			dhb, err := base64.StdEncoding.DecodeString(re.DataHint)
			if err != nil {
				return nil, err
			}
			var dh v1.DataDescriptor
			err = json.Unmarshal(dhb, &dh)
			if err != nil {
				return nil, err
			}
			if !(dh.Type == v1.DataTypeStructure &&
				dh.Descriptor == v1.DataDescriptorAnchor) {
				// Not a anchor. Try the next one.
				continue
			}

			// Found one!
			data, err := base64.StdEncoding.DecodeString(re.Data)
			if err != nil {
				return nil, err
			}
			var da v1.DataAnchor
			err = json.Unmarshal(data, &da)
			if err != nil {
				return nil, err
			}
			anchor = &da
			break
		}

		// Increment startIndex and try again
		startIndex += pageSize
	}

	return anchor, nil
}

// findLatestAnchor scans all leaves in a tree and returns the latest anchor.
// If there is no anchor it returns nil.
func (t *tserver) findLatestAnchor(tree *trillian.Tree, lrv1 *types.LogRootV1) (*v1.DataAnchor, error) {
	log.Tracef("findLatestAnchor")

	// Get leaves
	startIndex := int64(lrv1.TreeSize) - 1
	if startIndex < 0 {
		startIndex = 1
	}
	glbrr, err := t.client.GetLeavesByRange(t.ctx,
		&trillian.GetLeavesByRangeRequest{
			LogId:      tree.TreeId,
			StartIndex: startIndex,
			Count:      int64(lrv1.TreeSize),
		})
	if err != nil {
		return nil, err
	}

	// We can be clever and request only the top leaf and see if it is an
	// anchor. Note that the FSCK code must walk the entire tree backwards.
	log.Tracef("findLatestAnchor get: %s", glbrr.Leaves[0].ExtraData)
	payload, err := t.s.Get(glbrr.Leaves[0].ExtraData)
	if err != nil {
		return nil, err
	}
	re, err := deblob(payload)
	if err != nil {
		return nil, err
	}

	// investigate data hint
	dhb, err := base64.StdEncoding.DecodeString(re.DataHint)
	if err != nil {
		return nil, err
	}
	var dh v1.DataDescriptor
	err = json.Unmarshal(dhb, &dh)
	if err != nil {
		log.Errorf("findLatestAnchor invalid datahint %v", dh.Type)
		return nil, err
	}
	if !(dh.Type == v1.DataTypeStructure &&
		dh.Descriptor == v1.DataDescriptorAnchor) {
		return nil, nil
	}

	// Found one!
	data, err := base64.StdEncoding.DecodeString(re.Data)
	if err != nil {
		return nil, err
	}
	var da v1.DataAnchor
	err = json.Unmarshal(data, &da)
	if err != nil {
		log.Errorf("findLatestAnchor invalid DataAnchor %v", err)
		return nil, err
	}
	return &da, nil
}

// scanAllRecords scans all records and determines if a record is dirty and at
// what height.
func (t *tserver) scanAllRecords() error {
	log.Tracef("scanAllRecords")
	// List trees
	ltr, err := t.admin.ListTrees(t.ctx, &trillian.ListTreesRequest{})
	if err != nil {
		return err
	}

	if len(ltr.Tree) == 0 {
		log.Infof("scanAllRecords: nothing dirty")
		return nil
	}

	// Get all records
	log.Debugf("scanAllRecords scanning records: %v", len(ltr.Tree))
	for _, tree := range ltr.Tree {
		// Retrieve STH
		_, lrv1, err := t.getLatestSignedLogRoot(tree)
		if err != nil {
			return err
		}
		log.Tracef("scanAllRecords scanning %v %v", lrv1.TreeSize,
			tree.TreeId)

		// Load data from backend to find anchors
		anchor, err := t.findLatestAnchor(tree, lrv1)
		if err != nil {
			return err
		}

		if anchor == nil {
			// No anchor yet in this record
			t.Lock()
			t.dirty[tree.TreeId] = int64(lrv1.TreeSize)
			t.Unlock()
			continue
		}
	}

	t.Lock()
	r := len(t.dirty)
	t.Unlock()
	log.Infof("Unanchored records: %v", r)

	return nil
}

// anchorRecords is a function that is periodically called to anchor dirty
// records.
func (t *tserver) anchorRecords() {
	var exitError error // Set on exit if there is an error
	defer func() {
		if exitError != nil {
			log.Errorf("anchorRecords %v", exitError)
		}
	}()

	// Copy dirty records
	t.Lock()
	anchors := make([]v1.DataAnchor, 0, len(t.dirty))
	for k := range t.dirty {
		anchors = append(anchors, v1.DataAnchor{RecordId: k})
	}
	t.Unlock()
	if len(anchors) == 0 {
		log.Infof("Nothing to anchor")
		return
	}

	// XXX Abort entire run if there is an error for now.

	// Scan over the dirty records
	trees := make([]*trillian.Tree, len(anchors))      // Cache trees
	hashes := make([]*[sha256.Size]byte, len(anchors)) // Coalesce records
	lrv1s := make([]*types.LogRootV1, len(anchors))    // We need TreeSize
	for k, v := range anchors {
		log.Tracef("Obtaining anchoring data: %v", v.RecordId)

		tree, err := t.getTree(v.RecordId)
		if err != nil {
			exitError = fmt.Errorf("getTree %v", err)
			return
		}
		sth, lrv1, err := t.getLatestSignedLogRoot(tree)
		if err != nil {
			exitError = fmt.Errorf("getLatestSignedLogRoot: %v",
				err)
			return
		}

		trees[k] = tree
		anchors[k].STH = *sth
		lrv1s[k] = lrv1
		hashes[k] = util.Hash(sth.LogRoot)
	}

	// Ensure we aren't reentrant. This is done deliberately late in the
	// process.
	t.Lock()
	if t.droppingAnchor {
		// This shouldn't happen so let's warn the user of something
		// misbehaving.
		t.Unlock()
		log.Infof("Dropping anchor already in progress")
		return
	}
	t.Unlock()

	log.Infof("Anchoring records: %v", len(anchors))

	err := util.Timestamp("tserver", t.cfg.DcrtimeHost, hashes)
	if err != nil {
		exitError = err
		return
	}

	go t.waitForAchor(trees, anchors, hashes, lrv1s)
}

// waitForAchor waits until an anchor drops.
func (t *tserver) waitForAchor(trees []*trillian.Tree, anchors []v1.DataAnchor, hashes []*[sha256.Size]byte, lrv1s []*types.LogRootV1) {
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

	// Construct verify command
	waitFor := make([]string, 0, len(hashes))
	for _, v := range hashes {
		waitFor = append(waitFor, hex.EncodeToString(v[:]))
	}

	period := time.Duration(1)  // in minutes
	retries := 30 / int(period) // wait up to 30 minutes
	ticker := time.NewTicker(period * time.Minute)
	defer ticker.Stop()
	for try := 0; try < retries; try++ {
	restart:
		<-ticker.C

		log.Tracef("anchorRecords checking anchor")

		vr, err := util.Verify("tserver", t.cfg.DcrtimeHost, waitFor)
		if err != nil {
			if _, ok := err.(util.ErrNotAnchored); ok {
				// Anchor not dropped, try again
				log.Tracef("anchorRecords: try %v %v", try, err)
				continue
			} else {
				log.Errorf("waitForAchor: %v", err)
				return
			}
		}

		// Make sure we are actually anchored.
		for _, v := range vr.Digests {
			if v.ChainInformation.ChainTimestamp == 0 {
				log.Tracef("anchorRecords ChainTimestamp 0: %v",
					v.Digest)
				goto restart
			}
		}

		log.Tracef("%T %v", vr, spew.Sdump(vr))

		log.Infof("Anchor dropped")

		// Drop anchor records
		for k, v := range anchors {
			da := v1.DataAnchor{
				RecordId:     v.RecordId,
				STH:          v.STH,
				VerifyDigest: vr.Digests[k],
			}
			log.Tracef("DataAnchor: %v", spew.Sdump(da))

			data, err := json.Marshal(da)
			if err != nil {
				log.Errorf("waitForAchor: marshal data: %v",
					err)
				continue
			}

			// construct a RecordEntry
			dd, err := json.Marshal(v1.DataDescriptor{
				Type:       v1.DataTypeStructure,
				Descriptor: v1.DataDescriptorAnchor,
			})
			if err != nil {
				log.Errorf("waitForAchor: marshal desc: %v",
					err)
				continue
			}
			re := util.RecordEntryNew(nil, dd, data)

			treeID := trees[k].TreeId
			proofs, sth, err := t.appendRecord(trees[k], &v.STH,
				[]v1.RecordEntry{re})
			if err != nil {
				log.Errorf("waitForAchor appendRecord %v: %v",
					treeID, err)
				continue
			}

			// Check QueuedLogLeafProofs
			if len(proofs) != 1 {
				log.Errorf("waitForAchor %v: QueuedLogLeaveProofs != 1",
					treeID)
				continue
			}
			ql := proofs[0].QueuedLeaf
			c := codes.Code(ql.GetStatus().GetCode())
			if c != codes.OK {
				log.Errorf("waitForAnchor leaf not appended %v: %v",
					treeID, ql.GetStatus().GetMessage())
				continue
			}
			if proofs[0].Proof == nil {
				log.Errorf("waitForAnchor %v: no proof",
					treeID)
				continue
			}

			// Verify STH
			verifier, err := client.NewLogVerifierFromTree(trees[k])
			if err != nil {
				log.Errorf("waitForAnchor NewLogVerifierFromTree %v: %v",
					treeID, err)
				continue
			}
			lrv1, err := tcrypto.VerifySignedLogRoot(verifier.PubKey,
				crypto.SHA256, sth)
			if err != nil {
				log.Errorf("waitForAnchor VerifySignedLogRoot %v: %v",
					treeID, err)
				continue
			}

			// Verify inclusion proof
			err = verifier.VerifyInclusionByHash(lrv1,
				ql.Leaf.MerkleLeafHash, proofs[0].Proof)
			if err != nil {
				log.Errorf("waitForAnchor VerifyInclusionByHash %v: %v",
					treeID, err)
				continue
			}
		}

		// Fixup dirty structure
		t.Lock()
		defer t.Unlock()

		// Go over anchors and compare TreeSize to see if the tree was
		// made dirty during anchor process.
		for k, v := range anchors {
			size, ok := t.dirty[v.RecordId]
			if !ok {
				// XXX panic?
				log.Criticalf("anchorRecords id dissapeared: %v",
					v.RecordId)
				return
			}

			if int64(lrv1s[k].TreeSize) != size {
				log.Tracef("anchorRecords record changed, remains "+
					"dirty %v %v != %v", v.RecordId,
					lrv1s[k].TreeSize, size)

				// Updte size
				t.dirty[v.RecordId] = int64(lrv1s[k].TreeSize)
				continue
			}

			log.Tracef("anchorRecords marking record clean: %v",
				v.RecordId)
			delete(t.dirty, v.RecordId)
		}

		return
	}

	log.Errorf("Anchor drop timeout, waited for: %v", period*time.Minute)
}

func NewSHA256(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func (t *tserver) fsckRecord(tree *trillian.Tree, lrv1 *types.LogRootV1) error {
	log.Tracef("fsckRecord")

	// Get leaves
	glbrr, err := t.client.GetLeavesByRange(t.ctx,
		&trillian.GetLeavesByRangeRequest{
			LogId:      tree.TreeId,
			StartIndex: 0,
			Count:      int64(lrv1.TreeSize),
		})
	if err != nil {
		return err
	}

	// XXX perform trillian tree coherency test

	// Walk leaves backwards
	for x := len(glbrr.Leaves) - 1; x >= 0; x-- {
		log.Tracef("fsckRecord get: %s", glbrr.Leaves[x].ExtraData)
		payload, err := t.s.Get(glbrr.Leaves[x].ExtraData)
		if err != nil {
			// Absence of a record entry does not necessarily mean something
			// is wrong. If there was an error during the record append call
			// the trillian leaves will still exist but the record entry
			// blobs would have been unwound.
			log.Debugf("Record entry not found %v %v: %v",
				glbrr.Leaves[x].MerkleLeafHash,
				glbrr.Leaves[x].ExtraData, err)
			continue
		}
		re, err := deblob(payload)
		if err != nil {
			return err
		}

		// investigate data hint
		dhb, err := base64.StdEncoding.DecodeString(re.DataHint)
		if err != nil {
			return err
		}
		var dh v1.DataDescriptor
		err = json.Unmarshal(dhb, &dh)
		if err != nil {
			return fmt.Errorf("fsckRecord invalid datahint %v %v",
				x, dh.Type)
		}

		switch dh.Type {
		case v1.DataTypeKeyValue:
			data, err := base64.StdEncoding.DecodeString(re.Data)
			if err != nil {
				return fmt.Errorf("fsckRecord base64 %v %v",
					x, err)
			}
			log.Tracef("fsckRecord kv: %s", data)
			hash := NewSHA256(data)
			if !bytes.Equal(hash, glbrr.Leaves[x].LeafValue) {
				return fmt.Errorf("fsckRecord data key/value "+
					"corruption %s",
					glbrr.Leaves[x].ExtraData)
			}
			log.Tracef("fsckRecord %s Data integrity OK",
				glbrr.Leaves[x].ExtraData)
			continue
		case v1.DataTypeMime:
			log.Tracef("fsckRecord mime: %v", dh.Descriptor)

			data, err := base64.StdEncoding.DecodeString(re.Data)
			if err != nil {
				return fmt.Errorf("fsckRecord base64 %v %v",
					x, err)
			}
			hash := NewSHA256(data)
			if !bytes.Equal(hash, glbrr.Leaves[x].LeafValue) {
				return fmt.Errorf("fsckRecord data corruption %s",
					glbrr.Leaves[x].ExtraData)
			}
			log.Tracef("fsckRecord %s Data integrity OK",
				glbrr.Leaves[x].ExtraData)
			continue
		case v1.DataTypeStructure:
			if !(dh.Descriptor == v1.DataDescriptorAnchor) {
				log.Tracef("fsckRecord skipping %v %v",
					x, dh.Type)
				continue
			}
			log.Tracef("fsckRecord struct: %v", dh.Descriptor)
			data, err := base64.StdEncoding.DecodeString(re.Data)
			if err != nil {
				return fmt.Errorf("fsckRecord base64 %v %v",
					x, err)
			}
			var da v1.DataAnchor
			err = json.Unmarshal(data, &da)
			if err != nil {
				return fmt.Errorf("fsckRecord invalid "+
					"DataAnchor %v %v", x, err)
			}

			// Verify hash
			hash := NewSHA256(data)
			if !bytes.Equal(hash, glbrr.Leaves[x].LeafValue) {
				return fmt.Errorf("fsckRecord data structure "+
					"corruption %s",
					glbrr.Leaves[x].ExtraData)
			}
			log.Tracef("fsckRecord %s Data integrity OK",
				glbrr.Leaves[x].ExtraData)

			// Verify anchor
			_, err = util.Verify("tserver", t.cfg.DcrtimeHost,
				[]string{da.VerifyDigest.Digest})
			if err != nil {
				return fmt.Errorf("fsckRecord failed "+
					"anchor %v", err)
			}

			log.Tracef("fsckRecord %s Anchor OK",
				glbrr.Leaves[x].ExtraData)
			continue
		default:
			return fmt.Errorf("fsckRecord unknown type: %v", dh.Type)
		}
	}

	return nil
}

func (t *tserver) fsck(f v1.RecordFsck) error {
	// Get tree and STH to perform fsck on
	tree, err := t.getTree(f.Id)
	if err != nil {
		return err
	}
	sth, lrv1, err := t.getLatestSignedLogRoot(tree)
	if err != nil {
		return err
	}
	_ = sth

	return t.fsckRecord(tree, lrv1)
}
