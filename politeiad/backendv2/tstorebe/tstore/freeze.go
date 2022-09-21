// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tstore

import (
	"errors"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/google/trillian"
)

// freezeTrees checks if any trillian trees meet the requirements to be frozen.
// If they do, their status is updated in trillian to frozen.
//
// A frozen trillian tree can no longer be appended to. The trillian_log_signer
// will no longer poll the MySQL database for updates to a tree once it has
// been marked as frozen. This reduces the load on the server and helps prevent
// the CPUs from spinning.
//
// A record is marked as frozen when it can no longer be updated, such as when
// a record status is set to archived. The trillian tree, however, cannot be
// frozen until the record is frozen AND a final dcr timestamp has been added
// to tree. This means that we cannot simply freeze the tree at the same time
// that the record is frozen since it will still need to be timestamped one
// last time.
func (t *Tstore) freezeTrees() error {
	trees, err := t.tlog.TreesAll()
	if err != nil {
		return err
	}

	log.Infof("Starting tree freezing process; checking %v trees", len(trees))

	active := make([]*trillian.Tree, 0, len(trees))
	for _, v := range trees {
		if v.TreeState == trillian.TreeState_ACTIVE {
			active = append(active, v)
		}
	}

	log.Infof("%v active trees found", len(active))

	var frozen int
	for _, tree := range active {
		freeze, err := t.treeShouldBeFrozen(tree)
		if err != nil {
			log.Errorf("treeShouldBeFrozen %v: %v", tree.TreeId, err)
			continue
		}
		if !freeze {
			// Tree shouldn't be frozen. Nothing else to do.
			continue
		}
		_, err = t.tlog.TreeFreeze(tree.TreeId)
		if err != nil {
			return err
		}

		log.Infof("Tree frozen %v %x", tree.TreeId, tokenFromTreeID(tree.TreeId))

		frozen++
	}

	log.Infof("%v trees were frozen; %v active trees remaining",
		frozen, len(active)-frozen)

	return nil
}

// treeShouldBeFrozen returns whether a trillian tree meets the requirements to
// have it's status updated from ACTIVE to FROZEN. The requirments are that the
// tree is currently active, the record saved to the tree has been frozen, and
// a final dcr timestamp has been added to the tree.
func (t *Tstore) treeShouldBeFrozen(tree *trillian.Tree) (bool, error) {
	if tree.TreeState != trillian.TreeState_ACTIVE {
		return false, nil
	}
	leaves, err := t.tlog.LeavesAll(tree.TreeId)
	if err != nil {
		return false, err
	}
	if len(leaves) == 0 {
		return false, nil
	}
	r, err := t.recordIndexLatest(leaves)
	switch {
	case errors.Is(err, backend.ErrRecordNotFound):
		// A record index doesn't exist on this tree
		return false, nil
	case err != nil:
		return false, err
	}
	if !r.Frozen {
		// The record has not been frozen yet
		return false, nil
	}
	// The record has been frozen. Check for a final
	// timestamp leaf.
	lastLeaf := leaves[len(leaves)-1]
	d, err := extraDataDecode(lastLeaf.ExtraData)
	if err != nil {
		return false, err
	}
	if d.Desc != dataDescriptorAnchor {
		// The tree still needs a final timestamp.
		return false, nil
	}
	// The record has been frozen and a final timestamp
	// has been added to the tree. The tree can now be
	// frozen.
	return true, nil
}
