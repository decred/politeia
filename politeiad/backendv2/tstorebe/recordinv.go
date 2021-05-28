// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tstorebe

import (
	"encoding/hex"
	"fmt"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/inv"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
)

const (
	// Keys for the inventory objects that are saved to the key-value
	// store.
	keyUnvettedInv = "pd-recordinv-unvetted"
	keyVettedInv   = "pd-recordinv-vetted"
)

// invBits represents bit flags that are used to encode record data into an
// inventory entry. The inventory can be queried using these bit flags.
type invBits uint64

const (
	// Record status bits
	bitsInvalid          invBits = 0
	bitsStatusUnreviewed invBits = 1 << 0
	bitsStatusPublic     invBits = 1 << 1
	bitsStatusCensored   invBits = 1 << 2
	bitsStatusArchived   invBits = 1 << 3
)

// recordInv provides an API for interacting with the tstorebe record
// inventory. The inventory contains the token, status, and timestamp of the
// most recent status change for every record that has been submitted to the
// tstorebe. The unvetted inventory is saved encrypted. The vetted inventory
// is saved clear text.
type recordInv struct {
	unvetted *inv.Inv
	vetted   *inv.Inv
}

// newRecordInv returns a new recordInv.
func newRecordInv() *recordInv {
	return &recordInv{
		unvetted: inv.New(keyUnvettedInv, true),
		vetted:   inv.New(keyVettedInv, false),
	}
}

// invAdd adds a new entry to the unvetted record inventory.
func (t *tstoreBackend) invAdd(tx store.Tx, token []byte, timestamp int64) error {
	err := t.inv.unvetted.Add(tx, hex.EncodeToString(token),
		uint64(bitsStatusUnreviewed), timestamp)
	if err != nil {
		return err
	}

	log.Debugf("Inv add unvetted %x", token)

	return nil
}

// invUpdate updates the status and timestamp of a record entry in the
// inventory. The record state must remain the same when using this function.
func (t *tstoreBackend) invUpdate(tx store.Tx, state backend.StateT, token []byte, status backend.StatusT, timestamp int64) error {
	switch state {
	case backend.StateUnvetted:
		err := t.inv.unvetted.Update(tx, hex.EncodeToString(token),
			uint64(invBitsForStatus(status)), timestamp)
		if err != nil {
			return err
		}
	case backend.StateVetted:
		err := t.inv.vetted.Update(tx, hex.EncodeToString(token),
			uint64(invBitsForStatus(status)), timestamp)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("invalid record state: %v", state)
	}

	log.Debugf("Inv update %v %x to %v",
		backend.States[state], token, backend.Statuses[status])

	return nil
}

// invMoveToVetted deletes a record from the unvetted inventory then adds it
// to the vetted inventory.
func (t *tstoreBackend) invMoveToVetted(tx store.Tx, token []byte, timestamp int64) error {
	// Del entry from unvetted inv
	tkn := hex.EncodeToString(token)
	err := t.inv.unvetted.Del(tx, tkn)
	if err != nil {
		return err
	}

	// Add entry to vetted inv
	err = t.inv.vetted.Add(tx, tkn, uint64(bitsStatusPublic), timestamp)
	if err != nil {
		return fmt.Errorf("vetted add: %v", err)
	}

	log.Debugf("Inv move to vetted %x", token)

	return nil
}

// invByStatus contains the inventory categorized by record state and record
// status. Each list contains a page of tokens that are sorted by the timestamp
// of the status change from newest to oldest.
type invByStatus struct {
	Unvetted map[backend.StatusT][]string
	Vetted   map[backend.StatusT][]string
}

// invByStatusAll returns a page of tokens for all record states and statuses.
// The tokens are ordered by the timestamp of their most recent status change,
// sorted from newest to oldest.
func (t *tstoreBackend) invByStatusAll(sg store.Getter, pageSize uint32) (*invByStatus, error) {
	// Get unvetted inventory
	bits := []uint64{
		uint64(bitsStatusUnreviewed),
		uint64(bitsStatusCensored),
		uint64(bitsStatusArchived),
	}
	inv, err := t.inv.unvetted.GetMulti(sg, bits, pageSize, 1)
	if err != nil {
		return nil, err
	}

	// Prepare unvetted inventory reply
	var (
		unreviewed = inv[uint64(bitsStatusUnreviewed)]
		censored   = inv[uint64(bitsStatusCensored)]
		archived   = inv[uint64(bitsStatusArchived)]

		unvetted = make(map[backend.StatusT][]string, 16)
	)
	if len(unreviewed) != 0 {
		unvetted[backend.StatusUnreviewed] = unreviewed
	}
	if len(censored) != 0 {
		unvetted[backend.StatusCensored] = censored
	}
	if len(archived) != 0 {
		unvetted[backend.StatusArchived] = archived
	}

	// Get vetted inventory
	bits = []uint64{
		uint64(bitsStatusPublic),
		uint64(bitsStatusCensored),
		uint64(bitsStatusArchived),
	}
	inv, err = t.inv.vetted.GetMulti(sg, bits, pageSize, 1)
	if err != nil {
		return nil, err
	}

	// Prepare vetted inventory reply
	var (
		public    = inv[uint64(bitsStatusPublic)]
		vcensored = inv[uint64(bitsStatusCensored)]
		varchived = inv[uint64(bitsStatusArchived)]

		vetted = make(map[backend.StatusT][]string, 16)
	)
	if len(public) != 0 {
		vetted[backend.StatusPublic] = public
	}
	if len(vcensored) != 0 {
		vetted[backend.StatusCensored] = vcensored
	}
	if len(varchived) != 0 {
		vetted[backend.StatusArchived] = varchived
	}

	return &invByStatus{
		Unvetted: unvetted,
		Vetted:   vetted,
	}, nil
}

// invByStatus returns the tokens of records in the inventory categorized by
// record state and record status. The tokens are ordered by the timestamp of
// their most recent status change, sorted from newest to oldest.
//
// The state, status, and pageNum arguments can be provided to request a
// specific page of record tokens.
//
// If no status is provided then the most recent page of tokens for all
// statuses will be returned. The state and pageNum arguments are ignored when
// no status is provided.
func (t *tstoreBackend) invByStatus(sg store.Getter, state backend.StateT, status backend.StatusT, pageSize, pageNum uint32) (*invByStatus, error) {
	// If no status is provided a page of tokens for each status should
	// be returned.
	if status == backend.StatusInvalid {
		return t.invByStatusAll(sg, pageSize)
	}

	var (
		unvetted = make(map[backend.StatusT][]string, 16)
		vetted   = make(map[backend.StatusT][]string, 16)
	)
	switch state {
	case backend.StateUnvetted:
		// Get the requested page of entries
		// TODO pick up here
	case backend.StateVetted:
	}

	return *invByStatus{
		Unvetted: unvetted,
		Vetted:   vetted,
	}, nil
}

// invOrdered returns a page of record tokens ordered by the timestamp of their
// most recent status change. The returned tokens will include tokens for all
// record statuses.
func (t *tstoreBackend) invOrdered(state backend.StateT, pageSize, pageNumber uint32) ([]string, error) {
	// Get inventory file path
	// Get inventory
	// Return specified page of tokens
	return nil, nil
}

// invBits returns the invBits for the provided record status.
func invBitsForStatus(s backend.StatusT) invBits {
	switch s {
	case backend.StatusUnreviewed:
		return bitsStatusUnreviewed
	case backend.StatusPublic:
		return bitsStatusPublic
	case backend.StatusCensored:
		return bitsStatusCensored
	case backend.StatusArchived:
		return bitsStatusArchived
	}
	return bitsInvalid
}
