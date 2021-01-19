// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlogbe

import (
	"encoding/hex"
	"fmt"

	"github.com/decred/politeia/politeiad/backend"
)

const (
	// Record states
	stateUnvetted = "unvetted"
	stateVetted   = "vetted"
)

// inventory contains the tokens of all records in the inventory catagorized by
// MDStatusT.
type inventory struct {
	unvetted map[backend.MDStatusT][]string
	vetted   map[backend.MDStatusT][]string
}

func (t *tlogBackend) inventory() inventory {
	t.RLock()
	defer t.RUnlock()

	// Return a copy of the inventory
	var (
		unvetted = make(map[backend.MDStatusT][]string, len(t.inv.unvetted))
		vetted   = make(map[backend.MDStatusT][]string, len(t.inv.vetted))
	)
	for status, tokens := range t.inv.unvetted {
		s := make([]string, len(tokens))
		copy(s, tokens)
		unvetted[status] = s
	}
	for status, tokens := range t.inv.vetted {
		s := make([]string, len(tokens))
		copy(s, tokens)
		vetted[status] = s
	}

	return inventory{
		unvetted: unvetted,
		vetted:   vetted,
	}
}

func (t *tlogBackend) inventoryAdd(state string, tokenb []byte, s backend.MDStatusT) {
	t.Lock()
	defer t.Unlock()

	token := hex.EncodeToString(tokenb)
	switch state {
	case stateUnvetted:
		t.inv.unvetted[s] = append([]string{token}, t.inv.unvetted[s]...)
	case stateVetted:
		t.inv.vetted[s] = append([]string{token}, t.inv.vetted[s]...)
	default:
		e := fmt.Sprintf("unknown state '%v'", state)
		panic(e)
	}

	log.Debugf("Add to inv %v: %v %v", state, token, backend.MDStatus[s])
}

func (t *tlogBackend) inventoryUpdate(state string, tokenb []byte, currStatus, newStatus backend.MDStatusT) {
	token := hex.EncodeToString(tokenb)

	t.Lock()
	defer t.Unlock()

	var inv map[backend.MDStatusT][]string
	switch state {
	case stateUnvetted:
		inv = t.inv.unvetted
	case stateVetted:
		inv = t.inv.vetted
	default:
		e := fmt.Sprintf("unknown state '%v'", state)
		panic(e)
	}

	// Find the index of the token in its current status list
	var idx int
	var found bool
	for k, v := range inv[currStatus] {
		if v == token {
			// Token found
			idx = k
			found = true
			break
		}
	}
	if !found {
		// Token was never found. This should not happen.
		e := fmt.Sprintf("inventoryUpdate: token not found: %v %v %v",
			token, currStatus, newStatus)
		panic(e)
	}

	// Remove the token from its current status list
	tokens := inv[currStatus]
	inv[currStatus] = append(tokens[:idx], tokens[idx+1:]...)

	// Prepend token to new status
	inv[newStatus] = append([]string{token}, inv[newStatus]...)

	log.Debugf("Update inv %v: %v %v to %v", state, token,
		backend.MDStatus[currStatus], backend.MDStatus[newStatus])
}

// inventoryMoveToVetted moves a token from the unvetted inventory to the
// vetted inventory. The unvettedStatus is the status of the record prior to
// the update and the vettedStatus is the status of the record after the
// update.
func (t *tlogBackend) inventoryMoveToVetted(tokenb []byte, unvettedStatus, vettedStatus backend.MDStatusT) {
	t.Lock()
	defer t.Unlock()

	token := hex.EncodeToString(tokenb)
	unvetted := t.inv.unvetted
	vetted := t.inv.vetted

	// Find the index of the token in its current status list
	var idx int
	var found bool
	for k, v := range unvetted[unvettedStatus] {
		if v == token {
			// Token found
			idx = k
			found = true
			break
		}
	}
	if !found {
		// Token was never found. This should not happen.
		e := fmt.Sprintf("inventoryMoveToVetted: unvetted token not found: %v %v",
			token, unvettedStatus)
		panic(e)
	}

	// Remove the token from the unvetted status list
	tokens := unvetted[unvettedStatus]
	unvetted[unvettedStatus] = append(tokens[:idx], tokens[idx+1:]...)

	// Prepend token to vetted status
	vetted[vettedStatus] = append([]string{token}, vetted[vettedStatus]...)

	log.Debugf("Inv move to vetted: %v %v to %v", token,
		backend.MDStatus[unvettedStatus], backend.MDStatus[vettedStatus])
}
