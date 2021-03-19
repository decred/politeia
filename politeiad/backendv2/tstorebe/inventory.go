// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tstorebe

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	backend "github.com/decred/politeia/politeiad/backendv2"
)

const (
	filenameInvUnvetted = "inv-unvetted.json"
	filenameInvVetted   = "inv-vetted.json"
)

type entry struct {
	Token  string          `json:"token"`
	Status backend.StatusT `json:"status"`
}

type inventory struct {
	Entries []entry `json:"entries"`
}

func (t *tstoreBackend) invPathUnvetted() string {
	return filepath.Join(t.dataDir, filenameInvUnvetted)
}

func (t *tstoreBackend) invPathVetted() string {
	return filepath.Join(t.dataDir, filenameInvVetted)
}

// invGetLocked retrieves the inventory from disk. A new inventory is returned
// if one does not exist yet.
//
// This function must be called WITH the read lock held.
func (t *tstoreBackend) invGetLocked(filePath string) (*inventory, error) {
	b, err := ioutil.ReadFile(filePath)
	if err != nil {
		var e *os.PathError
		if errors.As(err, &e) && !os.IsExist(err) {
			// File does't exist. Return a new inventory.
			return &inventory{
				Entries: make([]entry, 0, 1024),
			}, nil
		}
		return nil, err
	}

	var inv inventory
	err = json.Unmarshal(b, &inv)
	if err != nil {
		return nil, err
	}

	return &inv, nil
}

// invGet retrieves the inventory from disk. A new inventory is returned if one
// does not exist yet.
//
// This function must be called WITHOUT the read lock held.
func (t *tstoreBackend) invGet(filePath string) (*inventory, error) {
	t.RLock()
	defer t.RUnlock()

	return t.invGetLocked(filePath)
}

// invSaveLocked writes the inventory to disk.
//
// This function must be called WITH the read/write lock held.
func (t *tstoreBackend) invSaveLocked(filePath string, inv inventory) error {
	b, err := json.Marshal(inv)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filePath, b, 0664)
}

func (t *tstoreBackend) invAdd(state backend.StateT, token []byte, s backend.StatusT) error {
	t.Lock()
	defer t.Unlock()

	// Get inventory file path
	var fp string
	switch state {
	case backend.StateUnvetted:
		fp = t.invPathUnvetted()
	case backend.StateVetted:
		fp = t.invPathVetted()
	default:
		return fmt.Errorf("invalid state %v", state)
	}

	// Get inventory
	inv, err := t.invGetLocked(fp)
	if err != nil {
		return err
	}

	// Prepend token
	e := entry{
		Token:  hex.EncodeToString(token),
		Status: s,
	}
	inv.Entries = append([]entry{e}, inv.Entries...)

	// Save inventory
	err = t.invSaveLocked(fp, *inv)
	if err != nil {
		return err
	}

	log.Debugf("Inv add %v %x %v",
		backend.States[state], token, backend.Statuses[s])

	return nil
}

func (t *tstoreBackend) invUpdate(state backend.StateT, token []byte, s backend.StatusT) error {
	t.Lock()
	defer t.Unlock()

	// Get inventory file path
	var fp string
	switch state {
	case backend.StateUnvetted:
		fp = t.invPathUnvetted()
	case backend.StateVetted:
		fp = t.invPathVetted()
	default:
		return fmt.Errorf("invalid state %v", state)
	}

	// Get inventory
	inv, err := t.invGetLocked(fp)
	if err != nil {
		return err
	}

	// Del entry
	entries, err := entryDel(inv.Entries, token)
	if err != nil {
		return fmt.Errorf("%v entry del: %v", state, err)
	}

	// Prepend new entry to inventory
	e := entry{
		Token:  hex.EncodeToString(token),
		Status: s,
	}
	inv.Entries = append([]entry{e}, entries...)

	// Save inventory
	err = t.invSaveLocked(fp, *inv)
	if err != nil {
		return err
	}

	log.Debugf("Inv update %v %x to %v",
		backend.States[state], token, backend.Statuses[s])

	return nil
}

// invMoveToVetted moves a token from the unvetted inventory to the vetted
// inventory.
func (t *tstoreBackend) invMoveToVetted(token []byte, s backend.StatusT) error {
	t.Lock()
	defer t.Unlock()

	// Get unvetted inventory
	upath := t.invPathUnvetted()
	u, err := t.invGetLocked(upath)
	if err != nil {
		return fmt.Errorf("unvetted invGetLocked: %v", err)
	}

	// Del entry
	u.Entries, err = entryDel(u.Entries, token)
	if err != nil {
		return fmt.Errorf("entryDel: %v", err)
	}

	// Save unvetted inventory
	err = t.invSaveLocked(upath, *u)
	if err != nil {
		return fmt.Errorf("unvetted invSaveLocked: %v", err)
	}

	// Get vetted inventory
	vpath := t.invPathVetted()
	v, err := t.invGetLocked(vpath)
	if err != nil {
		return fmt.Errorf("vetted invGetLocked: %v", err)
	}

	// Prepend new entry to inventory
	e := entry{
		Token:  hex.EncodeToString(token),
		Status: s,
	}
	v.Entries = append([]entry{e}, v.Entries...)

	// Save vetted inventory
	err = t.invSaveLocked(vpath, *v)
	if err != nil {
		return fmt.Errorf("vetted invSaveLocked: %v", err)
	}

	log.Debugf("Inv move to vetted %x %v", token, backend.Statuses[s])

	return nil
}

// inventoryAdd is a wrapper around the invAdd method that allows us to decide
// how errors should be handled. For now we just panic. If an error occurs the
// cache is no longer coherent and the only way to fix it is to rebuild it.
func (t *tstoreBackend) inventoryAdd(state backend.StateT, token []byte, s backend.StatusT) {
	err := t.invAdd(state, token, s)
	if err != nil {
		panic(fmt.Sprintf("invAdd %v %x %v: %v", state, token, s, err))
	}
}

// inventoryUpdate is a wrapper around the invUpdate method that allows us to
// decide how disk read/write errors should be handled. For now we just panic.
// If an error occurs the cache is no longer coherent and the only way to fix
// it is to rebuild it.
func (t *tstoreBackend) inventoryUpdate(state backend.StateT, token []byte, s backend.StatusT) {
	err := t.invUpdate(state, token, s)
	if err != nil {
		panic(fmt.Sprintf("invUpdate %v %x %v: %v", state, token, s, err))
	}
}

// inventoryMoveToVetted is a wrapper around the invMoveToVetted method that
// allows us to decide how disk read/write errors should be handled. For now we
// just panic. If an error occurs the cache is no longer coherent and the only
// way to fix it is to rebuild it.
func (t *tstoreBackend) inventoryMoveToVetted(token []byte, s backend.StatusT) {
	err := t.invMoveToVetted(token, s)
	if err != nil {
		panic(fmt.Sprintf("invMoveToVetted %x %v: %v", token, s, err))
	}
}

// invByStatus contains the inventory categorized by record state and record
// status. Each list contains a page of tokens that are sorted by the timestamp
// of the status change from newest to oldest.
type invByStatus struct {
	Unvetted map[backend.StatusT][]string
	Vetted   map[backend.StatusT][]string
}

func (t *tstoreBackend) invByStatusAll(pageSize uint32) (*invByStatus, error) {
	// Get unvetted inventory
	u, err := t.invGet(t.invPathUnvetted())
	if err != nil {
		return nil, err
	}

	// Prepare unvetted inventory reply
	var (
		unvetted = tokensParse(u.Entries, backend.StatusUnreviewed, pageSize, 1)
		censored = tokensParse(u.Entries, backend.StatusCensored, pageSize, 1)
		archived = tokensParse(u.Entries, backend.StatusArchived, pageSize, 1)

		unvettedInv = make(map[backend.StatusT][]string, 16)
	)
	if len(unvetted) != 0 {
		unvettedInv[backend.StatusUnreviewed] = unvetted
	}
	if len(censored) != 0 {
		unvettedInv[backend.StatusCensored] = censored
	}
	if len(archived) != 0 {
		unvettedInv[backend.StatusArchived] = archived
	}

	// Get vetted inventory
	v, err := t.invGet(t.invPathVetted())
	if err != nil {
		return nil, err
	}

	// Prepare vetted inventory reply
	var (
		vetted    = tokensParse(v.Entries, backend.StatusPublic, pageSize, 1)
		vcensored = tokensParse(v.Entries, backend.StatusCensored, pageSize, 1)
		varchived = tokensParse(v.Entries, backend.StatusArchived, pageSize, 1)

		vettedInv = make(map[backend.StatusT][]string, 16)
	)
	if len(vetted) != 0 {
		vettedInv[backend.StatusPublic] = vetted
	}
	if len(vcensored) != 0 {
		vettedInv[backend.StatusCensored] = vcensored
	}
	if len(varchived) != 0 {
		vettedInv[backend.StatusArchived] = varchived
	}

	return &invByStatus{
		Unvetted: unvettedInv,
		Vetted:   vettedInv,
	}, nil
}

func (t *tstoreBackend) invByStatus(state backend.StateT, s backend.StatusT, pageSize, page uint32) (*invByStatus, error) {
	// If no status is provided a page of tokens for each status should
	// be returned.
	if s == backend.StatusInvalid {
		return t.invByStatusAll(pageSize)
	}

	// Get inventory file path
	var fp string
	switch state {
	case backend.StateUnvetted:
		fp = t.invPathUnvetted()
	case backend.StateVetted:
		fp = t.invPathVetted()
	default:
		return nil, fmt.Errorf("unknown state '%v'", state)
	}

	// Get inventory
	inv, err := t.invGet(fp)
	if err != nil {
		return nil, err
	}

	// Get the page of tokens
	tokens := tokensParse(inv.Entries, s, pageSize, page)

	// Prepare reply
	var ibs invByStatus
	switch state {
	case backend.StateUnvetted:
		ibs = invByStatus{
			Unvetted: map[backend.StatusT][]string{
				s: tokens,
			},
			Vetted: map[backend.StatusT][]string{},
		}
	case backend.StateVetted:
		ibs = invByStatus{
			Unvetted: map[backend.StatusT][]string{},
			Vetted: map[backend.StatusT][]string{
				s: tokens,
			},
		}
	}

	return &ibs, nil
}

// entryDel removes the entry for the token and returns the updated slice.
func entryDel(entries []entry, token []byte) ([]entry, error) {
	// Find token in entries
	var i int
	var found bool
	htoken := hex.EncodeToString(token)
	for k, v := range entries {
		if v.Token == htoken {
			i = k
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("token not found %x", token)
	}

	// Del token from entries (linear time)
	copy(entries[i:], entries[i+1:])   // Shift entries[i+1:] left one index
	entries[len(entries)-1] = entry{}  // Del last element (write zero value)
	entries = entries[:len(entries)-1] // Truncate slice

	return entries, nil
}

// tokensParse parses a page of tokens from the provided entries.
func tokensParse(entries []entry, s backend.StatusT, countPerPage, page uint32) []string {
	tokens := make([]string, 0, countPerPage)
	if countPerPage == 0 || page == 0 {
		return tokens
	}

	startAt := (page - 1) * countPerPage
	var foundCount uint32
	for _, v := range entries {
		if v.Status != s {
			// Status does not match
			continue
		}

		// Matching status found
		if foundCount >= startAt {
			tokens = append(tokens, v.Token)
			if len(tokens) == int(countPerPage) {
				// We have a full page. We're done.
				return tokens
			}
		}

		foundCount++
	}

	return tokens
}
