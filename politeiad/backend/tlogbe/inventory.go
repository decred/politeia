// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlogbe

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/decred/politeia/politeiad/backend"
)

const (
	filenameInvUnvetted = "inv-unvetted.json"
	filenameInvVetted   = "inv-vetted.json"
)

type entry struct {
	Token  string            `json:"token"`
	Status backend.MDStatusT `json:"status"`
}

type inventory struct {
	Entries []entry `json:"entries"`
}

func (t *tlogBackend) invPathUnvetted() string {
	return filepath.Join(t.dataDir, filenameInvUnvetted)
}

func (t *tlogBackend) invPathVetted() string {
	return filepath.Join(t.dataDir, filenameInvVetted)
}

// invGetLocked retrieves the inventory from disk. A new inventory is returned
// if one does not exist yet.
//
// This function must be called WITH the read lock held.
func (t *tlogBackend) invGetLocked(filePath string) (*inventory, error) {
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
func (t *tlogBackend) invGet(filePath string) (*inventory, error) {
	t.RLock()
	defer t.RUnlock()

	return t.invGetLocked(filePath)
}

// invSaveLocked writes the inventory to disk.
//
// This function must be called WITH the read/write lock held.
func (t *tlogBackend) invSaveLocked(filePath string, inv inventory) error {
	b, err := json.Marshal(inv)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filePath, b, 0664)
}

func (t *tlogBackend) invAdd(state string, token []byte, s backend.MDStatusT) error {
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
		e := fmt.Sprintf("unknown state '%v'", state)
		panic(e)
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

	log.Debugf("Inv %v add %x %v", state, token, backend.MDStatus[s])

	return nil
}

func (t *tlogBackend) invUpdate(state string, token []byte, s backend.MDStatusT) error {
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
		e := fmt.Sprintf("unknown state '%v'", state)
		panic(e)
	}

	// Get inventory
	inv, err := t.invGetLocked(fp)
	if err != nil {
		return err
	}

	// Del entry
	entries, err := entryDel(inv.Entries, token)
	if err != nil {
		// This should not happen. Panic if it does.
		e := fmt.Sprintf("%v entry del: %v", state, err)
		panic(e)
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

	log.Debugf("Inv %v update %x to %v", state, token, backend.MDStatus[s])

	return nil
}

// invMoveToVetted moves a token from the unvetted inventory to the vetted
// inventory.
func (t *tlogBackend) invMoveToVetted(token []byte, s backend.MDStatusT) error {
	t.Lock()
	defer t.Unlock()

	// Get unvetted inventory
	upath := t.invPathUnvetted()
	u, err := t.invGetLocked(upath)
	if err != nil {
		return err
	}

	// Del entry
	u.Entries, err = entryDel(u.Entries, token)
	if err != nil {
		// This should not happen. Panic if it does.
		e := fmt.Sprintf("unvetted entry del: %v", err)
		panic(e)
	}

	// Save unvetted inventory
	err = t.invSaveLocked(upath, *u)
	if err != nil {
		return err
	}

	// Get vetted inventory
	vpath := t.invPathVetted()
	v, err := t.invGetLocked(vpath)
	if err != nil {
		return err
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
		return err
	}

	log.Debugf("Inv move %x from unvetted to vetted status %v",
		token, backend.MDStatus[s])

	return nil
}

// invByStatus contains the inventory categorized by record state and record
// status. Each list contains a page of tokens that are sorted by the timestamp
// of the status change from newest to oldest.
type invByStatus struct {
	Unvetted map[backend.MDStatusT][]string
	Vetted   map[backend.MDStatusT][]string
}

func (t *tlogBackend) invByStatusAll(pageSize uint32) (*invByStatus, error) {
	// Get unvetted inventory
	u, err := t.invGet(t.invPathUnvetted())
	if err != nil {
		return nil, err
	}

	// Prepare unvetted inventory reply
	var (
		unvetted = tokensParse(u.Entries, backend.MDStatusUnvetted, pageSize, 1)
		censored = tokensParse(u.Entries, backend.MDStatusCensored, pageSize, 1)
		archived = tokensParse(u.Entries, backend.MDStatusArchived, pageSize, 1)

		unvettedInv = make(map[backend.MDStatusT][]string, 16)
	)
	if len(unvetted) != 0 {
		unvettedInv[backend.MDStatusUnvetted] = unvetted
	}
	if len(censored) != 0 {
		unvettedInv[backend.MDStatusCensored] = censored
	}
	if len(archived) != 0 {
		unvettedInv[backend.MDStatusArchived] = archived
	}

	// Get vetted inventory
	v, err := t.invGet(t.invPathVetted())
	if err != nil {
		return nil, err
	}

	// Prepare vetted inventory reply
	var (
		vetted    = tokensParse(v.Entries, backend.MDStatusVetted, pageSize, 1)
		vcensored = tokensParse(v.Entries, backend.MDStatusCensored, pageSize, 1)
		varchived = tokensParse(v.Entries, backend.MDStatusArchived, pageSize, 1)

		vettedInv = make(map[backend.MDStatusT][]string, 16)
	)
	if len(vetted) != 0 {
		vettedInv[backend.MDStatusVetted] = vetted
	}
	if len(vcensored) != 0 {
		vettedInv[backend.MDStatusCensored] = vcensored
	}
	if len(varchived) != 0 {
		vettedInv[backend.MDStatusArchived] = varchived
	}

	return &invByStatus{
		Unvetted: unvettedInv,
		Vetted:   vettedInv,
	}, nil
}

// inventoryAdd is a wrapper around the invAdd method that allows us to decide
// how disk read/write errors should be handled. For now we simply panic. The
// best thing to do would be to kick off a non-block fsck job that checks the
// inventory cache and corrects any mistakes that it finds.
func (t *tlogBackend) inventoryAdd(state string, token []byte, s backend.MDStatusT) {
	err := t.invAdd(state, token, s)
	if err != nil {
		e := fmt.Sprintf("invAdd %v %x %v: %v", state, token, s, err)
		panic(e)
	}
}

// inventoryUpdate is a wrapper around the invUpdate method that allows us to
// decide how disk read/write errors should be handled. For now we simply
// panic. The best thing to do would be to kick off a non-block fsck job that
// checks the inventory cache and corrects any mistakes that it finds.
func (t *tlogBackend) inventoryUpdate(state string, token []byte, s backend.MDStatusT) {
	err := t.invUpdate(state, token, s)
	if err != nil {
		e := fmt.Sprintf("invUpdate %v %x %v: %v", state, token, s, err)
		panic(e)
	}
}

// inventoryMoveToVetted is a wrapper around the invMoveToVetted method that
// allows us to decide how disk read/write errors should be handled. For now we
// simply panic. The best thing to do would be to kick off a non-block fsck job
// that checks the inventory cache and corrects any mistakes that it finds.
func (t *tlogBackend) inventoryMoveToVetted(token []byte, s backend.MDStatusT) {
	err := t.invMoveToVetted(token, s)
	if err != nil {
		e := fmt.Sprintf("invMoveToVetted %x %v: %v", token, s, err)
		panic(e)
	}
}

func (t *tlogBackend) inventory(state string, s backend.MDStatusT, pageSize, page uint32) (*invByStatus, error) {
	// If no status is provided a page of tokens for each status should
	// be returned.
	if s == backend.MDStatusInvalid {
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
		e := fmt.Sprintf("unknown state '%v'", state)
		panic(e)
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
			Unvetted: map[backend.MDStatusT][]string{
				s: tokens,
			},
			Vetted: map[backend.MDStatusT][]string{},
		}
	case backend.StateVetted:
		ibs = invByStatus{
			Unvetted: map[backend.MDStatusT][]string{},
			Vetted: map[backend.MDStatusT][]string{
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
func tokensParse(entries []entry, s backend.MDStatusT, countPerPage, page uint32) []string {
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
				// We got a full page. We're done.
				return tokens
			}
		}

		foundCount++
	}

	return tokens
}
