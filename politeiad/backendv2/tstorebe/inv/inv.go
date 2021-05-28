// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package inv implements a concurrency safe API for managing an inventory of
// tokens.
package inv

import (
	"encoding/json"
	"fmt"

	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
)

// entry represents an entry in the inventory.
type entry struct {
	Token     string `json:"token"`     // Unique token
	Bits      uint64 `json:"bits"`      // Bitwise filtering bits
	Timestamp int64  `json:"timestamp"` // Caller provided Unix timestamp
}

// newEntry returns a new inventory entry.
func newEntry(token string, bits uint64, timestamp int64) entry {
	return entry{
		Token:     token,
		Bits:      bits,
		Timestamp: timestamp,
	}
}

const (
	// invVersion is the most recent version of the inv struct.
	invVersion uint32 = 1
)

// inv represents an inventory. This structure is saved to the key-value store.
type inv struct {
	Version uint32  `json:"version"` // Struct version
	Entries []entry `json:"entries"`
}

// save saves the inventory to the key-value store using the provided
// transaction.
func (i *inv) save(tx store.Tx, key string, encrypt bool) error {
	b, err := json.Marshal(i)
	if err != nil {
		return err
	}
	return tx.Put(map[string][]byte{key: b}, encrypt)
}

// invGet retrieves the inventory from the key-value store using the provided
// store getter. A new inventory object is returned if one does not exist yet.
func invGet(sg store.Getter, key string) (*inv, error) {
	blobs, err := sg.Get([]string{key})
	if err != nil {
		return nil, err
	}
	b, ok := blobs[key]
	if !ok {
		// Inventory does't exist. Return a new one.
		return &inv{
			Version: invVersion,
			Entries: make([]entry, 0, 1024),
		}, nil
	}

	var i inv
	err = json.Unmarshal(b, &i)
	if err != nil {
		return nil, err
	}

	return &i, nil
}

// Inv provides an API for interacting with a specific inv object. The key
// identities the key-value store key for the inv object.
type Inv struct {
	key     string // Key-value store key
	encrypt bool   // Save encrypted
}

// New returns a new Inv.
func New(key string, encrypt bool) *Inv {
	return &Inv{
		key:     key,
		encrypt: encrypt,
	}
}

// Add adds a new entry to the inventory. If an inv object does not exist yet
// in the key-value store a new one will be created.
func (i *Inv) Add(tx store.Tx, token string, bits uint64, timestamp int64) error {
	// Get existing inventory
	inv, err := invGet(tx, i.key)
	if err != nil {
		return err
	}

	// Prepend a new entry
	e := newEntry(token, bits, timestamp)
	inv.Entries = append([]entry{e}, inv.Entries...)

	// Save the updated inventory
	return inv.save(tx, i.key, i.encrypt)
}

// Update updates an inventory entry.
func (i *Inv) Update(tx store.Tx, token string, bits uint64, timestamp int64) error {
	// Get existing inventory
	inv, err := invGet(tx, i.key)
	if err != nil {
		return err
	}

	// Find the specified entry
	for i, v := range inv.Entries {
		if v.Token != token {
			// The the entry we're looking for
			continue
		}

		// We have a match. Update it.
		inv.Entries[i] = newEntry(token, bits, timestamp)
		break
	}

	// Save the updated inventory
	return inv.save(tx, i.key, i.encrypt)
}

// Del deletes an entry from the inventory.
func (i *Inv) Del(tx store.Tx, token string) error {
	// Get existing inventory
	inv, err := invGet(tx, i.key)
	if err != nil {
		return err
	}

	// Del the specified entry
	inv.Entries, err = delEntry(inv.Entries, token)
	if err != nil {
		return err
	}

	// Save the updated inventory
	return inv.save(tx, i.key, i.encrypt)
}

// Get returns a page of tokens that match the provided filtering criteria.
func (i *Inv) Get(sg store.Getter, bits uint64, pageSize, pageNum uint32) ([]string, error) {
	// Get existing inventory
	inv, err := invGet(sg, i.key)
	if err != nil {
		return nil, err
	}

	// Filter out the requested page of entries
	filtered := filterEntries(inv.Entries, bits, pageSize, pageNum)

	// Compile tokens
	tokens := make([]string, 0, len(filtered))
	for _, v := range filtered {
		tokens = append(tokens, v.Token)
	}

	return tokens, nil
}

// GetMulti returns a page of tokens for each of the provided bits. The bits
// are used as filtering criteria. The returned map is a map[bits][]token.
func (i *Inv) GetMulti(sg store.Getter, bits []uint64, pageSize, page uint32) (map[uint64][]string, error) {
	// Get existing inventory
	inv, err := invGet(sg, i.key)
	if err != nil {
		return nil, err
	}

	pages := make(map[uint64][]string, len(bits))
	for _, v := range bits {
		// Filter out the requested page of entries
		filtered := filterEntries(inv.Entries, v, pageSize, page)

		// Compile tokens
		tokens := make([]string, 0, len(filtered))
		for _, v := range filtered {
			tokens = append(tokens, v.Token)
		}
		pages[v] = tokens
	}

	return pages, nil
}

// delEntry removes the entry for a token and returns the updated slice.
func delEntry(entries []entry, token string) ([]entry, error) {
	// Find token in entries
	var i int
	var found bool
	for k, v := range entries {
		if v.Token == token {
			i = k
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("token not found %v", token)
	}

	// Del token from entries (linear time)
	copy(entries[i:], entries[i+1:])   // Shift entries[i+1:] left one index
	entries[len(entries)-1] = entry{}  // Del last element (write zero value)
	entries = entries[:len(entries)-1] // Truncate slice

	return entries, nil
}

// filterEntriesi returns a page of entries that meet the provided filtering
// criteria.
func filterEntries(entries []entry, bits uint64, pageSize, page uint32) []entry {
	filtered := make([]entry, 0, pageSize)
	if pageSize == 0 || page == 0 {
		return filtered
	}

	var (
		// matchCount is the total number of matches that have
		// been found.
		matchCount uint32

		// pageStart is the match count that the requested page
		// starts at.
		pageStart = (page - 1) * pageSize
	)
	for _, v := range entries {
		if (v.Bits & bits) != bits {
			// Entry bits do not contains all of the provided
			// filtering bits. This is not a match.
			continue
		}

		// Match found
		if matchCount >= pageStart {
			filtered = append(filtered, v)
			if len(filtered) == int(pageSize) {
				// We have a full page. We're done.
				return filtered
			}
		}

		matchCount++
	}

	return filtered
}
