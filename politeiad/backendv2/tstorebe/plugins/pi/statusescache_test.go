// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pi

import (
	"container/list"
	"testing"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/plugins/pi"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
)

func TestGet(t *testing.T) {
	// Create a new cache
	statuses := proposalStatuses{
		data:    make(map[string]*statusEntry, statusesCacheLimit),
		entries: list.New(),
	}

	// Setup a cache entry
	token := "key"
	entry := statusEntry{
		propStatus: pi.PropStatusCompleted,
	}

	// Ensure nil is returned when no cache entry associated with
	// the token exists in cache.
	ce := statuses.get(token)
	if ce != nil {
		t.Errorf("unexpected cache entry; want nil, got '%v'", ce)
	}

	// Store entry in cache.
	statuses.set(token, entry)

	// Get entry from cache and verify value
	ce = statuses.get(token)
	if entry.propStatus != ce.propStatus {
		t.Errorf("want proposal status %v, got '%v'", entry.propStatus,
			ce.propStatus)
	}
}

func TestSet(t *testing.T) {
	// Temporarily set global cache capacity limit to two in order to test
	// adding a new entry to a full cache.
	defaultCacheLimit := statusesCacheLimit
	statusesCacheLimit = 2
	defer func() {
		statusesCacheLimit = defaultCacheLimit
	}()

	// Create cache
	statuses := proposalStatuses{
		data:    make(map[string]*statusEntry, statusesCacheLimit),
		entries: list.New(),
	}

	// Setup test tokens and cache entries
	tokens := []string{"45154fb45664714a", "45154fb45664714b"}
	entries := []statusEntry{
		{
			propStatus:   pi.PropStatusActive,
			recordState:  backend.StateUnvetted,
			recordStatus: backend.StatusPublic,
			voteStatus:   ticketvote.VoteStatusRejected,
		},
		{
			propStatus:   pi.PropStatusActive,
			recordState:  backend.StateUnvetted,
			recordStatus: backend.StatusPublic,
			voteStatus:   ticketvote.VoteStatusApproved,
		},
	}

	// Store entries in cache
	for i, token := range tokens {
		statuses.set(token, entries[i])
	}

	// Store a third entry, it should replace the oldest entry as the cache
	// is a FIFO data structure.
	tokenThird := "45154fb45664714c"
	entryThird := statusEntry{
		propStatus:   pi.PropStatusClosed,
		recordState:  backend.StateUnvetted,
		recordStatus: backend.StatusPublic,
		voteStatus:   ticketvote.VoteStatusApproved,
	}
	statuses.set(tokenThird, entryThird)

	// Ensure that oldest entry was removed, and that the other two entries
	// exist is cache.
	var e *statusEntry
	if e = statuses.get(tokenThird); e == nil {
		t.Errorf("entry not found in cache, token: %v", tokenThird)
	}
	if e = statuses.get(tokens[1]); e == nil {
		t.Errorf("entry not found in cache, token: %v", tokens[1])
	}
	if e = statuses.get(tokens[0]); e != nil {
		t.Errorf("unexpected entry found in cache, token: %v", tokenThird)
	}

	// Ensure that the cache's tokens list is a FIFO data structure where
	// the oldest element is at the back of the list and the newest is the
	// at the front.
	listTokenLast := statuses.entries.Back().Value.(string)
	if listTokenLast != tokens[1] {
		t.Errorf("unexpected entry is at the back of the entries list; "+
			"expected %v, got %v", tokens[1], listTokenLast)
	}
	listTokenFirst := statuses.entries.Front().Value.(string)
	if listTokenFirst != tokenThird {
		t.Errorf("unexpected entry is at the front of the entries list; "+
			"expected %v, got %v", tokenThird, listTokenFirst)
	}

	// Overwrite existing cache entry.
	entryThird.propStatus = pi.PropStatusActive
	statuses.set(tokenThird, entryThird)

	// Ensure new entry was stored in cache successfully
	e = statuses.data[tokenThird]
	if e.propStatus != pi.PropStatusActive {
		t.Errorf("unexpected proposal status: want %v, got %v",
			pi.PropStatusActive, e.propStatus)
	}
}
