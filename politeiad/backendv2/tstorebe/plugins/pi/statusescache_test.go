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
		data:    make(map[string]*statusEntry, defaultCacheLimit),
		entries: list.New(),
		limit:   defaultCacheLimit,
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
	// Create a new cache with limit of two entries
	statuses := proposalStatuses{
		data:    make(map[string]*statusEntry, 2),
		entries: list.New(),
		limit:   2,
	}

	// Test tokens and cache entries
	tokens := [2]string{"45154fb45664714a", "45154fb45664714b"}
	entries := [2]statusEntry{
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

	// Store a third entry, it should replace the first entry as the cache
	// is a FIFO data structure.
	tokenThird := "45154fb45664714c"
	entryThird := statusEntry{
		propStatus:   pi.PropStatusClosed,
		recordState:  backend.StateUnvetted,
		recordStatus: backend.StatusPublic,
		voteStatus:   ticketvote.VoteStatusApproved,
	}
	statuses.set(tokenThird, entryThird)

	// Verify that second and third entries stored in cached and that first
	// entry was removed.
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
	// the oldest element is the back of the list and the newest is the
	// the front.
	listTokenLast := statuses.entries.Back().Value.(string)
	if listTokenLast != tokens[1] {
		t.Errorf("unexpected entry at the back of the entries list; "+
			"expected %v, got %v", tokens[1], listTokenLast)
	}
	listTokenFirst := statuses.entries.Front().Value.(string)
	if listTokenFirst != tokenThird {
		t.Errorf("unexpected entry is in the front of the entries list; "+
			"expected %v, got %v", tokenThird, listTokenFirst)
	}
}
