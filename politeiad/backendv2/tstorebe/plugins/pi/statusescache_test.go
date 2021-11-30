// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pi

import (
	"container/list"
	"testing"

	"github.com/decred/politeia/politeiad/plugins/pi"
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
	// Create a new cache with limit of two entries
	//statuses := proposalStatuses{
	//data:    make(map[string]*statusEntry, 2),
	//entries: list.New(),
	//}

	// Setup cache entries
}
