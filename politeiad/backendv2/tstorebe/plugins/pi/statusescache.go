// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pi

import (
	"container/list"
	"sync"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/plugins/pi"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
)

// statusEntry represents a cached proposal status and proposal data required
// to determine the proposal status.
type statusEntry struct {
	propStatus pi.PropStatusT

	// The following fields cache data in order to reduce the number of backend
	// calls required to determine the proposal status.
	recordState  backend.StateT
	recordStatus backend.StatusT
	voteStatus   ticketvote.VoteStatusT
	voteMetadata *ticketvote.VoteMetadata
}

// statusesCacheLimit limits the number of entries in the proposal statuses
// cache.
const statusesCacheLimit = 1000

// proposalStatuses is used to cache final proposal statuses which are not
// expected to change in the future; or proposal statuses which only need
// to fetch the latest billing status changes to determine the proposal status
// on runtime.
//
// Number of entries stored in cache is limited by statusesCacheLimit. If the
// cache is full and a new entry is being added, the oldest entry is removed
// from the `data` map and the `entries` list.
//
// Currently the limit is set to 1000 as we don't really need more than that
// as the goal of the cache is to speed up fetching the statuses of the
// most recent proposals. Each cache entry size is ~25bytes so the cache total
// size when full is expected to be ~25KB.
//
// The cache entries are lazy loaded.
type proposalStatuses struct {
	sync.Mutex
	data    map[string]*statusEntry // [token]statusEntry
	entries *list.List              // list of cache records tokens
}

// get retrieves the data associated with the given token from the
// memory cache.  If data doesn't exist in cache it returns nil.
func (s *proposalStatuses) get(token string) *statusEntry {
	s.Lock()
	defer s.Unlock()

	return s.data[token]
}

// set stores the proposal status associated with the given token in cache.
// If the cache is full and a new entry is being added, the oldest entry is
// removed from the cache.
func (s *proposalStatuses) set(token string, entry statusEntry) {
	s.Lock()
	defer s.Unlock()

	// If an entry associated with the proposal already exists in cache
	// overwrite the proposal status.
	if s.data[token] != nil {
		s.data[token] = &entry
		return
	}

	// If entry does not exist and cache is full, then remove oldest entry
	if s.entries.Len() == statusesCacheLimit {
		// Remove front - oldest entry from entries list.
		t := s.entries.Remove(s.entries.Front()).(string)
		// Remove oldest status from map.
		delete(s.data, t)
	}

	// Store new status.
	s.entries.PushBack(token)
	s.data[token] = &entry
}
