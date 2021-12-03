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
	recordState          backend.StateT
	recordStatus         backend.StatusT
	voteStatus           ticketvote.VoteStatusT
	voteMetadata         *ticketvote.VoteMetadata
	billingStatusesCount int // Number of billing status changes
}

// statusesCacheLimit is the cache's default maximum capacity. Note that it's
// a var in order to allow setting different limit values in test files.
var statusesCacheLimit = 1000

// proposalStatuses is used to cache proposal data required to determine
// the proposal status at runtime such as record metadata, vote metadata, the
// vote status and the proposal billing status changes. The cache is necessary
// to improve the performance and to reduce the number of backend calls when
// determining a status of a proposal at runtime and can be helpful when the
// cached data is not expected to change, which means that once we store the
// data in cache we don't need to fetch it again. The cache entries are lazy
// loaded.
//
// Number of entries stored in cache is limited by statusesCacheLimit. If the
// cache is full and a new entry is being added, the oldest entry is removed
// from the `data` map and the `entries` list.
//
// Currently the limit is set to 1000 as we don't really need more than that
// as the goal of the cache is to speed up fetching the statuses of the
// most recent proposals. Each cache entry size is ~150bytes so the cache total
// size when full is expected to be ~150KB.
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

// set stores the given entry in cache, if a cache entry associated with the
// token already exists it overwrites the old entry. If the cache is full and
// a new entry is being added, the oldest entry is removed from the cache.
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
		t := s.entries.Remove(s.entries.Back()).(string)
		// Remove oldest status from map.
		delete(s.data, t)
	}

	// Store new status.
	s.entries.PushFront(token)
	s.data[token] = &entry
}
