// Copyright (c) 2021-2022 The Decred developers
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

// statusesCacheLimit is the cache's default maximum capacity. Note that it's
// a var in order to allow setting different limit values in test files.
var statusesCacheLimit = 1000

// proposalStatuses is a lazy loaded, memory cache that caches proposal data
// required to determine the proposal status at runtime such as record
// metadata, vote metadata, the vote status and the proposal billing status
// changes. The cache is necessary to improve the performance of determining a
// status of a proposal at runtime by reducing the number of expensive backend
// calls that result in the tlog tree be retrieved, which gets very expensive
// when a tree contains tens of thousands of ticket vote leaves. This is
// helpful when the cached data is not expected to change, which means that
// once we store the data in cache we don't need to fetch it again.
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
	if e, ok := s.data[token]; ok {
		if e.propStatus == entry.propStatus {
			// Entry exists, but has not changed. No
			// need to overwrite the existing entry.
			return
		}
		s.data[token] = &entry
		log.Debugf("proposalStatuses: updated entry %v from %v to %v",
			token, e.propStatus, entry.propStatus)
		return
	}

	// If entry does not exist and cache is full, then remove oldest entry
	if s.entries.Len() == statusesCacheLimit {
		// Remove front - oldest entry from entries list.
		t := s.entries.Remove(s.entries.Back()).(string)
		// Remove oldest status from map.
		delete(s.data, t)
		log.Debugf("proposalStatuses: removed entry %v", t)
	}

	// Store new status.
	s.entries.PushFront(token)
	s.data[token] = &entry
	log.Debugf("proposalStatuses: added entry %v with status %v",
		token, entry.propStatus)
}
