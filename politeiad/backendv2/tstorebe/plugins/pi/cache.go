// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pi

import (
	"container/list"
	"sync"

	"github.com/decred/politeia/politeiad/plugins/pi"
)

// statusEntry includes the cached proposal statuses.
type statusEntry struct {
	status pi.PropStatusT
}

// statusesLimit limits the number of entries in the proposal statuses cache.
const statusesLimit = 1000

// proposalStatuses is used to cache final proposal statuses which are not
// expected to change in the future; or proposal statuses which only need
// to fetch the latest billing status changes to determine the proposal status
// on runtime.
//
// Number of entries stored in cache is limited. If the cache is full and a
// new entry is being added, the oldest entry is removed from the `data`
// map and the `entries` list.
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
func (s *proposalStatuses) set(token string, status pi.PropStatusT) {
	s.Lock()
	defer s.Unlock()

	// If an entry associated with the proposal already exists in cache
	// overwrite the proposal status.
	if s.data[token] != nil {
		s.data[token].status = status
		return
	}

	// If entry does not exist and cache is full, then remove oldest entry
	if s.entries.Len() == statusesLimit {
		// Remove front - oldest entry from entries list.
		t := s.entries.Remove(s.entries.Front()).(string)
		// Remove oldest status from map.
		delete(s.data, t)
	}

	// Store new status.
	s.entries.PushBack(token)
	s.data[token] = &statusEntry{
		status: status,
	}
}
