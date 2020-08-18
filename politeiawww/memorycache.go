// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.
// Copyright (c) 2017 Guilherme Oenning
// https://github.com/goenning/go-cache-demo/blob/master/LICENSE

package main

import (
	"sync"
	"time"
)

// item is a cached reference.
type item struct {
	Content    []byte
	Expiration int64 // Unix timestamp
}

// storage mechanism for caching strings in memory.
type storage struct {
	sync.RWMutex
	items map[string]item
}

// expired returns true if the item has expired.
func (item item) expired() bool {
	if item.Expiration == 0 {
		return false
	}
	return time.Now().UnixNano() > item.Expiration
}

// newStorage creates a new in-memory storage.
func (p *politeiawww) newStorage() *storage {
	return &storage{
		items: make(map[string]item),
	}
}

// get a cached content by key.
func (s *storage) get(key string) []byte {
	s.RLock()
	defer s.RUnlock()

	item := s.items[key]
	if item.expired() {
		delete(s.items, key)
		return nil
	}
	return item.Content
}

// set a cached content by key.
func (s *storage) set(key string, content []byte, duration string) {
	s.Lock()
	defer s.Unlock()

	d, err := time.ParseDuration(duration)
	if err != nil {
		log.Errorf("Memorycache set: %v", err)
		return
	}

	s.items[key] = item{
		Content:    content,
		Expiration: time.Now().Add(d).UnixNano(),
	}
}
