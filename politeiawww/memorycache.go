package main

import (
	"sync"
	"time"
)

// Item is a cached reference
type Item struct {
	Content    []byte
	Expiration int64
}

//Storage mechanism for caching strings in memory
type Storage struct {
	items map[string]Item
	mu    *sync.RWMutex
}

// Expired returns true if the item has expired.
func (item Item) Expired() bool {
	if item.Expiration == 0 {
		return false
	}
	return time.Now().UnixNano() > item.Expiration
}

//NewStorage creates a new in memory storage
func (p *politeiawww) NewStorage() *Storage {
	return &Storage{
		items: make(map[string]Item),
		mu:    &sync.RWMutex{},
	}
}

//Get a cached content by key
func (s Storage) Get(key string) []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()

	item := s.items[key]
	if item.Expired() {
		delete(s.items, key)
		return nil
	}
	return item.Content
}

//Set a cached content by key
func (s Storage) Set(key string, content []byte, duration string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	d, _ := time.ParseDuration(duration)

	s.items[key] = Item{
		Content:    content,
		Expiration: time.Now().Add(d).UnixNano(),
	}
}
