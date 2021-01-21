// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package events

import (
	"sync"
)

// Manager manages event listeners for different event types.
type Manager struct {
	sync.Mutex
	listeners map[string][]chan interface{}
}

// Register registers an event listener (channel) to listen for the provided
// event type.
func (e *Manager) Register(event string, listener chan interface{}) {
	e.Lock()
	defer e.Unlock()

	l, ok := e.listeners[event]
	if !ok {
		l = make([]chan interface{}, 0)
	}

	l = append(l, listener)
	e.listeners[event] = l
}

// Emit emits an event by passing it to all channels that have been registered
// to listen for the event.
func (e *Manager) Emit(event string, data interface{}) {
	e.Lock()
	defer e.Unlock()

	listeners, ok := e.listeners[event]
	if !ok {
		return
	}

	for _, ch := range listeners {
		ch <- data
	}
}

// NewManager returns a new Manager context.
func NewManager() *Manager {
	return &Manager{
		listeners: make(map[string][]chan interface{}),
	}
}
