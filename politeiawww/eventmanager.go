// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"sync"

	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/user"
)

type eventT int

const (
	// Event types
	eventTypeInvalid eventT = iota

	// Pi events
	eventProposalSubmitted
)

// eventManager manages event listeners for different event types.
type eventManager struct {
	sync.Mutex
	listeners map[eventT][]chan interface{}
}

// register adds adds a listener for the given event type.
func (e *eventManager) register(event eventT, listener chan interface{}) {
	e.Lock()
	defer e.Unlock()

	l, ok := e.listeners[event]
	if !ok {
		l = make([]chan interface{}, 0)
	}

	l = append(l, listener)
	e.listeners[event] = l
}

// fire fires off an event by passing it to all channels that have been
// registered to listen for the event.
func (e *eventManager) fire(event eventT, data interface{}) {
	e.Lock()
	defer e.Unlock()

	listeners, ok := e.listeners[event]
	if !ok {
		log.Errorf("fire: unregistered event %v", event)
		return
	}

	for _, ch := range listeners {
		ch <- data
	}
}

// newEventManager returns a new eventManager context.
func newEventManager() *eventManager {
	return &eventManager{
		listeners: make(map[eventT][]chan interface{}),
	}
}

func (p *politeiawww) setupEventListenersPi() {
	// Setup process for each event:
	// 1. Create a channel for the event
	// 2. Register the channel with the event manager
	// 3. Launch an event handler to listen for new events

	// Setup proposal submitted event
	ch := make(chan interface{})
	p.eventManager.register(eventProposalSubmitted, ch)
	go p.handleEventProposalSubmitted(ch)
}

// notificationIsSet returns whether the provided user has the provided
// notification bit set.
func notificationIsSet(u user.User, n www.EmailNotificationT) bool {
	// Notifications should not be sent to deactivated users
	if u.Deactivated {
		return false
	}

	if u.EmailNotifications&uint64(n) == 0 {
		// Notification bit not set
		return false
	}

	// Notification bit is set
	return true
}

type dataProposalSubmitted struct {
	token    string // Proposal token
	name     string // Proposal name
	username string // Author username
}

func (p *politeiawww) handleEventProposalSubmitted(ch chan interface{}) {
	for msg := range ch {
		d, ok := msg.(dataProposalSubmitted)
		if !ok {
			log.Errorf("handleEventProposalSubmitted invalid msg: %v", msg)
			continue
		}

		// Compile email notification recipients
		emails := make([]string, 0, 256)
		err := p.db.AllUsers(func(u *user.User) {
			// Only send proposal submitted notifications to admins
			if !u.Admin {
				return
			}

			// Check if notification bit is set
			if notificationIsSet(*u, www.NotificationEmailAdminProposalNew) {
				emails = append(emails, u.Email)
			}
		})
		if err != nil {
			log.Errorf("handleEventProposalSubmitted: AllUsers: %v", err)
			continue
		}

		// Send email notification
		err = p.emailProposalSubmitted(d.token, d.name, d.username, emails)
		if err != nil {
			log.Errorf("emailProposalSubmitted %v: %v", err)
		}

		log.Debugf("Sent proposal submitted notification %v", d.token)
	}
}
