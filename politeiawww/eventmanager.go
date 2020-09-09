// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"sync"

	v1 "github.com/decred/politeia/politeiawww/api/pi/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/google/uuid"
)

type eventT int

const (
	// Event types
	eventTypeInvalid eventT = iota

	// Pi events
	eventProposalSubmitted
	eventProposalStatusChange
	eventProposalEdited
	eventProposalVoteAuthorized
	eventProposalVoteStarted

	// CMS events
	eventInvoiceComment
	eventInvoiceStatusUpdate
	eventDCCNew
	eventDCCSupportOppose
)

// eventManager manages event listeners for different event types.
type eventManager struct {
	sync.Mutex
	listeners map[eventT][]chan interface{}
}

// register registers an event listener (channel) to listen for the provided
// event type.
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

// emit emits an event by passing it to all channels that have been registered
// to listen for the event.
func (e *eventManager) emit(event eventT, data interface{}) {
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

	// Setup proposal status change event
	ch = make(chan interface{})
	p.eventManager.register(eventProposalStatusChange, ch)
	go p.handleEventProposalStatusChange(ch)

	// Setup proposal edit event
	ch = make(chan interface{})
	p.eventManager.register(eventProposalEdited, ch)
	go p.handleEventProposalEdited(ch)

	// Setup proposal vote authorized event
	ch = make(chan interface{})
	p.eventManager.register(eventProposalVoteAuthorized, ch)
	go p.handleEventProposalVoteAuthorized(ch)

	// Setup proposal vote started event
	ch = make(chan interface{})
	p.eventManager.register(eventProposalVoteStarted, ch)
	go p.handleEventProposalVoteStarted(ch)

}

func (p *politeiawww) setupEventListenersCms() {
	// Setup invoice comment event
	ch := make(chan interface{})
	p.eventManager.register(eventInvoiceComment, ch)
	go p.handleEventInvoiceComment(ch)

	// Setup invoice status update event
	ch = make(chan interface{})
	p.eventManager.register(eventInvoiceStatusUpdate, ch)
	go p.handleEventInvoiceStatusUpdate(ch)

	// Setup DCC new update event
	ch = make(chan interface{})
	p.eventManager.register(eventDCCNew, ch)
	go p.handleEventDCCNew(ch)

	// Setup DCC support/oppose event
	ch = make(chan interface{})
	p.eventManager.register(eventDCCSupportOppose, ch)
	go p.handleEventDCCSupportOppose(ch)
}

// notificationIsSet returns whether the provided user has the provided
// notification bit set.
func notificationIsSet(emailNotifications uint64, n www.EmailNotificationT) bool {
	if emailNotifications&uint64(n) == 0 {
		// Notification bit not set
		return false
	}
	// Notification bit is set
	return true
}

// userNotificationEnabled wraps all user checks to see if he is in correct
// state to receive notifications
func userNotificationEnabled(u user.User, n www.EmailNotificationT) bool {
	// Never send notification to deactivated users
	if u.Deactivated {
		return false
	}
	// Check if notification bit is set
	if !notificationIsSet(u.EmailNotifications, n) {
		return false
	}
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
			// Check if user is able to receive notification
			if userNotificationEnabled(*u,
				www.NotificationEmailAdminProposalNew) {
				emails = append(emails, u.Email)
			}

			// Only send proposal submitted notifications to admins
			if !u.Admin {
				return
			}
		})
		if err != nil {
			log.Errorf("handleEventProposalSubmitted: AllUsers: %v", err)
			return
		}

		// Send email notification
		err = p.emailProposalSubmitted(d.token, d.name, d.username, emails)
		if err != nil {
			log.Errorf("emailProposalSubmitted: %v", err)
		}

		log.Debugf("Sent proposal submitted notification %v", d.token)
	}
}

type dataProposalStatusChange struct {
	name                string         // Proposal name
	token               string         // Proposal censorship token
	adminID             uuid.UUID      // Admin uuid
	id                  uuid.UUID      // Author uuid
	email               string         // Author user email
	emailNotifications  uint64         // Author notification settings
	username            string         // Author username
	status              v1.PropStatusT // Proposal status
	statusChangeMessage string         // Status change message
}

func (p *politeiawww) handleEventProposalStatusChange(ch chan interface{}) {
	for msg := range ch {
		d, ok := msg.(dataProposalStatusChange)
		if !ok {
			log.Errorf("handleProposalStatusChange invalid msg: %v", msg)
			continue
		}

		// Check if proposal is in correct status for notification
		if d.status != v1.PropStatusPublic &&
			d.status != v1.PropStatusCensored {
			continue
		}

		emails := make([]string, 0, 256)
		err := p.db.AllUsers(func(u *user.User) {
			// Check circunstances where we don't notify
			if u.ID == d.adminID || u.ID == d.id ||
				!userNotificationEnabled(*u,
					www.NotificationEmailRegularProposalVetted) {
				return
			}

			emails = append(emails, u.Email)
		})

		err = p.emailProposalStatusChange(d, emails)
		if err != nil {
			log.Errorf("emailProposalStatusChange: %v", err)
		}

		log.Debugf("Sent proposal status change notifications %v", d.token)
	}
}

type dataProposalEdited struct {
	id       uuid.UUID // Author id
	username string    // Author username
	token    string    // Proposal censorship token
	name     string    // Proposal name
	version  string    // Proposal version
}

func (p *politeiawww) handleEventProposalEdited(ch chan interface{}) {
	for msg := range ch {
		d, ok := msg.(dataProposalEdited)
		if !ok {
			log.Errorf("handleEventProposalEdited invalid msg: %v", msg)
			continue
		}

		emails := make([]string, 0, 256)
		err := p.db.AllUsers(func(u *user.User) {
			// Check circunstances where we don't notify
			if u.NewUserPaywallTx == "" || u.ID == d.id ||
				!userNotificationEnabled(*u,
					www.NotificationEmailRegularProposalEdited) {
				return
			}

			emails = append(emails, u.Email)
		})

		err = p.emailProposalEdited(d.name, d.username, d.token, d.version,
			emails)
		if err != nil {
			log.Errorf("emailProposalEdited: %v", err)
		}

		log.Debugf("Sent proposal edited notifications %v", d.token)
	}
}

type dataProposalVoteAuthorized struct {
	token    string // Proposal censhorship token
	name     string // Proposal name
	username string // Author username
	email    string // Author email
}

func (p *politeiawww) handleEventProposalVoteAuthorized(ch chan interface{}) {
	for msg := range ch {
		d, ok := msg.(dataProposalVoteAuthorized)
		if !ok {
			log.Errorf("handleEventProposalVoteAuthorized invalid msg: %v", msg)
			continue
		}

		emails := make([]string, 0, 256)
		err := p.db.AllUsers(func(u *user.User) {
			// Check circunstances where we don't notify
			if !u.Admin || !userNotificationEnabled(*u,
				www.NotificationEmailAdminProposalVoteAuthorized) {
				return
			}

			emails = append(emails, u.Email)
		})

		err = p.emailProposalVoteAuthorized(d.token, d.name, d.username,
			d.email, emails)
		if err != nil {
			log.Errorf("emailProposalVoteAuthorized: %v", err)
		}

		log.Debugf("Sent proposal vote authorized notifications %v", d.token)
	}
}

type dataProposalVoteStarted struct {
	token              string    // Proposal censhorship token
	name               string    // Proposal name
	adminID            uuid.UUID // Admin uuid
	id                 uuid.UUID // Author uuid
	username           string    // Author username
	email              string    // Author email
	emailNotifications uint64    // Author notifications bits
}

func (p *politeiawww) handleEventProposalVoteStarted(ch chan interface{}) {
	for msg := range ch {
		d, ok := msg.(dataProposalVoteStarted)
		if !ok {
			log.Errorf("handleEventProposalVoteStarted invalid msg: %v", msg)
			continue
		}

		emails := make([]string, 0, 256)
		err := p.db.AllUsers(func(u *user.User) {
			// Check circunstances where we don't notify
			if u.NewUserPaywallTx == "" || u.ID == d.adminID || u.ID == d.id ||
				!userNotificationEnabled(*u,
					www.NotificationEmailRegularProposalVoteStarted) {
				return
			}

			emails = append(emails, u.Email)
		})

		err = p.emailProposalVoteStarted(d.token, d.name, d.username,
			d.email, d.emailNotifications, emails)
		if err != nil {
			log.Errorf("emailProposalVoteAuthorized: %v", err)
		}

		log.Debugf("Sent proposal authorized vote notifications %v", d.token)
	}
}

type dataInvoiceComment struct {
	token string // Comment token
	email string // User email
}

func (p *politeiawww) handleEventInvoiceComment(ch chan interface{}) {
	for msg := range ch {
		d, ok := msg.(dataInvoiceComment)
		if !ok {
			log.Errorf("handleEventInvoiceComment invalid msg: %v", msg)
			continue
		}

		err := p.emailInvoiceComment(d.email)
		if err != nil {
			log.Errorf("emailInvoiceComment %v: %v", err)
		}

		log.Debugf("Sent invoice comment notification %v", d.token)
	}
}

type dataInvoiceStatusUpdate struct {
	token string // Comment token
	email string // User email
}

func (p *politeiawww) handleEventInvoiceStatusUpdate(ch chan interface{}) {
	for msg := range ch {
		d, ok := msg.(dataInvoiceComment)
		if !ok {
			log.Errorf("handleEventInvoiceStatusUpdate invalid msg: %v", msg)
			continue
		}

		err := p.emailInvoiceStatusUpdate(d.token, d.email)
		if err != nil {
			log.Errorf("emailInvoiceComment %v: %v", err)
		}

		log.Debugf("Sent invoice comment notification %v", d.token)
	}
}

type dataDCCNew struct {
	token string // DCC token
	email string // User email
}

func (p *politeiawww) handleEventDCCNew(ch chan interface{}) {
	for msg := range ch {
		d, ok := msg.(dataDCCNew)
		if !ok {
			log.Errorf("handleEventDCCNew invalid msg: %v", msg)
			continue
		}

		emails := make([]string, 0, 256)
		err := p.db.AllUsers(func(u *user.User) {
			// Check circunstances where we don't notify
			if !u.Admin || u.Deactivated {
				return
			}

			emails = append(emails, u.Email)
		})

		err = p.emailDCCNew(d.token, emails)
		if err != nil {
			log.Errorf("emailDCCNew %v: %v", err)
		}

		log.Debugf("Sent DCC new notification %v", d.token)
	}
}

type dataDCCSupportOppose struct {
	token string // DCC token
	email string // User email
}

func (p *politeiawww) handleEventDCCSupportOppose(ch chan interface{}) {
	for msg := range ch {
		d, ok := msg.(dataDCCSupportOppose)
		if !ok {
			log.Errorf("handleEventDCCSupportOppose invalid msg: %v", msg)
			continue
		}

		emails := make([]string, 0, 256)
		err := p.db.AllUsers(func(u *user.User) {
			// Check circunstances where we don't notify
			if !u.Admin || u.Deactivated {
				return
			}

			emails = append(emails, u.Email)
		})

		err = p.emailDCCSupportOppose(d.token, emails)
		if err != nil {
			log.Errorf("emailDCCSupportOppose %v: %v", err)
		}

		log.Debugf("Sent DCC support/oppose notification %v", d.token)
	}
}
