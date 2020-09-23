// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"strconv"
	"sync"

	pi "github.com/decred/politeia/politeiawww/api/pi/v1"
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
	eventProposalEdited
	eventProposalStatusChange
	eventProposalComment
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

	// Setup proposal edit event
	ch = make(chan interface{})
	p.eventManager.register(eventProposalEdited, ch)
	go p.handleEventProposalEdited(ch)

	// Setup proposal status change event
	ch = make(chan interface{})
	p.eventManager.register(eventProposalStatusChange, ch)
	go p.handleEventProposalStatusChange(ch)

	// Setup proposal comment event
	ch = make(chan interface{})
	p.eventManager.register(eventProposalComment, ch)
	go p.handleEventProposalComment(ch)

	// Setup proposal vote authorized event
	ch = make(chan interface{})
	p.eventManager.register(eventProposalVoteAuthorized, ch)
	go p.handleEventProposalVoteAuthorized(ch)

	// Setup proposal vote started event
	ch = make(chan interface{})
	p.eventManager.register(eventProposalVoteStarted, ch)
	go p.handleEventProposalVoteStarted(ch)
}

func (p *politeiawww) setupEventListenersCMS() {
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

// userNotificationEnabled returns whether the user should receive the provided
// notification.
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

		// Compile a list of users to send the notification to
		emails := make([]string, 0, 256)
		err := p.db.AllUsers(func(u *user.User) {
			switch {
			case !u.Admin:
				// Only admins get this notification
				return
			case !userNotificationEnabled(*u,
				www.NotificationEmailAdminProposalNew):
				// Admin doesn't have notification bit set
				return
			}

			// Add user to notification list
			emails = append(emails, u.Email)
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

type dataProposalEdited struct {
	userID   string // Author id
	username string // Author username
	token    string // Proposal censorship token
	name     string // Proposal name
	version  string // Proposal version
}

func (p *politeiawww) handleEventProposalEdited(ch chan interface{}) {
	for msg := range ch {
		d, ok := msg.(dataProposalEdited)
		if !ok {
			log.Errorf("handleEventProposalEdited invalid msg: %v", msg)
			continue
		}

		// Compile a list of users to send the notification to
		emails := make([]string, 0, 256)
		err := p.db.AllUsers(func(u *user.User) {
			// Check circumstances where we don't notify
			switch {
			case u.ID.String() == d.userID:
				// User is the author
				return
			case !userNotificationEnabled(*u,
				www.NotificationEmailRegularProposalEdited):
				// User doesn't have notification bit set
				return
			}

			// Add user to notification list
			emails = append(emails, u.Email)
		})

		err = p.emailProposalEdited(d.name, d.username,
			d.token, d.version, emails)
		if err != nil {
			log.Errorf("emailProposalEdited: %v", err)
			continue
		}

		log.Debugf("Sent proposal edited notifications %v", d.token)
	}
}

type dataProposalStatusChange struct {
	token   string         // Proposal censorship token
	status  pi.PropStatusT // Proposal status
	version string         // Proposal version
	reason  string         // Status change reason
	adminID string         // Admin uuid
}

func (p *politeiawww) handleEventProposalStatusChange(ch chan interface{}) {
	for msg := range ch {
		d, ok := msg.(dataProposalStatusChange)
		if !ok {
			log.Errorf("handleProposalStatusChange invalid msg: %v", msg)
			continue
		}

		// Check if proposal is in correct status for notification
		switch d.status {
		case pi.PropStatusPublic, pi.PropStatusCensored:
			// The status requires a notification be sent
		default:
			// The status does not require a notification be sent. Listen
			// for next event.
			continue
		}

		// Get the proposal author
		state := convertPropStateFromPropStatus(d.status)
		pr, err := p.proposalRecordLatest(state, d.token)
		if err != nil {
			log.Errorf("handleEventProposalStatusChange: proposalRecordLatest "+
				"%v %v: %v", state, d.token, err)
			continue
		}
		author, err := p.db.UserGetByPubKey(pr.PublicKey)
		if err != nil {
			log.Errorf("handleEventProposalStatusChange: UserGetByPubKey %v: %v",
				pr.PublicKey, err)
			continue
		}

		// Email author
		proposalName := proposalName(*pr)
		notification := www.NotificationEmailRegularProposalVetted
		if userNotificationEnabled(*author, notification) {
			err = p.emailProposalStatusChangeToAuthor(d, proposalName, author.Email)
			if err != nil {
				log.Errorf("emailProposalStatusChangeToAuthor: %v", err)
				continue
			}
		}

		// Compile list of users to send the notification to
		emails := make([]string, 0, 256)
		err = p.db.AllUsers(func(u *user.User) {
			switch {
			case u.ID.String() == d.adminID:
				// User is the admin that made the status change
				return
			case u.ID.String() == author.ID.String():
				// User is the author. The author is sent a different
				// notification. Don't include them in the users list.
				return
			case !userNotificationEnabled(*u, notification):
				// User does not have notification bit set
				return
			}

			// Add user to notification list
			emails = append(emails, u.Email)
		})

		// Email users
		err = p.emailProposalStatusChange(d, proposalName, emails)
		if err != nil {
			log.Errorf("emailProposalStatusChange: %v", err)
			continue
		}

		log.Debugf("Sent proposal status change notifications %v", d.token)
	}
}

func (p *politeiawww) notifyProposalAuthorOnComment(d dataProposalComment) error {
	// Lookup proposal author to see if they should be sent a
	// notification.
	pr, err := p.proposalRecordLatest(d.state, d.token)
	if err != nil {
		return fmt.Errorf("proposalRecordLatest %v %v: %v",
			d.state, d.token, err)
	}
	userID, err := uuid.Parse(pr.UserID)
	if err != nil {
		return err
	}
	author, err := p.db.UserGetById(userID)
	if err != nil {
		return fmt.Errorf("UserGetByID %v: %v", userID.String(), err)
	}

	// Check if notification should be sent to author
	switch {
	case d.username == author.Username:
		// Author commented on their own proposal
		return nil
	case !userNotificationEnabled(*author,
		www.NotificationEmailCommentOnMyProposal):
		// Author does not have notification bit set on
		return nil
	}

	// Send notification eamil
	commentID := strconv.FormatUint(uint64(d.commentID), 10)
	return p.emailProposalCommentSubmitted(d.token, commentID, d.username,
		proposalName(*pr), author.Email)
}

func (p *politeiawww) notifyParentAuthorOnComment(d dataProposalComment) error {
	// Verify this is a reply comment
	if d.parentID == 0 {
		return nil
	}

	// Lookup the parent comment author to check if they should receive
	// a reply notification.

	// Get the parent comment
	// TODO

	// Lookup the parent comment author
	var author *user.User

	// Check if notification should be sent to author
	switch {
	case d.username == author.Username:
		// Author commented on their own proposal
		return nil
	case !userNotificationEnabled(*author,
		www.NotificationEmailCommentOnMyProposal):
		// Author does not have notification bit set on
		return nil
	}

	// Get proposal. We need this proposal name for the notification.
	pr, err := p.proposalRecordLatest(d.state, d.token)
	if err != nil {
		return fmt.Errorf("proposalRecordLatest %v %v: %v",
			d.state, d.token, err)
	}

	// Send notification eamil
	commentID := strconv.FormatUint(uint64(d.commentID), 10)

	return p.emailProposalCommentReply(d.token, commentID, d.username,
		proposalName(*pr), author.Email)
}

type dataProposalComment struct {
	state     pi.PropStateT
	token     string
	commentID uint32
	parentID  uint32
	username  string // Comment author username
}

func (p *politeiawww) handleEventProposalComment(ch chan interface{}) {
	for msg := range ch {
		d, ok := msg.(dataProposalComment)
		if !ok {
			log.Errorf("handleEventProposalComment invalid msg: %v", msg)
			continue
		}

		// Notify the proposal author
		err := p.notifyProposalAuthorOnComment(d)
		if err != nil {
			err = fmt.Errorf("notifyProposalAuthorOnComment: %v", err)
			goto next
		}

		// Notify the parent comment author
		err = p.notifyParentAuthorOnComment(d)
		if err != nil {
			err = fmt.Errorf("notifyParentAuthorOnComment: %v", err)
			goto next
		}

		// Notifications successfully sent
		log.Debugf("Sent proposal commment notification %v", d.token)
		continue

	next:
		// If we made it here then there was an error. Log the error
		// before listening for the next event.
		log.Errorf("handleEventProposalComment: %v", err)
		continue
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

		// Compile a list of emails to send the notification to.
		emails := make([]string, 0, 256)
		err := p.db.AllUsers(func(u *user.User) {
			switch {
			case !u.Admin:
				// Only notify admin users
				return
			case !userNotificationEnabled(*u,
				www.NotificationEmailAdminProposalVoteAuthorized):
				// User does not have notification bit set
				return
			}

			// Add user to notification list
			emails = append(emails, u.Email)
		})

		// Send notification email
		err = p.emailProposalVoteAuthorized(d.token, d.name, d.username, emails)
		if err != nil {
			log.Errorf("emailProposalVoteAuthorized: %v", err)
			continue
		}

		log.Debugf("Sent proposal vote authorized notifications %v", d.token)
	}
}

type dataProposalVoteStarted struct {
	token   string    // Proposal censhorship token
	name    string    // Proposal name
	adminID string    // Admin uuid
	author  user.User // Proposal author
}

func (p *politeiawww) handleEventProposalVoteStarted(ch chan interface{}) {
	for msg := range ch {
		d, ok := msg.(dataProposalVoteStarted)
		if !ok {
			log.Errorf("handleEventProposalVoteStarted invalid msg: %v", msg)
			continue
		}

		// Email author
		notification := www.NotificationEmailRegularProposalVoteStarted
		if userNotificationEnabled(d.author, notification) {
			err := p.emailProposalVoteStartedToAuthor(d.token, d.name,
				d.author.Username, d.author.Email)
			if err != nil {
				log.Errorf("emailProposalVoteStartedToAuthor: %v", err)
				continue
			}
		}

		// Compile a list of users to send the notification to.
		emails := make([]string, 0, 256)
		err := p.db.AllUsers(func(u *user.User) {
			switch {
			case u.ID.String() == d.adminID:
				// Don't notify admin who started the vote
				return
			case u.ID.String() == d.author.ID.String():
				// Don't send this notification to the author
				return
			case !userNotificationEnabled(*u, notification):
				// User does not have notification bit set
				return
			}

			// Add user to notification list
			emails = append(emails, u.Email)
		})

		// Email users
		err = p.emailProposalVoteStarted(d.token, d.name, emails)
		if err != nil {
			log.Errorf("emailProposalVoteStartedToUsers: %v", err)
			continue
		}

		log.Debugf("Sent proposal vote started notifications %v", d.token)
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

		err := p.emailInvoiceNewComment(d.email)
		if err != nil {
			log.Errorf("emailInvoiceNewComment %v: %v", err)
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
		d, ok := msg.(dataInvoiceStatusUpdate)
		if !ok {
			log.Errorf("handleEventInvoiceStatusUpdate invalid msg: %v", msg)
			continue
		}

		err := p.emailInvoiceStatusUpdate(d.token, d.email)
		if err != nil {
			log.Errorf("emailInvoiceStatusUpdate %v: %v", err)
		}

		log.Debugf("Sent invoice status update notification %v", d.token)
	}
}

type dataDCCNew struct {
	token string // DCC token
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
			switch {
			case !u.Admin:
				// Only notify admin users
				return
			case u.Deactivated:
				// Never notify deactivated users
				return
			}

			emails = append(emails, u.Email)
		})

		err = p.emailDCCSubmitted(d.token, emails)
		if err != nil {
			log.Errorf("emailDCCSubmitted %v: %v", err)
		}

		log.Debugf("Sent DCC new notification %v", d.token)
	}
}

type dataDCCSupportOppose struct {
	token string // DCC token
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
			switch {
			case !u.Admin:
				// Only notify admin users
				return
			case u.Deactivated:
				// Never notify deactivated users
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
