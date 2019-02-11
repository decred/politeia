// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/google/uuid"

	"github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/politeiawww/database"
)

// EventT is the type of event.
type EventT int

// EventManager manages listeners (channels) for different event types.
type EventManager struct {
	Listeners map[EventT][]chan interface{}
}

const (
	EventTypeInvalid EventT = iota
	EventTypeProposalSubmitted
	EventTypeProposalStatusChange
	EventTypeProposalEdited
	EventTypeProposalVoteStarted
	EventTypeProposalVoteAuthorized
	EventTypeProposalVoteFinished
	EventTypeComment
	EventTypeUserManage
)

type EventDataProposalSubmitted struct {
	CensorshipRecord *v1.CensorshipRecord
	ProposalName     string
	User             *database.User
}

type EventDataProposalStatusChange struct {
	Proposal          *v1.ProposalRecord
	SetProposalStatus *v1.SetProposalStatus
	AdminUser         *database.User
}

type EventDataProposalEdited struct {
	Proposal *v1.ProposalRecord
}

type EventDataProposalVoteStarted struct {
	AdminUser *database.User
	StartVote *v1.StartVote
}

type EventDataProposalVoteAuthorized struct {
	AuthorizeVote *v1.AuthorizeVote
	User          *database.User
}

type EventDataComment struct {
	Comment *v1.Comment
}

type EventDataUserManage struct {
	AdminUser  *database.User
	User       *database.User
	ManageUser *v1.ManageUser
}

func (b *backend) _getProposalAuthor(proposal *v1.ProposalRecord) (*database.User, error) {
	if proposal.UserId == "" {
		proposal.UserId = b.userPubkeys[proposal.PublicKey]
	}

	userID, err := uuid.Parse(proposal.UserId)
	if err != nil {
		return nil, fmt.Errorf("cannot parse UUID for proposal author: %v", err)
	}

	author, err := b.db.UserGetById(userID)
	if err != nil {
		return nil, fmt.Errorf("cannot fetch author for proposal: %v", err)
	}

	return author, nil
}

func (b *backend) getProposalAuthor(proposal *v1.ProposalRecord) (*database.User, error) {
	b.RLock()
	defer b.RUnlock()

	return b._getProposalAuthor(proposal)
}

func (b *backend) getProposalAndAuthor(token string) (*v1.ProposalRecord, *database.User, error) {
	proposal, err := b.getProp(token)
	if err != nil {
		return nil, nil, err
	}

	userID, err := uuid.Parse(proposal.UserId)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot parse UUID %v: %v",
			proposal.UserId, err)
	}

	author, err := b.db.UserGetById(userID)
	if err != nil {
		return nil, nil, fmt.Errorf("user lookup failed for userID %v: %v",
			userID, err)
	}

	return proposal, author, nil
}

// fireEvent is a convenience wrapper for EventManager._fireEvent which
// holds the lock.
//
// This function must be called WITHOUT the mutex held.
func (b *backend) fireEvent(eventType EventT, data interface{}) {
	b.Lock()
	defer b.Unlock()

	b.eventManager._fireEvent(eventType, data)
}

func (b *backend) initEventManager() {
	b.Lock()
	defer b.Unlock()

	b.eventManager = &EventManager{}

	b._setupProposalStatusChangeLogging()
	b._setupProposalVoteStartedLogging()
	b._setupUserManageLogging()

	if b.cfg.SMTP == nil {
		return
	}

	b._setupProposalSubmittedEmailNotification()
	b._setupProposalStatusChangeEmailNotification()
	b._setupProposalEditedEmailNotification()
	b._setupProposalVoteStartedEmailNotification()
	b._setupProposalVoteAuthorizedEmailNotification()
	b._setupCommentReplyEmailNotifications()
}

func (b *backend) _setupProposalSubmittedEmailNotification() {
	ch := make(chan interface{})
	go func() {
		for data := range ch {
			ps, ok := data.(EventDataProposalSubmitted)
			if !ok {
				log.Errorf("invalid event data")
				continue
			}

			err := b.emailAdminsForNewSubmittedProposal(
				ps.CensorshipRecord.Token, ps.ProposalName,
				ps.User.Username, ps.User.Email)
			if err != nil {
				log.Errorf("email all admins for new submitted proposal %v: %v",
					ps.CensorshipRecord.Token, err)
			}
		}
	}()
	b.eventManager._register(EventTypeProposalSubmitted, ch)
}

func (b *backend) _setupProposalStatusChangeEmailNotification() {
	ch := make(chan interface{})
	go func() {
		for data := range ch {
			psc, ok := data.(EventDataProposalStatusChange)
			if !ok {
				log.Errorf("invalid event data")
				continue
			}

			if psc.SetProposalStatus.ProposalStatus != v1.PropStatusPublic &&
				psc.SetProposalStatus.ProposalStatus != v1.PropStatusCensored {
				continue
			}

			author, err := b.getProposalAuthor(psc.Proposal)
			if err != nil {
				log.Errorf("cannot fetch author for proposal: %v", err)
				continue
			}

			switch psc.SetProposalStatus.ProposalStatus {
			case v1.PropStatusPublic:
				err = b.emailAuthorForVettedProposal(psc.Proposal, author,
					psc.AdminUser)
				if err != nil {
					log.Errorf("email author for vetted proposal %v: %v",
						psc.Proposal.CensorshipRecord.Token, err)
				}
				err = b.emailUsersForVettedProposal(psc.Proposal, author,
					psc.AdminUser)
				if err != nil {
					log.Errorf("email users for vetted proposal %v: %v",
						psc.Proposal.CensorshipRecord.Token, err)
				}
			case v1.PropStatusCensored:
				err = b.emailAuthorForCensoredProposal(psc.Proposal, author,
					psc.AdminUser)
				if err != nil {
					log.Errorf("email author for censored proposal %v: %v",
						psc.Proposal.CensorshipRecord.Token, err)
				}
			default:
			}
		}
	}()
	b.eventManager._register(EventTypeProposalStatusChange, ch)
}

func (b *backend) _setupProposalStatusChangeLogging() {
	ch := make(chan interface{})
	go func() {
		for data := range ch {
			psc, ok := data.(EventDataProposalStatusChange)
			if !ok {
				log.Errorf("invalid event data")
				continue
			}

			// Log the action in the admin log.
			err := b.logAdminProposalAction(psc.AdminUser,
				psc.Proposal.CensorshipRecord.Token,
				fmt.Sprintf("set proposal status to %v",
					v1.PropStatus[psc.SetProposalStatus.ProposalStatus]),
				psc.SetProposalStatus.StatusChangeMessage)

			if err != nil {
				log.Errorf("could not log action to file: %v", err)
			}
		}
	}()
	b.eventManager._register(EventTypeProposalStatusChange, ch)
}

func (b *backend) _setupProposalEditedEmailNotification() {
	ch := make(chan interface{})
	go func() {
		for data := range ch {
			pe, ok := data.(EventDataProposalEdited)
			if !ok {
				log.Errorf("invalid event data")
				continue
			}

			if pe.Proposal.Status != v1.PropStatusPublic {
				continue
			}

			author, err := b.getProposalAuthor(pe.Proposal)
			if err != nil {
				log.Errorf("cannot fetch author for proposal: %v", err)
				continue
			}

			err = b.emailUsersForEditedProposal(pe.Proposal, author)
			if err != nil {
				log.Errorf("email users for edited proposal %v: %v",
					pe.Proposal.CensorshipRecord.Token, err)
			}
		}
	}()
	b.eventManager._register(EventTypeProposalEdited, ch)
}

func (b *backend) _setupProposalVoteStartedEmailNotification() {
	ch := make(chan interface{})
	go func() {
		for data := range ch {
			pvs, ok := data.(EventDataProposalVoteStarted)
			if !ok {
				log.Errorf("invalid event data")
				continue
			}

			token := pvs.StartVote.Vote.Token
			proposal, author, err := b.getProposalAndAuthor(
				token)
			if err != nil {
				log.Error(err)
				continue
			}

			err = b.emailUsersForProposalVoteStarted(proposal, author,
				pvs.AdminUser)
			if err != nil {
				log.Errorf("email all admins for new submitted proposal %v: %v",
					token, err)
			}
		}
	}()
	b.eventManager._register(EventTypeProposalVoteStarted, ch)
}

func (b *backend) _setupProposalVoteStartedLogging() {
	ch := make(chan interface{})
	go func() {
		for data := range ch {
			pvs, ok := data.(EventDataProposalVoteStarted)
			if !ok {
				log.Errorf("invalid event data")
				continue
			}

			// Log the action in the admin log.
			err := b.logAdminProposalAction(pvs.AdminUser,
				pvs.StartVote.Vote.Token, "start vote", "")
			if err != nil {
				log.Errorf("could not log action to file: %v", err)
			}
		}
	}()
	b.eventManager._register(EventTypeProposalVoteStarted, ch)
}

func (b *backend) _setupProposalVoteAuthorizedEmailNotification() {
	ch := make(chan interface{})
	go func() {
		for data := range ch {
			pvs, ok := data.(EventDataProposalVoteAuthorized)
			if !ok {
				log.Errorf("invalid event data")
				continue
			}

			token := pvs.AuthorizeVote.Token
			record, err := b.cache.Record(token)
			if err != nil {
				log.Errorf("proposal not found: %v", err)
				continue
			}
			proposal := convertPropFromCache(*record)

			err = b.emailAdminsForProposalVoteAuthorized(&proposal, pvs.User)
			if err != nil {
				log.Errorf("email all admins for new submitted proposal %v: %v",
					token, err)
			}
		}
	}()
	b.eventManager._register(EventTypeProposalVoteAuthorized, ch)
}

func (b *backend) _setupCommentReplyEmailNotifications() {
	ch := make(chan interface{})
	go func() {
		for data := range ch {
			c, ok := data.(EventDataComment)
			if !ok {
				log.Errorf("invalid event data")
				continue
			}

			token := c.Comment.Token
			proposal, author, err := b.getProposalAndAuthor(token)
			if err != nil {
				log.Error(err)
				continue
			}

			if c.Comment.ParentID == "0" {
				// Top-level comment
				err := b.emailAuthorForCommentOnProposal(proposal, author,
					c.Comment.CommentID, c.Comment.Username)
				if err != nil {
					log.Errorf("email author of proposal %v for new comment %v: %v",
						c.Comment.Token, c.Comment.CommentID, err)
				}
			} else {
				parent, err := b.decredGetComment(token, c.Comment.ParentID)
				if err != nil {
					log.Errorf("EventManager: getComment failed for token %v "+
						"commentID %v: %v", token, c.Comment.ParentID, err)
					continue
				}

				authorID, ok := b.userPubkeys[parent.PublicKey]
				if !ok {
					log.Errorf("EventManager: userID lookup failed for pubkey %v",
						parent.PublicKey)
					continue
				}

				authorUUID, err := uuid.Parse(authorID)
				if err != nil {
					log.Errorf("cannot parse UUID for comment author: %v",
						err)
					continue
				}

				author, err := b.db.UserGetById(authorUUID)
				if err != nil {
					log.Errorf("cannot fetch author for comment: %v", err)
					continue
				}

				// Comment reply to another comment
				err = b.emailAuthorForCommentOnComment(proposal, author,
					c.Comment.CommentID, c.Comment.Username)
				if err != nil {
					log.Errorf("email author of comment %v for new comment %v: %v",
						c.Comment.CommentID, c.Comment.ParentID, err)
				}
			}
		}
	}()
	b.eventManager._register(EventTypeComment, ch)
}

func (b *backend) _setupUserManageLogging() {
	ch := make(chan interface{})
	go func() {
		for data := range ch {
			ue, ok := data.(EventDataUserManage)
			if !ok {
				log.Errorf("invalid event data")
				continue
			}

			// Log the action in the admin log.
			err := b.logAdminUserAction(ue.AdminUser, ue.User,
				ue.ManageUser.Action, ue.ManageUser.Reason)
			if err != nil {
				log.Errorf("could not log action to file: %v", err)
			}
		}
	}()
	b.eventManager._register(EventTypeUserManage, ch)
}

// _register adds a listener channel for the given event type.
//
// This function must be called WITH the mutex held.
func (e *EventManager) _register(eventType EventT, listenerToAdd chan interface{}) {
	if e.Listeners == nil {
		e.Listeners = make(map[EventT][]chan interface{})
	}

	if _, ok := e.Listeners[eventType]; ok {
		e.Listeners[eventType] = append(e.Listeners[eventType], listenerToAdd)
	} else {
		e.Listeners[eventType] = []chan interface{}{listenerToAdd}
	}
}

// _unregister removes the given listener channel for the given event type.
//
// This function must be called WITH the mutex held.
func (e *EventManager) _unregister(eventType EventT, listenerToRemove chan interface{}) {
	listeners, ok := e.Listeners[eventType]
	if !ok {
		return
	}

	for i, listener := range listeners {
		if listener == listenerToRemove {
			e.Listeners[eventType] = append(e.Listeners[eventType][:i],
				e.Listeners[eventType][i+1:]...)
			break
		}
	}
}

// _fireEvent iterates all listener channels for the given event type and
// passes the given data to it.
//
// This function must be called WITH the mutex held.
func (e *EventManager) _fireEvent(eventType EventT, data interface{}) {
	listeners, ok := e.Listeners[eventType]
	if !ok {
		return
	}

	for _, listener := range listeners {
		go func(listener chan interface{}) {
			listener <- data
		}(listener)
	}
}
