// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/google/uuid"

	v1 "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/politeiawww/user"
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
	User             *user.User
}

type EventDataProposalStatusChange struct {
	Proposal          *v1.ProposalRecord
	SetProposalStatus *v1.SetProposalStatus
	AdminUser         *user.User
}

type EventDataProposalEdited struct {
	Proposal *v1.ProposalRecord
}

type EventDataProposalVoteStarted struct {
	AdminUser *user.User
	StartVote *v1.StartVote
}

type EventDataProposalVoteAuthorized struct {
	AuthorizeVote *v1.AuthorizeVote
	User          *user.User
}

type EventDataComment struct {
	Comment *v1.Comment
}

type EventDataUserManage struct {
	AdminUser  *user.User
	User       *user.User
	ManageUser *v1.ManageUser
}

func (p *politeiawww) _getProposalAuthor(proposal *v1.ProposalRecord) (*user.User, error) {
	if proposal.UserId == "" {
		proposal.UserId = p.userPubkeys[proposal.PublicKey]
	}

	userID, err := uuid.Parse(proposal.UserId)
	if err != nil {
		return nil, fmt.Errorf("cannot parse UUID for proposal author: %v", err)
	}

	author, err := p.db.UserGetById(userID)
	if err != nil {
		return nil, fmt.Errorf("cannot fetch author for proposal: %v", err)
	}

	return author, nil
}

func (p *politeiawww) getProposalAuthor(proposal *v1.ProposalRecord) (*user.User, error) {
	p.RLock()
	defer p.RUnlock()

	return p._getProposalAuthor(proposal)
}

func (p *politeiawww) getProposalAndAuthor(token string) (*v1.ProposalRecord, *user.User, error) {
	proposal, err := p.getProp(token)
	if err != nil {
		return nil, nil, err
	}

	userID, err := uuid.Parse(proposal.UserId)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot parse UUID %v: %v",
			proposal.UserId, err)
	}

	author, err := p.db.UserGetById(userID)
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
func (p *politeiawww) fireEvent(eventType EventT, data interface{}) {
	p.Lock()
	defer p.Unlock()

	p.eventManager._fireEvent(eventType, data)
}

func (p *politeiawww) initEventManager() {
	p.Lock()
	defer p.Unlock()

	p.eventManager = &EventManager{}

	p._setupProposalStatusChangeLogging()
	p._setupProposalVoteStartedLogging()
	p._setupUserManageLogging()

	if p.smtp.disabled {
		return
	}

	p._setupProposalSubmittedEmailNotification()
	p._setupProposalStatusChangeEmailNotification()
	p._setupProposalEditedEmailNotification()
	p._setupProposalVoteStartedEmailNotification()
	p._setupProposalVoteAuthorizedEmailNotification()
	p._setupCommentReplyEmailNotifications()
}

func (p *politeiawww) _setupProposalSubmittedEmailNotification() {
	ch := make(chan interface{})
	go func() {
		for data := range ch {
			ps, ok := data.(EventDataProposalSubmitted)
			if !ok {
				log.Errorf("invalid event data")
				continue
			}

			err := p.emailAdminsForNewSubmittedProposal(
				ps.CensorshipRecord.Token, ps.ProposalName,
				ps.User.Username, ps.User.Email)
			if err != nil {
				log.Errorf("email all admins for new submitted proposal %v: %v",
					ps.CensorshipRecord.Token, err)
			}
		}
	}()
	p.eventManager._register(EventTypeProposalSubmitted, ch)
}

func (p *politeiawww) _setupProposalStatusChangeEmailNotification() {
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

			author, err := p.getProposalAuthor(psc.Proposal)
			if err != nil {
				log.Errorf("cannot fetch author for proposal: %v", err)
				continue
			}

			switch psc.SetProposalStatus.ProposalStatus {
			case v1.PropStatusPublic:
				err = p.emailAuthorForVettedProposal(psc.Proposal, author,
					psc.AdminUser)
				if err != nil {
					log.Errorf("email author for vetted proposal %v: %v",
						psc.Proposal.CensorshipRecord.Token, err)
				}
				err = p.emailUsersForVettedProposal(psc.Proposal, author,
					psc.AdminUser)
				if err != nil {
					log.Errorf("email users for vetted proposal %v: %v",
						psc.Proposal.CensorshipRecord.Token, err)
				}
			case v1.PropStatusCensored:
				err = p.emailAuthorForCensoredProposal(psc.Proposal, author,
					psc.AdminUser)
				if err != nil {
					log.Errorf("email author for censored proposal %v: %v",
						psc.Proposal.CensorshipRecord.Token, err)
				}
			default:
			}
		}
	}()
	p.eventManager._register(EventTypeProposalStatusChange, ch)
}

func (p *politeiawww) _setupProposalStatusChangeLogging() {
	ch := make(chan interface{})
	go func() {
		for data := range ch {
			psc, ok := data.(EventDataProposalStatusChange)
			if !ok {
				log.Errorf("invalid event data")
				continue
			}

			// Log the action in the admin log.
			err := p.logAdminProposalAction(psc.AdminUser,
				psc.Proposal.CensorshipRecord.Token,
				fmt.Sprintf("set proposal status to %v",
					v1.PropStatus[psc.SetProposalStatus.ProposalStatus]),
				psc.SetProposalStatus.StatusChangeMessage)

			if err != nil {
				log.Errorf("could not log action to file: %v", err)
			}
		}
	}()
	p.eventManager._register(EventTypeProposalStatusChange, ch)
}

func (p *politeiawww) _setupProposalEditedEmailNotification() {
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

			author, err := p.getProposalAuthor(pe.Proposal)
			if err != nil {
				log.Errorf("cannot fetch author for proposal: %v", err)
				continue
			}

			err = p.emailUsersForEditedProposal(pe.Proposal, author)
			if err != nil {
				log.Errorf("email users for edited proposal %v: %v",
					pe.Proposal.CensorshipRecord.Token, err)
			}
		}
	}()
	p.eventManager._register(EventTypeProposalEdited, ch)
}

func (p *politeiawww) _setupProposalVoteStartedEmailNotification() {
	ch := make(chan interface{})
	go func() {
		for data := range ch {
			pvs, ok := data.(EventDataProposalVoteStarted)
			if !ok {
				log.Errorf("invalid event data")
				continue
			}

			token := pvs.StartVote.Vote.Token
			proposal, author, err := p.getProposalAndAuthor(
				token)
			if err != nil {
				log.Error(err)
				continue
			}

			err = p.emailUsersForProposalVoteStarted(proposal, author,
				pvs.AdminUser)
			if err != nil {
				log.Errorf("email all admins for new submitted proposal %v: %v",
					token, err)
			}
		}
	}()
	p.eventManager._register(EventTypeProposalVoteStarted, ch)
}

func (p *politeiawww) _setupProposalVoteStartedLogging() {
	ch := make(chan interface{})
	go func() {
		for data := range ch {
			pvs, ok := data.(EventDataProposalVoteStarted)
			if !ok {
				log.Errorf("invalid event data")
				continue
			}

			// Log the action in the admin log.
			err := p.logAdminProposalAction(pvs.AdminUser,
				pvs.StartVote.Vote.Token, "start vote", "")
			if err != nil {
				log.Errorf("could not log action to file: %v", err)
			}
		}
	}()
	p.eventManager._register(EventTypeProposalVoteStarted, ch)
}

func (p *politeiawww) _setupProposalVoteAuthorizedEmailNotification() {
	ch := make(chan interface{})
	go func() {
		for data := range ch {
			pvs, ok := data.(EventDataProposalVoteAuthorized)
			if !ok {
				log.Errorf("invalid event data")
				continue
			}

			token := pvs.AuthorizeVote.Token
			record, err := p.cache.Record(token)
			if err != nil {
				log.Errorf("proposal not found: %v", err)
				continue
			}
			proposal := convertPropFromCache(*record)

			err = p.emailAdminsForProposalVoteAuthorized(&proposal, pvs.User)
			if err != nil {
				log.Errorf("email all admins for new submitted proposal %v: %v",
					token, err)
			}
		}
	}()
	p.eventManager._register(EventTypeProposalVoteAuthorized, ch)
}

func (p *politeiawww) _setupCommentReplyEmailNotifications() {
	ch := make(chan interface{})
	go func() {
		for data := range ch {
			c, ok := data.(EventDataComment)
			if !ok {
				log.Errorf("invalid event data")
				continue
			}

			token := c.Comment.Token
			proposal, author, err := p.getProposalAndAuthor(token)
			if err != nil {
				log.Error(err)
				continue
			}

			if c.Comment.ParentID == "0" {
				// Top-level comment
				err := p.emailAuthorForCommentOnProposal(proposal, author,
					c.Comment.CommentID, c.Comment.Username)
				if err != nil {
					log.Errorf("email author of proposal %v for new comment %v: %v",
						c.Comment.Token, c.Comment.CommentID, err)
				}
			} else {
				parent, err := p.decredGetComment(token, c.Comment.ParentID)
				if err != nil {
					log.Errorf("EventManager: getComment failed for token %v "+
						"commentID %v: %v", token, c.Comment.ParentID, err)
					continue
				}

				authorID, ok := p.userPubkeys[parent.PublicKey]
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

				author, err := p.db.UserGetById(authorUUID)
				if err != nil {
					log.Errorf("cannot fetch author for comment: %v", err)
					continue
				}

				// Comment reply to another comment
				err = p.emailAuthorForCommentOnComment(proposal, author,
					c.Comment.CommentID, c.Comment.Username)
				if err != nil {
					log.Errorf("email author of comment %v for new comment %v: %v",
						c.Comment.CommentID, c.Comment.ParentID, err)
				}
			}
		}
	}()
	p.eventManager._register(EventTypeComment, ch)
}

func (p *politeiawww) _setupUserManageLogging() {
	ch := make(chan interface{})
	go func() {
		for data := range ch {
			ue, ok := data.(EventDataUserManage)
			if !ok {
				log.Errorf("invalid event data")
				continue
			}

			// Log the action in the admin log.
			err := p.logAdminUserAction(ue.AdminUser, ue.User,
				ue.ManageUser.Action, ue.ManageUser.Reason)
			if err != nil {
				log.Errorf("could not log action to file: %v", err)
			}
		}
	}()
	p.eventManager._register(EventTypeUserManage, ch)
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
