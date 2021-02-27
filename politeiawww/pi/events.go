// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pi

import (
	"github.com/decred/politeia/politeiawww/comments"
	"github.com/decred/politeia/politeiawww/records"
	"github.com/decred/politeia/politeiawww/ticketvote"
)

func (p *Pi) setupEventListeners() {
	// Setup process for each event:
	// 1. Create a channel for the event.
	// 2. Register the channel with the event manager.
	// 3. Launch an event handler to listen for events emitted into the
	//    channel by the event manager.

	// Record new
	ch := make(chan interface{})
	p.events.Register(records.EventTypeNew, ch)
	go p.handleEventRecordNew(ch)

	// Record edit
	ch = make(chan interface{})
	p.events.Register(records.EventTypeEdit, ch)
	go p.handleEventRecordEdit(ch)

	// Record set status
	ch = make(chan interface{})
	p.events.Register(records.EventTypeSetStatus, ch)
	go p.handleEventRecordSetStatus(ch)

	// Comment new
	ch = make(chan interface{})
	p.events.Register(comments.EventTypeNew, ch)
	go p.handleEventCommentNew(ch)

	// Ticket vote authorized
	ch = make(chan interface{})
	p.events.Register(ticketvote.EventTypeAuthorize, ch)
	go p.handleEventVoteAuthorized(ch)

	// Ticket vote started
	ch = make(chan interface{})
	p.events.Register(ticketvote.EventTypeStart, ch)
	go p.handleEventVoteStart(ch)
}

func (p *Pi) handleEventRecordNew(ch chan interface{}) {
	for msg := range ch {
		e, ok := msg.(records.EventNew)
		if !ok {
			log.Errorf("handleEventRecordNew invalid msg: %v", msg)
			continue
		}

		/*
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
				log.Errorf("handleEventRecordNew: AllUsers: %v", err)
				return
			}

			// Send email notification
			err = p.emailRecordNew(d.token, d.name, d.username, emails)
			if err != nil {
				log.Errorf("emailRecordNew: %v", err)
			}

		*/
		log.Debugf("Proposal new ntfn sent %v", e.Record.CensorshipRecord.Token)
	}
}

func (p *Pi) handleEventRecordEdit(ch chan interface{}) {
	for msg := range ch {
		e, ok := msg.(records.EventEdit)
		if !ok {
			log.Errorf("handleEventRecordEdit invalid msg: %v", msg)
			continue
		}

		/*
			// Compile a list of users to send the notification to
			emails := make([]string, 0, 256)
			err := p.db.AllUsers(func(u *user.User) {
				// Check circumstances where we don't notify
				switch {
				case u.ID.String() == d.userID:
					// User is the author
					return
				case !userNotificationEnabled(*u,
					www.NotificationEmailRegularRecordEdit):
					// User doesn't have notification bit set
					return
				}

				// Add user to notification list
				emails = append(emails, u.Email)
			})
			if err != nil {
				log.Errorf("handleEventRecordEdit: AllUsers: %v", err)
				continue
			}

			err = p.emailRecordEdit(d.name, d.username,
				d.token, d.version, emails)
			if err != nil {
				log.Errorf("emailRecordEdit: %v", err)
				continue
			}

		*/
		log.Debugf("Proposal edit ntfn sent %v", e.Record.CensorshipRecord.Token)
	}
}

func (p *Pi) handleEventRecordSetStatus(ch chan interface{}) {
	for msg := range ch {
		e, ok := msg.(records.EventSetStatus)
		if !ok {
			log.Errorf("handleRecordSetStatus invalid msg: %v", msg)
			continue
		}

		/*
			// Check if proposal is in correct status for notification
			switch d.status {
			case rcv1.RecordStatusPublic, rcv1.RecordStatusCensored:
				// The status requires a notification be sent
			default:
				// The status does not require a notification be sent. Listen
				// for next event.
				continue
			}

				// Get the proposal author
				pr, err := p.proposalRecordLatest(context.Background(), d.state, d.token)
				if err != nil {
					log.Errorf("handleEventRecordSetStatus: proposalRecordLatest "+
						"%v %v: %v", d.state, d.token, err)
					continue
				}
				author, err := p.db.UserGetByPubKey(pr.PublicKey)
				if err != nil {
					log.Errorf("handleEventRecordSetStatus: UserGetByPubKey %v: %v",
						pr.PublicKey, err)
					continue
				}

				// Email author
				proposalName := proposalName(*pr)
				notification := www.NotificationEmailRegularProposalVetted
				if userNotificationEnabled(*author, notification) {
					err = p.emailRecordSetStatusToAuthor(d, proposalName, author.Email)
					if err != nil {
						log.Errorf("emailRecordSetStatusToAuthor: %v", err)
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
				if err != nil {
					log.Errorf("handleEventRecordSetStatus: AllUsers: %v", err)
					continue
				}

				// Email users
				err = p.emailRecordSetStatus(d, proposalName, emails)
				if err != nil {
					log.Errorf("emailRecordSetStatus: %v", err)
					continue
				}
		*/

		log.Debugf("Record set status event sent %v",
			e.Record.CensorshipRecord.Token)
	}
}

/*
func (p *Pi) notifyProposalAuthorOnComment(d dataCommentNew, userID, proposalName string) error {
	// Lookup proposal author to see if they should be sent a
	// notification.
	uuid, err := uuid.Parse(userID)
	if err != nil {
		return err
	}
	author, err := p.db.UserGetById(uuid)
	if err != nil {
		return fmt.Errorf("UserGetByID %v: %v", uuid.String(), err)
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
	return p.emailCommentNewSubmitted(d.token, commentID, d.username,
		proposalName, author.Email)
}

func (p *Pi) notifyParentAuthorOnComment(d dataCommentNew, proposalName string) error {
	// Verify this is a reply comment
	if d.parentID == 0 {
		return nil
	}

	// Lookup the parent comment author to check if they should receive
	// a reply notification.
	g := comments.Get{
		CommentIDs: []uint32{d.parentID},
	}
	_ = g
	var parentComment comments.GetReply
		parentComment, err := p.commentsGet(context.Background(), g)
		if err != nil {
			return err
		}
	userID, err := uuid.Parse(parentComment.Comments[0].UserID)
	if err != nil {
		return err
	}
	author, err := p.db.UserGetById(userID)
	if err != nil {
		return err
	}

	// Check if notification should be sent
	switch {
	case d.username == author.Username:
		// Author replied to their own comment
		return nil
	case !userNotificationEnabled(*author,
		www.NotificationEmailCommentOnMyComment):
		// Author does not have notification bit set on
		return nil
	}

	// Send notification email to parent comment author
	commentID := strconv.FormatUint(uint64(d.commentID), 10)
	return p.emailCommentNewReply(d.token, commentID, d.username,
		proposalName, author.Email)
}
*/

func (p *Pi) handleEventCommentNew(ch chan interface{}) {
	for msg := range ch {
		d, ok := msg.(comments.EventNew)
		if !ok {
			log.Errorf("handleEventCommentNew invalid msg: %v", msg)
			continue
		}

		_ = d
		/*
				// Fetch the proposal record here to avoid calling this two times
				// on the notify functions below
				pr, err := p.proposalRecordLatest(context.Background(), d.state,
					d.token)
				if err != nil {
					err = fmt.Errorf("proposalRecordLatest %v %v: %v",
						d.state, d.token, err)
					goto next
				}

				// Notify the proposal author
				err = p.notifyProposalAuthorOnComment(d, pr.UserID, proposalName(*pr))
				if err != nil {
					err = fmt.Errorf("notifyProposalAuthorOnComment: %v", err)
					goto next
				}

				// Notify the parent comment author
				err = p.notifyParentAuthorOnComment(d, proposalName(*pr))
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
				log.Errorf("handleEventCommentNew: %v", err)
				continue
		*/

		log.Debugf("Proposal comment ntfn sent %v", d.Comment.Token)
	}
}

func (p *Pi) handleEventVoteAuthorized(ch chan interface{}) {
	for msg := range ch {
		e, ok := msg.(ticketvote.EventAuthorize)
		if !ok {
			log.Errorf("handleEventVoteAuthorized invalid msg: %v", msg)
			continue
		}

		/*
			// Compile a list of emails to send the notification to.
			emails := make([]string, 0, 256)
			err := p.db.AllUsers(func(u *user.User) {
				switch {
				case !u.Admin:
					// Only notify admin users
					return
				case !userNotificationEnabled(*u,
					www.NotificationEmailAdminVoteAuthorized):
					// User does not have notification bit set
					return
				}

				// Add user to notification list
				emails = append(emails, u.Email)
			})
			if err != nil {
				log.Errorf("handleEventVoteAuthorized: AllUsers: %v", err)
				continue
			}

			// Send notification email
			err = p.emailVoteAuthorized(d.token, d.name, d.username, emails)
			if err != nil {
				log.Errorf("emailVoteAuthorized: %v", err)
				continue
			}
		*/

		log.Debugf("Proposal vote authorized ntfn sent %v", e.Auth.Token)
	}
}

func (p *Pi) handleEventVoteStart(ch chan interface{}) {
	for msg := range ch {
		e, ok := msg.(ticketvote.EventStart)
		if !ok {
			log.Errorf("handleEventVoteStart invalid msg: %v", msg)
			continue
		}

		/*
			// Email author
			notification := www.NotificationEmailRegularVoteStart
			if userNotificationEnabled(d.author, notification) {
				err := p.emailVoteStartToAuthor(d.token, d.name,
					d.author.Username, d.author.Email)
				if err != nil {
					log.Errorf("emailVoteStartToAuthor: %v", err)
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
			if err != nil {
				log.Errorf("handleEventVoteStart: AllUsers: %v", err)
			}

			// Email users
			err = p.emailVoteStart(d.token, d.name, emails)
			if err != nil {
				log.Errorf("emailVoteStartToUsers: %v", err)
				continue
			}
		*/

		_ = e
		token := "fix me"
		log.Debugf("Proposal vote started ntfn sent %v", token)
	}
}

/*
// emailProposalSubmitted send a proposal submitted notification email to
// the provided list of emails.
func (p *politeiawww) emailProposalSubmitted(token, name, username string, emails []string) error {
	route := strings.Replace(guiRouteProposalDetails, "{token}", token, 1)
	l, err := url.Parse(p.cfg.WebServerAddress + route)
	if err != nil {
		return err
	}

	tmplData := proposalSubmitted{
		Username: username,
		Name:     name,
		Link:     l.String(),
	}

	subject := "New Proposal Submitted"
	body, err := createBody(proposalSubmittedTmpl, tmplData)
	if err != nil {
		return err
	}

	return p.smtp.sendEmailTo(subject, body, emails)
}

// emailProposalEdited sends a proposal edited notification email to the
// provided list of emails.
func (p *politeiawww) emailProposalEdited(name, username, token, version string, emails []string) error {
	route := strings.Replace(guiRouteProposalDetails, "{token}", token, 1)
	l, err := url.Parse(p.cfg.WebServerAddress + route)
	if err != nil {
		return err
	}

	tmplData := proposalEdited{
		Name:     name,
		Version:  version,
		Username: username,
		Link:     l.String(),
	}

	subject := "Proposal Edited"
	body, err := createBody(proposalEditedTmpl, tmplData)
	if err != nil {
		return err
	}

	return p.smtp.sendEmailTo(subject, body, emails)
}

// emailProposalStatusChange sends a proposal status change email to the
// provided email addresses.
func (p *politeiawww) emailProposalStatusChange(d dataProposalStatusChange, proposalName string, emails []string) error {
	route := strings.Replace(guiRouteProposalDetails, "{token}", d.token, 1)
	l, err := url.Parse(p.cfg.WebServerAddress + route)
	if err != nil {
		return err
	}

	var (
		subject string
		body    string
	)
	switch d.status {
	case rcv1.RecordStatusPublic:
		subject = "New Proposal Published"
		tmplData := proposalVetted{
			Name: proposalName,
			Link: l.String(),
		}
		body, err = createBody(tmplProposalVetted, tmplData)
		if err != nil {
			return err
		}

	default:
		log.Debugf("no user notification for prop status %v", d.status)
		return nil
	}

	return p.smtp.sendEmailTo(subject, body, emails)
}

// emailProposalStatusChangeAuthor sends a proposal status change notification
// email to the provided email address.
func (p *politeiawww) emailProposalStatusChangeToAuthor(d dataProposalStatusChange, proposalName, authorEmail string) error {
	route := strings.Replace(guiRouteProposalDetails, "{token}", d.token, 1)
	l, err := url.Parse(p.cfg.WebServerAddress + route)
	if err != nil {
		return err
	}

	var (
		subject string
		body    string
	)
	switch d.status {
	case rcv1.RecordStatusPublic:
		subject = "Your Proposal Has Been Published"
		tmplData := proposalVettedToAuthor{
			Name: proposalName,
			Link: l.String(),
		}
		body, err = createBody(proposalVettedToAuthorTmpl, tmplData)
		if err != nil {
			return err
		}

	case rcv1.RecordStatusCensored:
		subject = "Your Proposal Has Been Censored"
		tmplData := proposalCensoredToAuthor{
			Name:   proposalName,
			Reason: d.reason,
		}
		body, err = createBody(tmplProposalCensoredForAuthor, tmplData)
		if err != nil {
			return err
		}

	default:
		return fmt.Errorf("no author notification for prop status %v", d.status)
	}

	return p.smtp.sendEmailTo(subject, body, []string{authorEmail})
}

// emailProposalCommentSubmitted sends a proposal comment submitted email to
// the provided email address.
func (p *politeiawww) emailProposalCommentSubmitted(token, commentID, commentUsername, proposalName, proposalAuthorEmail string) error {
	// Setup comment URL
	route := strings.Replace(guirouteProposalComments, "{token}", token, 1)
	route = strings.Replace(route, "{id}", commentID, 1)
	l, err := url.Parse(p.cfg.WebServerAddress + route)
	if err != nil {
		return err
	}

	// Setup email
	subject := "New Comment On Your Proposal"
	tmplData := proposalCommentSubmitted{
		Username: commentUsername,
		Name:     proposalName,
		Link:     l.String(),
	}
	body, err := createBody(proposalCommentSubmittedTmpl, tmplData)
	if err != nil {
		return err
	}

	// Send email
	return p.smtp.sendEmailTo(subject, body, []string{proposalAuthorEmail})
}

// emailProposalCommentReply sends a proposal comment reply email to the
// provided email address.
func (p *politeiawww) emailProposalCommentReply(token, commentID, commentUsername, proposalName, parentCommentEmail string) error {
	// Setup comment URL
	route := strings.Replace(guirouteProposalComments, "{token}", token, 1)
	route = strings.Replace(route, "{id}", commentID, 1)
	l, err := url.Parse(p.cfg.WebServerAddress + route)
	if err != nil {
		return err
	}

	// Setup email
	subject := "New Reply To Your Comment"
	tmplData := proposalCommentReply{
		Username: commentUsername,
		Name:     proposalName,
		Link:     l.String(),
	}
	body, err := createBody(proposalCommentReplyTmpl, tmplData)
	if err != nil {
		return err
	}

	// Send email
	return p.smtp.sendEmailTo(subject, body, []string{parentCommentEmail})
}

// emailProposalVoteAuthorized sends a proposal vote authorized email to the
// provided list of emails.
func (p *politeiawww) emailProposalVoteAuthorized(token, name, username string, emails []string) error {
	// Setup URL
	route := strings.Replace(guiRouteProposalDetails, "{token}", token, 1)
	l, err := url.Parse(p.cfg.WebServerAddress + route)
	if err != nil {
		return err
	}

	// Setup email
	subject := "Proposal Authorized To Start Voting"
	tplData := proposalVoteAuthorized{
		Username: username,
		Name:     name,
		Link:     l.String(),
	}
	body, err := createBody(proposalVoteAuthorizedTmpl, tplData)
	if err != nil {
		return err
	}

	// Send email
	return p.smtp.sendEmailTo(subject, body, emails)
}

// emailProposalVoteStarted sends a proposal vote started email notification
// to the provided email addresses.
func (p *politeiawww) emailProposalVoteStarted(token, name string, emails []string) error {
	// Setup URL
	route := strings.Replace(guiRouteProposalDetails, "{token}", token, 1)
	l, err := url.Parse(p.cfg.WebServerAddress + route)
	if err != nil {
		return err
	}

	// Setup email
	subject := "Voting Started for Proposal"
	tplData := proposalVoteStarted{
		Name: name,
		Link: l.String(),
	}
	body, err := createBody(proposalVoteStartedTmpl, tplData)
	if err != nil {
		return err
	}

	// Send email
	return p.smtp.sendEmailTo(subject, body, emails)
}

// emailProposalVoteStartedToAuthor sends a proposal vote started email to
// the provided email address.
func (p *politeiawww) emailProposalVoteStartedToAuthor(token, name, username, email string) error {
	// Setup URL
	route := strings.Replace(guiRouteProposalDetails, "{token}", token, 1)
	l, err := url.Parse(p.cfg.WebServerAddress + route)
	if err != nil {
		return err
	}

	// Setup email
	subject := "Your Proposal Has Started Voting"
	tplData := proposalVoteStartedToAuthor{
		Name: name,
		Link: l.String(),
	}
	body, err := createBody(proposalVoteStartedToAuthorTmpl, tplData)
	if err != nil {
		return err
	}

	// Send email
	return p.smtp.sendEmailTo(subject, body, []string{email})
}
*/
