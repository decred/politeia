// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/decred/politeia/politeiad/plugins/pi"
	"github.com/decred/politeia/politeiad/plugins/usermd"
	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/comments"
	"github.com/decred/politeia/politeiawww/records"
	"github.com/decred/politeia/politeiawww/ticketvote"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/google/uuid"
)

func (p *Pi) setupEventListeners() {
	// Setup process for each event:
	// 1. Create a channel for the event.
	// 2. Register the channel with the event manager.
	// 3. Launch an event handler to listen for events emitted into the
	//    channel by the event manager.

	log.Debugf("Setting up pi event listeners")

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

		// Compile notification email list
		var (
			emails  = make([]string, 0, 256)
			ntfnBit = uint64(www.NotificationEmailAdminProposalNew)
		)
		err := p.userdb.AllUsers(func(u *user.User) {
			switch {
			case !u.Admin:
				// Only admins get this notification
				return
			case !u.NotificationIsEnabled(ntfnBit):
				// Admin doesn't have notification bit set
				return
			default:
				// User is an admin and has the notification bit set. Add
				// them to the email list.
				emails = append(emails, u.Email)
			}
		})
		if err != nil {
			log.Errorf("handleEventRecordNew: AllUsers: %v", err)
			return
		}

		// Send notfication email
		var (
			token = e.Record.CensorshipRecord.Token
			name  = proposalName(e.Record)
		)
		err = p.mailNtfnProposalNew(token, name, e.User.Username, emails)
		if err != nil {
			log.Errorf("mailNtfnProposalNew: %v", err)
		}

		log.Debugf("Proposal new ntfn sent %v", token)
	}
}

func (p *Pi) handleEventRecordEdit(ch chan interface{}) {
	for msg := range ch {
		e, ok := msg.(records.EventEdit)
		if !ok {
			log.Errorf("handleEventRecordEdit invalid msg: %v", msg)
			continue
		}

		// Only send edit notifications for public proposals
		if e.State == rcv1.RecordStateUnvetted {
			log.Debugf("Proposal is unvetted no edit ntfn %v",
				e.Record.CensorshipRecord.Token)
			continue
		}

		// Compile notification email list
		var (
			emails   = make([]string, 0, 256)
			authorID = e.User.ID.String()
			ntfnBit  = uint64(www.NotificationEmailRegularProposalEdited)
		)
		err := p.userdb.AllUsers(func(u *user.User) {
			switch {
			case u.ID.String() == authorID:
				// User is the author. No need to send the notification to
				// the author.
				return
			case u.NotificationIsEnabled(ntfnBit):
				// User doesn't have notification bit set
				return
			default:
				// User has the notification bit set. Add them to the email
				// list.
				emails = append(emails, u.Email)
			}
		})
		if err != nil {
			log.Errorf("handleEventRecordEdit: AllUsers: %v", err)
			continue
		}

		// Send notification email
		var (
			token    = e.Record.CensorshipRecord.Token
			version  = e.Record.Version
			name     = proposalName(e.Record)
			username = e.User.Username
		)
		err = p.mailNtfnProposalEdit(token, version, name, username, emails)
		if err != nil {
			log.Errorf("mailNtfnProposaledit: %v", err)
			continue
		}

		log.Debugf("Proposal edit ntfn sent %v", token)
	}
}

func (p *Pi) handleEventRecordSetStatus(ch chan interface{}) {
	for msg := range ch {
		e, ok := msg.(records.EventSetStatus)
		if !ok {
			log.Errorf("handleRecordSetStatus invalid msg: %v", msg)
			continue
		}

		// Unpack args
		var (
			token    = e.Record.CensorshipRecord.Token
			status   = e.Record.Status
			reason   = "" // Populated below
			name     = proposalName(e.Record)
			authorID = userIDFromMetadata(e.Record.Metadata)

			author  *user.User
			uid     uuid.UUID
			ntfnBit = uint64(www.NotificationEmailRegularProposalVetted)
			emails  = make([]string, 0, 256)
		)

		sc, err := statusChangesFromMetadata(e.Record.Metadata)
		if err != nil {
			err = fmt.Errorf("decode status changes: %v", err)
			goto ntfnFailed
		}
		if len(sc) == 0 {
			err = fmt.Errorf("not status changes found %v", token)
			goto ntfnFailed
		}
		reason = sc[len(sc)-1].Reason

		// Verify a notification should be sent
		switch status {
		case rcv1.RecordStatusPublic, rcv1.RecordStatusCensored:
			// The status requires a notification be sent
		default:
			// The status does not require a notification be sent. Listen
			// for next event.
			log.Debugf("Record set status ntfn not needed for %v %v",
				token, rcv1.RecordStatuses[status])
			continue
		}

		// Send author notification
		uid, err = uuid.Parse(authorID)
		if err != nil {
			goto ntfnFailed
		}
		author, err = p.userdb.UserGetById(uid)
		if err != nil {
			err = fmt.Errorf("UserGetById %v: %v", uid, err)
			goto ntfnFailed
		}
		switch {
		case !author.NotificationIsEnabled(ntfnBit):
			// Author does not have notification enabled
			log.Debugf("Record set status ntfn to author not enabled %v", token)

		default:
			// Author does have notification enabled
			err = p.mailNtfnProposalSetStatusToAuthor(token, name,
				status, reason, author.Email)
			if err != nil {
				// Log the error and continue. This error should not prevent
				// the other notifications from being sent.
				log.Errorf("mailNtfnProposalSetStatusToAuthor: %v", err)
				break
			}

			log.Debugf("Record set status ntfn sent to author %v", token)
		}

		// Only send a notification to non-author users if the proposal
		// is being made public.
		if status != rcv1.RecordStatusPublic {
			log.Debugf("Record set status ntfn to users not needed for %v %v",
				token, rcv1.RecordStatuses[status])
			continue
		}

		// Compile user notification email list
		err = p.userdb.AllUsers(func(u *user.User) {
			switch {
			case u.ID.String() == author.ID.String():
				// User is the author. The author is sent a different
				// notification. Don't include them in the users list.
				return
			case !u.NotificationIsEnabled(ntfnBit):
				// User does not have notification bit set
				return
			default:
				// Add user to notification list
				emails = append(emails, u.Email)
			}
		})
		if err != nil {
			err = fmt.Errorf("AllUsers: %v", err)
			goto ntfnFailed
		}

		// Send user notifications
		err = p.mailNtfnProposalSetStatus(token, name, status, emails)
		if err != nil {
			err = fmt.Errorf("mailNtfnProposalSetStatus: %v", err)
			goto ntfnFailed
		}

		log.Debugf("Record set status ntfn sent to users %v", token)

	ntfnFailed:
		log.Errorf("handleEventRecordSetStatus %v %v: %v",
			token, rcv1.RecordStatuses[status], err)
		continue
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

// userMetadataDecode decodes and returns the UserMetadata from the provided
// metadata streams. If a UserMetadata is not found, nil is returned.
func userMetadataDecode(ms []rcv1.MetadataStream) (*usermd.UserMetadata, error) {
	var userMD *usermd.UserMetadata
	for _, v := range ms {
		if v.ID == usermd.MDStreamIDUserMetadata {
			var um usermd.UserMetadata
			err := json.Unmarshal([]byte(v.Payload), &um)
			if err != nil {
				return nil, err
			}
			userMD = &um
			break
		}
	}
	return userMD, nil
}

// userIDFromMetadata searches for a UserMetadata and parses the user ID from
// it if found. An empty string is returned if no UserMetadata is found.
func userIDFromMetadata(ms []rcv1.MetadataStream) string {
	um, err := userMetadataDecode(ms)
	if err != nil {
		return ""
	}
	if um == nil {
		return ""
	}
	return um.UserID
}

// proposalName parses the proposal name from the ProposalMetadata file and
// returns it. An empty string will be returned if any errors occur or if a
// name is not found.
func proposalName(r rcv1.Record) string {
	var name string
	for _, v := range r.Files {
		if v.Name == pi.FileNameProposalMetadata {
			b, err := base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				return ""
			}
			var pm pi.ProposalMetadata
			err = json.Unmarshal(b, &pm)
			if err != nil {
				return ""
			}
			name = pm.Name
		}
	}
	return name
}

func statusChangesDecode(payload []byte) ([]usermd.StatusChangeMetadata, error) {
	statuses := make([]usermd.StatusChangeMetadata, 0, 16)
	d := json.NewDecoder(strings.NewReader(string(payload)))
	for {
		var sc usermd.StatusChangeMetadata
		err := d.Decode(&sc)
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, err
		}
		statuses = append(statuses, sc)
	}
	return statuses, nil
}

func statusChangesFromMetadata(metadata []rcv1.MetadataStream) ([]usermd.StatusChangeMetadata, error) {
	var (
		sc  []usermd.StatusChangeMetadata
		err error
	)
	for _, v := range metadata {
		if v.ID == usermd.MDStreamIDStatusChanges {
			sc, err = statusChangesDecode([]byte(v.Payload))
			if err != nil {
				return nil, err
			}
		}
	}
	return sc, nil
}
