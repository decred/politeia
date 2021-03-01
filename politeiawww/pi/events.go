// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	pdv1 "github.com/decred/politeia/politeiad/api/v1"
	cmplugin "github.com/decred/politeia/politeiad/plugins/comments"
	"github.com/decred/politeia/politeiad/plugins/usermd"
	cmv1 "github.com/decred/politeia/politeiawww/api/comments/v1"
	piv1 "github.com/decred/politeia/politeiawww/api/pi/v1"
	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
	tkv1 "github.com/decred/politeia/politeiawww/api/ticketvote/v1"
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
	go p.handleEventVoteStarted(ch)
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
			emails  = make([]string, 0, 1024)
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
			name  = proposalNameFromRecord(e.Record)
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
			emails   = make([]string, 0, 1024)
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
			name     = proposalNameFromRecord(e.Record)
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

func (p *Pi) ntfnRecordSetStatusToAuthor(r rcv1.Record) error {
	// Unpack args
	var (
		token    = r.CensorshipRecord.Token
		status   = r.Status
		name     = proposalNameFromRecord(r)
		authorID = userIDFromMetadata(r.Metadata)
	)

	// Parse the status change reason
	sc, err := statusChangesFromMetadata(r.Metadata)
	if err != nil {
		return fmt.Errorf("decode status changes: %v", err)
	}
	if len(sc) == 0 {
		return fmt.Errorf("not status changes found %v", token)
	}
	reason := sc[len(sc)-1].Reason

	// Get author
	uid, err := uuid.Parse(authorID)
	if err != nil {
		return err
	}
	author, err := p.userdb.UserGetById(uid)
	if err != nil {
		return fmt.Errorf("UserGetById %v: %v", uid, err)
	}

	// Send notification to author
	ntfnBit := uint64(www.NotificationEmailRegularProposalVetted)
	if !author.NotificationIsEnabled(ntfnBit) {
		// Author does not have notification enabled
		log.Debugf("Record set status ntfn to author not enabled %v", token)
		return nil
	}

	// Author has notification enabled
	err = p.mailNtfnProposalSetStatusToAuthor(token, name,
		status, reason, author.Email)
	if err != nil {
		return fmt.Errorf("mailNtfnProposalSetStatusToAuthor: %v", err)
	}

	log.Debugf("Record set status ntfn to author sent %v", token)

	return nil
}

func (p *Pi) ntfnRecordSetStatus(r rcv1.Record) error {
	// Unpack args
	var (
		token    = r.CensorshipRecord.Token
		status   = r.Status
		name     = proposalNameFromRecord(r)
		authorID = userIDFromMetadata(r.Metadata)
	)

	// Compile user notification email list
	var (
		emails  = make([]string, 0, 1024)
		ntfnBit = uint64(www.NotificationEmailRegularProposalVetted)
	)
	err := p.userdb.AllUsers(func(u *user.User) {
		switch {
		case u.ID.String() == authorID:
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
		return fmt.Errorf("AllUsers: %v", err)
	}

	// Send user notifications
	err = p.mailNtfnProposalSetStatus(token, name, status, emails)
	if err != nil {
		return fmt.Errorf("mailNtfnProposalSetStatus: %v", err)
	}

	log.Debugf("Record set status ntfn to users sent %v", token)

	return nil
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
			token  = e.Record.CensorshipRecord.Token
			status = e.Record.Status
		)

		// Verify a notification should be sent
		switch status {
		case rcv1.RecordStatusPublic, rcv1.RecordStatusCensored:
			// Status requires a notification be sent
		default:
			// Status does not require a notification be sent
			log.Debugf("Record set status ntfn not needed for %v status %v",
				rcv1.RecordStatuses[status], token)
			continue
		}

		// Send notification to the author
		err := p.ntfnRecordSetStatusToAuthor(e.Record)
		if err != nil {
			// Log the error and continue. This error should not prevent
			// the other notifications from attempting to be sent.
			log.Errorf("ntfnRecordSetStatusToAuthor: %v", err)
		}

		// Only send a notification to non-author users if the proposal
		// is being made public.
		if status != rcv1.RecordStatusPublic {
			log.Debugf("Record set status ntfn to users not needed for %v status %v",
				rcv1.RecordStatuses[status], token)
			continue
		}

		// Send notification to the users
		err = p.ntfnRecordSetStatus(e.Record)
		if err != nil {
			log.Errorf("ntfnRecordSetStatus: %v", err)
			continue
		}

		// Notifications sent!
		continue
	}
}

func (p *Pi) ntfnCommentNewProposalAuthor(c cmv1.Comment, proposalAuthorID, proposalName string) error {
	// Get the proposal author
	uid, err := uuid.Parse(proposalAuthorID)
	if err != nil {
		return err
	}
	pauthor, err := p.userdb.UserGetById(uid)
	if err != nil {
		return fmt.Errorf("UserGetByID %v: %v", uid.String(), err)
	}

	// Check if notification should be sent
	ntfnBit := uint64(www.NotificationEmailCommentOnMyProposal)
	switch {
	case c.Username == pauthor.Username:
		// Author commented on their own proposal
		log.Debugf("Comment ntfn to proposal author not needed %v", c.Token)
		return nil
	case !pauthor.NotificationIsEnabled(ntfnBit):
		// Author does not have notification bit set on
		log.Debugf("Comment ntfn to proposal author not enabled %v", c.Token)
		return nil
	}

	// Send notification email
	err = p.mailNtfnCommentNewToProposalAuthor(c.Token, c.CommentID,
		c.Username, proposalName, pauthor.Email)
	if err != nil {
		return err
	}

	log.Debugf("Comment new ntfn to proposal author sent %v", c.Token)

	return nil
}

func (p *Pi) ntfnCommentReply(state string, c cmv1.Comment, proposalName string) error {
	// Verify there is work to do. This notification only applies to
	// reply comments.
	if c.ParentID == 0 {
		log.Debugf("Comment reply ntfn not needed %v", c.Token)
		return nil
	}

	// Get the parent comment author
	g := cmplugin.Get{
		CommentIDs: []uint32{c.ParentID},
	}
	cs, err := p.politeiad.CommentsGet(context.Background(), state, c.Token, g)
	if err != nil {
		return err
	}
	parent, ok := cs[c.ParentID]
	if !ok {
		return fmt.Errorf("parent comment %v not found", c.ParentID)
	}
	userID, err := uuid.Parse(parent.UserID)
	if err != nil {
		return err
	}
	pauthor, err := p.userdb.UserGetById(userID)
	if err != nil {
		return err
	}

	// Check if notification should be sent
	ntfnBit := uint64(www.NotificationEmailCommentOnMyComment)
	switch {
	case c.UserID == pauthor.ID.String():
		// Author replied to their own comment
		log.Debugf("Comment reply ntfn to parent author not needed %v", c.Token)
		return nil
	case !pauthor.NotificationIsEnabled(ntfnBit):
		// Author does not have notification bit set
		log.Debugf("Comment reply ntfn to parent author not enabled %v", c.Token)
		return nil
	}

	// Send notification email
	err = p.mailNtfnCommentReply(c.Token, c.CommentID,
		c.Username, proposalName, pauthor.Email)
	if err != nil {
		return err
	}

	log.Debugf("Comment reply ntfn to parent author sent %v", c.Token)

	return nil
}

func (p *Pi) handleEventCommentNew(ch chan interface{}) {
	for msg := range ch {
		e, ok := msg.(comments.EventNew)
		if !ok {
			log.Errorf("handleEventCommentNew invalid msg: %v", msg)
			continue
		}

		// Get the record author and record name
		var (
			pdr              *pdv1.Record
			r                rcv1.Record
			proposalAuthorID string
			proposalName     string
			err              error
		)
		pdr, err = p.recordAbridged(e.State, e.Comment.Token)
		if err != nil {
			goto failed
		}
		r = convertRecordToV1(*pdr, e.State)
		proposalAuthorID = userIDFromMetadata(r.Metadata)
		proposalName = proposalNameFromRecord(r)

		// Notify the proposal author
		err = p.ntfnCommentNewProposalAuthor(e.Comment,
			proposalAuthorID, proposalName)
		if err != nil {
			// Log error and continue. This error should not prevent the
			// other notifications from attempting to be sent.
			log.Errorf("ntfnCommentNewProposalAuthor: %v", err)
		}

		// Notify the parent comment author
		err = p.ntfnCommentReply(e.State, e.Comment, proposalName)
		if err != nil {
			err = fmt.Errorf("ntfnCommentReply: %v", err)
			goto failed
		}

		// Notifications sent!
		continue

	failed:
		log.Errorf("handleEventCommentNew: %v", err)
		continue
	}
}

func (p *Pi) handleEventVoteAuthorized(ch chan interface{}) {
	for msg := range ch {
		e, ok := msg.(ticketvote.EventAuthorize)
		if !ok {
			log.Errorf("handleEventVoteAuthorized invalid msg: %v", msg)
			continue
		}

		// Verify there is work to do. We don't need to send a
		// notification on revocations.
		if e.Auth.Action != tkv1.AuthActionAuthorize {
			log.Debugf("Vote authorize ntfn to admin not needed %v", e.Auth.Token)
			continue
		}

		// Setup args to prevent goto errors
		var (
			state        = rcv1.RecordStateVetted
			token        = e.Auth.Token
			proposalName string
			r            rcv1.Record
			emails       = make([]string, 0, 1024)
			ntfnBit      = uint64(www.NotificationEmailAdminProposalVoteAuthorized)
			err          error
		)

		// Get record
		pdr, err := p.recordAbridged(state, token)
		if err != nil {
			goto failed
		}
		r = convertRecordToV1(*pdr, state)
		proposalName = proposalNameFromRecord(r)

		// Compile notification email list
		err = p.userdb.AllUsers(func(u *user.User) {
			switch {
			case !u.Admin:
				// Only notify admin users
				return
			case !u.NotificationIsEnabled(ntfnBit):
				// Admin does not have notfication enabled
				return
			default:
				// Admin has notification enabled
				emails = append(emails, u.Email)
			}
		})
		if err != nil {
			err = fmt.Errorf("AllUsers: %v", err)
			goto failed
		}

		// Send notification email
		err = p.mailNtfnVoteAuthorized(token, proposalName, emails)
		if err != nil {
			err = fmt.Errorf("mailNtfnVoteAuthorized: %v", err)
			goto failed
		}

		log.Debugf("Vote authorized ntfn to admin sent %v", e.Auth.Token)
		continue

	failed:
		log.Errorf("handleEventVoteAuthorized: %v", err)
		continue
	}
}

func (p *Pi) ntfnVoteStartedToAuthor(sd tkv1.StartDetails, authorID, proposalName string) error {
	var (
		token   = sd.Params.Token
		ntfnBit = uint64(www.NotificationEmailRegularProposalVoteStarted)
	)

	// Get record author
	uid, err := uuid.Parse(authorID)
	if err != nil {
		return err
	}
	author, err := p.userdb.UserGetById(uid)
	if err != nil {
		return fmt.Errorf("UserGetByID %v: %v", authorID, err)
	}

	// Verify author notification settings
	if !author.NotificationIsEnabled(ntfnBit) {
		log.Debugf("Vote started ntfn to author not enabled %v", token)
		return nil
	}

	// Send notification to author
	err = p.mailNtfnVoteStartedToAuthor(token, proposalName, author.Email)
	if err != nil {
		return err
	}

	log.Debugf("Vote started ntfn to author sent %v", token)

	return nil
}

func (p *Pi) ntfnVoteStarted(sd tkv1.StartDetails, eventUser user.User, authorID, proposalName string) error {
	var (
		token   = sd.Params.Token
		ntfnBit = uint64(www.NotificationEmailRegularProposalVoteStarted)
	)

	// Compile user notification list
	emails := make([]string, 0, 1024)
	err := p.userdb.AllUsers(func(u *user.User) {
		switch {
		case u.ID.String() == eventUser.ID.String():
			// Don't send a notification to the user that sent the request
			// to start the vote.
			return
		case u.ID.String() == authorID:
			// Don't send the notification to the author. They are sent a
			// seperate notification.
			return
		case !u.NotificationIsEnabled(ntfnBit):
			// User does not have notification bit set
			return
		default:
			// User has notification bit set
			emails = append(emails, u.Email)
		}
	})
	if err != nil {
		return fmt.Errorf("AllUsers: %v", err)
	}

	// Email users
	err = p.mailNtfnVoteStarted(token, proposalName, emails)
	if err != nil {
		return fmt.Errorf("mailNtfnVoteStarted: %v", err)
	}

	log.Debugf("Vote started ntfn to users sent %v", token)

	return nil
}

func (p *Pi) handleEventVoteStarted(ch chan interface{}) {
	for msg := range ch {
		e, ok := msg.(ticketvote.EventStart)
		if !ok {
			log.Errorf("handleEventVoteStarted invalid msg: %v", msg)
			continue
		}

		for _, v := range e.Starts {
			// Setup args to prevent goto errors
			var (
				state = rcv1.RecordStateVetted
				token = v.Params.Token

				pdr *pdv1.Record
				r   rcv1.Record
				err error

				authorID     string
				proposalName string
			)
			pdr, err = p.recordAbridged(state, token)
			if err != nil {
				goto failed
			}
			r = convertRecordToV1(*pdr, state)
			authorID = userIDFromMetadata(r.Metadata)
			proposalName = proposalNameFromRecord(r)

			// Send notification to record author
			err = p.ntfnVoteStartedToAuthor(v, authorID, proposalName)
			if err != nil {
				// Log the error and continue. This error should not prevent
				// the other notifications from attempting to be sent.
				log.Errorf("ntfnVoteStartedToAuthor: %v", err)
			}

			// Send notification to users
			err = p.ntfnVoteStarted(v, e.User, authorID, proposalName)
			if err != nil {
				err = fmt.Errorf("ntfnVoteStarted: %v", err)
				goto failed
			}

			// Notifications sent!
			continue

		failed:
			log.Errorf("handleVoteStarted %v: %v", token, err)
			continue
		}
	}
}

func (p *Pi) records(state string, reqs []pdv1.RecordRequest) (map[string]pdv1.Record, error) {
	var (
		records map[string]pdv1.Record
		err     error
	)
	switch state {
	case rcv1.RecordStateUnvetted:
		records, err = p.politeiad.GetUnvettedBatch(context.Background(), reqs)
		if err != nil {
			return nil, err
		}
	case rcv1.RecordStateVetted:
		records, err = p.politeiad.GetVettedBatch(context.Background(), reqs)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("invalid state %v", state)
	}

	return records, nil
}

// recordAbridged returns a proposal record without its index file or any
// attachment files. This allows the request to be light weight.
func (p *Pi) recordAbridged(state, token string) (*pdv1.Record, error) {
	reqs := []pdv1.RecordRequest{
		{
			Token: token,
			Filenames: []string{
				piv1.FileNameProposalMetadata,
				piv1.FileNameVoteMetadata,
			},
		},
	}
	rs, err := p.records(state, reqs)
	if err != nil {
		return nil, fmt.Errorf("politeiad records: %v", err)
	}
	r, ok := rs[token]
	if !ok {
		return nil, fmt.Errorf("record not found %v", token)
	}
	return &r, nil
}

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

// proposalNameFromRecord parses the proposal name from the ProposalMetadata
// file and returns it. An empty string will be returned if any errors occur or
// if a name is not found.
func proposalNameFromRecord(r rcv1.Record) string {
	var name string
	for _, v := range r.Files {
		if v.Name == piv1.FileNameProposalMetadata {
			b, err := base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				return ""
			}
			var pm piv1.ProposalMetadata
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

func convertStatusToV1(s pdv1.RecordStatusT) rcv1.RecordStatusT {
	switch s {
	case pdv1.RecordStatusNotReviewed:
		return rcv1.RecordStatusUnreviewed
	case pdv1.RecordStatusPublic:
		return rcv1.RecordStatusPublic
	case pdv1.RecordStatusCensored:
		return rcv1.RecordStatusCensored
	case pdv1.RecordStatusArchived:
		return rcv1.RecordStatusArchived
	}
	return rcv1.RecordStatusInvalid
}

func convertFilesToV1(f []pdv1.File) []rcv1.File {
	files := make([]rcv1.File, 0, len(f))
	for _, v := range f {
		files = append(files, rcv1.File{
			Name:    v.Name,
			MIME:    v.MIME,
			Digest:  v.Digest,
			Payload: v.Payload,
		})
	}
	return files
}

func convertMetadataStreamsToV1(ms []pdv1.MetadataStream) []rcv1.MetadataStream {
	metadata := make([]rcv1.MetadataStream, 0, len(ms))
	for _, v := range ms {
		metadata = append(metadata, rcv1.MetadataStream{
			PluginID: v.PluginID,
			ID:       v.ID,
			Payload:  v.Payload,
		})
	}
	return metadata
}

func convertRecordToV1(r pdv1.Record, state string) rcv1.Record {
	// User fields that are not part of the politeiad record have
	// been intentionally left blank. These fields must be pulled
	// from the user database.
	return rcv1.Record{
		State:     state,
		Status:    convertStatusToV1(r.Status),
		Version:   r.Version,
		Timestamp: r.Timestamp,
		Username:  "", // Intentionally left blank
		Metadata:  convertMetadataStreamsToV1(r.Metadata),
		Files:     convertFilesToV1(r.Files),
		CensorshipRecord: rcv1.CensorshipRecord{
			Token:     r.CensorshipRecord.Token,
			Merkle:    r.CensorshipRecord.Merkle,
			Signature: r.CensorshipRecord.Signature,
		},
	}
}