// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cms

import (
	"context"
	"fmt"

	pdv2 "github.com/decred/politeia/politeiad/api/v2"
	cmsplugin "github.com/decred/politeia/politeiad/plugins/cms"
	tkplugin "github.com/decred/politeia/politeiad/plugins/ticketvote"
	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
	v1 "github.com/decred/politeia/politeiawww/api/records/v1"
	"github.com/decred/politeia/politeiawww/client"
	"github.com/decred/politeia/politeiawww/legacy/comments"
	"github.com/decred/politeia/politeiawww/legacy/user"
)

const (
	// EventTypeInvoiceStatusUpdated is emitted when an invoice status is
	// updated.
	EventTypeInvoiceStatusUpdated = "invoicestatus-updated"
)

// EventTypeInvoiceStatusUpdated is the event data for EventTypeAuthorize.
type EventInvoiceStatusUpdated struct {
	Token string
	Email string
}

func (c *Cms) setupEventListeners() {
	// Setup process for each event:
	// 1. Create a channel for the event.
	// 2. Register the channel with the event manager.
	// 3. Launch an event handler to listen for events emitted into the
	//    channel by the event manager.

	log.Debugf("Setting up cms event listeners")
	// Setup invoice comment event
	ch := make(chan interface{})
	c.events.Register(comments.EventTypeNew, ch)
	go c.handleEventInvoiceComment(ch)

	// Setup invoice status update event
	ch = make(chan interface{})
	c.events.Register(EventTypeInvoiceStatusUpdated, ch)
	go c.handleEventInvoiceStatusUpdate(ch)
	/*
		// Setup DCC new update event
		ch = make(chan interface{})
		c.events.Register(eventDCCNew, ch)
		go c.handleEventDCCNew(ch)

		// Setup DCC support/oppose event
		ch = make(chan interface{})
		c.events.Register(eventDCCSupportOppose, ch)
		go c.handleEventDCCSupportOppose(ch)
	*/

}

type dataInvoiceComment struct {
	token string // Comment token
	email string // User email
}

func (c *Cms) handleEventInvoiceComment(ch chan interface{}) {
	for msg := range ch {
		d, ok := msg.(dataInvoiceComment)
		if !ok {
			log.Errorf("handleEventInvoiceComment invalid msg: %v", msg)
			continue
		}

		err := c.mailInvoiceNewComment(d.email)
		if err != nil {
			log.Errorf("emailInvoiceNewComment %v: %v", err)
		}

		log.Debugf("Sent invoice comment notification %v", d.token)
	}
}

func (c *Cms) handleEventInvoiceStatusUpdate(ch chan interface{}) {
	for msg := range ch {
		d, ok := msg.(EventInvoiceStatusUpdated)
		if !ok {
			log.Errorf("handleEventInvoiceStatusUpdate invalid msg: %v", msg)
			continue
		}

		err := c.mailInvoiceStatusUpdate(d.Token, d.Email)
		if err != nil {
			log.Errorf("emailInvoiceStatusUpdate %v: %v", err)
		}

		log.Debugf("Sent invoice status update notification %v", d.Token)
	}
}

type dataDCCNew struct {
	token string // DCC token
}

func (c *Cms) handleEventDCCNew(ch chan interface{}) {
	for msg := range ch {
		d, ok := msg.(dataDCCNew)
		if !ok {
			log.Errorf("handleEventDCCNew invalid msg: %v", msg)
			continue
		}

		emails := make([]string, 0, 256)
		err := c.userdb.AllUsers(func(u *user.User) {
			// Check circumstances where we don't notify
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
		if err != nil {
			log.Errorf("handleEventDCCNew: AllUsers: %v", err)
		}

		err = c.mailDCCSubmitted(d.token, emails)
		if err != nil {
			log.Errorf("emailDCCSubmitted %v: %v", err)
		}

		log.Debugf("Sent DCC new notification %v", d.token)
	}
}

type dataDCCSupportOppose struct {
	token string // DCC token
}

func (c *Cms) handleEventDCCSupportOppose(ch chan interface{}) {
	for msg := range ch {
		d, ok := msg.(dataDCCSupportOppose)
		if !ok {
			log.Errorf("handleEventDCCSupportOppose invalid msg: %v", msg)
			continue
		}

		emails := make([]string, 0, 256)
		err := c.userdb.AllUsers(func(u *user.User) {
			// Check circumstances where we don't notify
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
		if err != nil {
			log.Errorf("handleEventDCCSupportOppose: AllUsers: %v", err)
		}

		err = c.mailDCCSupportOppose(d.token, emails)
		if err != nil {
			log.Errorf("emailDCCSupportOppose %v: %v", err)
		}

		log.Debugf("Sent DCC support/oppose notification %v", d.token)
	}
}

// recordAbridged returns a proposal record without its index file or any
// attachment files. This allows the request to be light weight.
func (c *Cms) recordAbridged(token string) (*pdv2.Record, error) {
	reqs := []pdv2.RecordRequest{
		{
			Token: token,
			Filenames: []string{
				cmsplugin.FileNameInvoiceMetadata,
				tkplugin.FileNameVoteMetadata, //  XXX CHANGE TO DCC VOTE
			},
		},
	}
	rs, err := c.politeiad.Records(context.Background(), reqs)
	if err != nil {
		return nil, fmt.Errorf("politeiad records: %v", err)
	}
	r, ok := rs[token]
	if !ok {
		return nil, fmt.Errorf("record not found %v", token)
	}
	return &r, nil
}

// proposalNameFromFiles parses the proposal name from the ProposalMetadata file and
// returns it. An empty string is returned if a proposal name is not found.
func proposalNameFromFiles(files []rcv1.File) string {
	pm, err := client.ProposalMetadataDecode(files)
	if err != nil {
		return ""
	}
	return pm.Name
}

// userIDFromMetadata searches for a UserMetadata and parses the user ID from
// it if found. An empty string is returned if no UserMetadata is found.
func userIDFromMetadata(ms []v1.MetadataStream) string {
	um, err := client.UserMetadataDecode(ms)
	if err != nil {
		return ""
	}
	if um == nil {
		return ""
	}
	return um.UserID
}

func convertStateToV1(s pdv2.RecordStateT) rcv1.RecordStateT {
	switch s {
	case pdv2.RecordStateUnvetted:
		return rcv1.RecordStateUnvetted
	case pdv2.RecordStateVetted:
		return rcv1.RecordStateVetted
	}
	return rcv1.RecordStateInvalid
}

func convertStatusToV1(s pdv2.RecordStatusT) rcv1.RecordStatusT {
	switch s {
	case pdv2.RecordStatusUnreviewed:
		return rcv1.RecordStatusUnreviewed
	case pdv2.RecordStatusPublic:
		return rcv1.RecordStatusPublic
	case pdv2.RecordStatusCensored:
		return rcv1.RecordStatusCensored
	case pdv2.RecordStatusArchived:
		return rcv1.RecordStatusArchived
	}
	return rcv1.RecordStatusInvalid
}

func convertFilesToV1(f []pdv2.File) []rcv1.File {
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

func convertMetadataStreamsToV1(ms []pdv2.MetadataStream) []rcv1.MetadataStream {
	metadata := make([]rcv1.MetadataStream, 0, len(ms))
	for _, v := range ms {
		metadata = append(metadata, rcv1.MetadataStream{
			PluginID: v.PluginID,
			StreamID: v.StreamID,
			Payload:  v.Payload,
		})
	}
	return metadata
}

func convertRecordToV1(r pdv2.Record) rcv1.Record {
	// User fields that are not part of the politeiad record have
	// been intentionally left blank. These fields must be pulled
	// from the user database.
	return rcv1.Record{
		State:     convertStateToV1(r.State),
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
