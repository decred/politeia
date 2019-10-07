// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/decred/politeia/decredplugin"
	pd "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/cache"
	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/cmsdatabase"
)

func convertCastVoteReplyFromDecredPlugin(cvr decredplugin.CastVoteReply) www.CastVoteReply {
	return www.CastVoteReply{
		ClientSignature: cvr.ClientSignature,
		Signature:       cvr.Signature,
		Error:           cvr.Error,
		ErrorStatus:     cvr.ErrorStatus,
	}
}

func convertCastVoteFromWWW(b www.CastVote) decredplugin.CastVote {
	return decredplugin.CastVote{
		Token:     b.Token,
		Ticket:    b.Ticket,
		VoteBit:   b.VoteBit,
		Signature: b.Signature,
	}
}

func convertBallotFromWWW(b www.Ballot) decredplugin.Ballot {
	br := decredplugin.Ballot{
		Votes: make([]decredplugin.CastVote, 0, len(b.Votes)),
	}
	for _, v := range b.Votes {
		br.Votes = append(br.Votes, convertCastVoteFromWWW(v))
	}
	return br
}

func convertBallotReplyFromDecredPlugin(b decredplugin.BallotReply) www.BallotReply {
	br := www.BallotReply{
		Receipts: make([]www.CastVoteReply, 0, len(b.Receipts)),
	}
	for _, v := range b.Receipts {
		br.Receipts = append(br.Receipts,
			convertCastVoteReplyFromDecredPlugin(v))
	}
	return br
}

func convertVoteOptionFromWWW(vo www.VoteOption) decredplugin.VoteOption {
	return decredplugin.VoteOption{
		Id:          vo.Id,
		Description: vo.Description,
		Bits:        vo.Bits,
	}
}

func convertVoteOptionsFromWWW(vo []www.VoteOption) []decredplugin.VoteOption {
	vor := make([]decredplugin.VoteOption, 0, len(vo))
	for _, v := range vo {
		vor = append(vor, convertVoteOptionFromWWW(v))
	}
	return vor
}

func convertVoteFromWWW(v www.Vote) decredplugin.Vote {
	return decredplugin.Vote{
		Token:            v.Token,
		Mask:             v.Mask,
		Duration:         v.Duration,
		QuorumPercentage: v.QuorumPercentage,
		PassPercentage:   v.PassPercentage,
		Options:          convertVoteOptionsFromWWW(v.Options),
	}
}

func convertAuthorizeVoteFromWWW(av www.AuthorizeVote) decredplugin.AuthorizeVote {
	return decredplugin.AuthorizeVote{
		Action:    av.Action,
		Token:     av.Token,
		PublicKey: av.PublicKey,
		Signature: av.Signature,
	}
}

func convertStartVoteFromWWW(sv www.StartVote) decredplugin.StartVote {
	return decredplugin.StartVote{
		PublicKey: sv.PublicKey,
		Vote:      convertVoteFromWWW(sv.Vote),
		Signature: sv.Signature,
	}
}

func convertPropStatusFromWWW(s www.PropStatusT) pd.RecordStatusT {
	switch s {
	case www.PropStatusNotFound:
		return pd.RecordStatusNotFound
	case www.PropStatusNotReviewed:
		return pd.RecordStatusNotReviewed
	case www.PropStatusCensored:
		return pd.RecordStatusCensored
	case www.PropStatusPublic:
		return pd.RecordStatusPublic
	case www.PropStatusAbandoned:
		return pd.RecordStatusArchived
	}
	return pd.RecordStatusInvalid
}

func convertPropFileFromWWW(f www.File) pd.File {
	return pd.File{
		Name:    f.Name,
		MIME:    f.MIME,
		Digest:  f.Digest,
		Payload: f.Payload,
	}
}

func convertPropFilesFromWWW(f []www.File) []pd.File {
	files := make([]pd.File, 0, len(f))
	for _, v := range f {
		files = append(files, convertPropFileFromWWW(v))
	}
	return files
}

func convertPropStatusFromPD(s pd.RecordStatusT) www.PropStatusT {
	switch s {
	case pd.RecordStatusNotFound:
		return www.PropStatusNotFound
	case pd.RecordStatusNotReviewed:
		return www.PropStatusNotReviewed
	case pd.RecordStatusCensored:
		return www.PropStatusCensored
	case pd.RecordStatusPublic:
		return www.PropStatusPublic
	case pd.RecordStatusUnreviewedChanges:
		return www.PropStatusUnreviewedChanges
	case pd.RecordStatusArchived:
		return www.PropStatusAbandoned
	}
	return www.PropStatusInvalid
}

func convertPropCensorFromPD(f pd.CensorshipRecord) www.CensorshipRecord {
	return www.CensorshipRecord{
		Token:     f.Token,
		Merkle:    f.Merkle,
		Signature: f.Signature,
	}
}

func convertPropCensorFromWWW(f www.CensorshipRecord) pd.CensorshipRecord {
	return pd.CensorshipRecord{
		Token:     f.Token,
		Merkle:    f.Merkle,
		Signature: f.Signature,
	}
}

func convertErrorStatusFromPD(s int) www.ErrorStatusT {
	switch pd.ErrorStatusT(s) {
	case pd.ErrorStatusInvalidFileDigest:
		return www.ErrorStatusInvalidFileDigest
	case pd.ErrorStatusInvalidBase64:
		return www.ErrorStatusInvalidBase64
	case pd.ErrorStatusInvalidMIMEType:
		return www.ErrorStatusInvalidMIMEType
	case pd.ErrorStatusUnsupportedMIMEType:
		return www.ErrorStatusUnsupportedMIMEType
	case pd.ErrorStatusInvalidRecordStatusTransition:
		return www.ErrorStatusInvalidPropStatusTransition
	case pd.ErrorStatusInvalidFilename:
		return www.ErrorStatusInvalidFilename

		// These cases are intentionally omitted because
		// they are indicative of some internal server error,
		// so ErrorStatusInvalid is returned.
		//
		//case pd.ErrorStatusInvalidRequestPayload
		//case pd.ErrorStatusInvalidChallenge
	}
	return www.ErrorStatusInvalid
}

func convertPropStatusToState(status www.PropStatusT) www.PropStateT {
	switch status {
	case www.PropStatusNotReviewed, www.PropStatusUnreviewedChanges,
		www.PropStatusCensored:
		return www.PropStateUnvetted
	case www.PropStatusPublic, www.PropStatusAbandoned:
		return www.PropStateVetted
	}
	return www.PropStateInvalid
}

func convertPropStatusFromCache(s cache.RecordStatusT) www.PropStatusT {
	switch s {
	case cache.RecordStatusNotFound:
		return www.PropStatusNotFound
	case cache.RecordStatusNotReviewed:
		return www.PropStatusNotReviewed
	case cache.RecordStatusCensored:
		return www.PropStatusCensored
	case cache.RecordStatusPublic:
		return www.PropStatusPublic
	case cache.RecordStatusUnreviewedChanges:
		return www.PropStatusUnreviewedChanges
	case cache.RecordStatusArchived:
		return www.PropStatusAbandoned
	}
	return www.PropStatusInvalid
}

func convertPropFromCache(r cache.Record) www.ProposalRecord {
	// Decode markdown stream payloads
	var bpm *BackendProposalMetadata
	var msc []MDStreamChanges
	for _, ms := range r.Metadata {
		// General metadata
		if ms.ID == mdStreamGeneral {
			md, err := decodeBackendProposalMetadata([]byte(ms.Payload))
			if err != nil {
				log.Errorf("convertPropFromCache: decode BackedProposalMetadata "+
					"'%v' token '%v': %v", ms, r.CensorshipRecord.Token, err)
			}
			bpm = md
		}

		// Status change metatdata
		if ms.ID == mdStreamChanges {
			md, err := decodeMDStreamChanges([]byte(ms.Payload))
			if err != nil {
				log.Errorf("convertPropFromCache: decode MDStreamChanges "+
					"'%v' token '%v': %v", ms, r.CensorshipRecord.Token, err)
			}
			msc = md
		}
	}

	// Compile proposal status change metadata
	var (
		changeMsg   string
		publishedAt int64
		censoredAt  int64
		abandonedAt int64
	)
	for _, v := range msc {
		// Overwrite change message because we only need to keep
		// the most recent one.
		changeMsg = v.StatusChangeMessage

		switch convertPropStatusFromPD(v.NewStatus) {
		case www.PropStatusPublic:
			publishedAt = v.Timestamp
		case www.PropStatusCensored:
			censoredAt = v.Timestamp
		case www.PropStatusAbandoned:
			abandonedAt = v.Timestamp
		}
	}

	// Convert files
	files := make([]www.File, 0, len(r.Files))
	for _, f := range r.Files {
		files = append(files,
			www.File{
				Name:    f.Name,
				MIME:    f.MIME,
				Digest:  f.Digest,
				Payload: f.Payload,
			})
	}

	status := convertPropStatusFromCache(r.Status)

	// The UserId, Username, and NumComments fields are returned
	// as zero values since a cache record does not contain that
	// data.
	return www.ProposalRecord{
		Name:                bpm.Name,
		State:               convertPropStatusToState(status),
		Status:              status,
		Timestamp:           r.Timestamp,
		UserId:              "",
		Username:            "",
		PublicKey:           bpm.PublicKey,
		Signature:           bpm.Signature,
		Files:               files,
		NumComments:         0,
		Version:             r.Version,
		StatusChangeMessage: changeMsg,
		PublishedAt:         publishedAt,
		CensoredAt:          censoredAt,
		AbandonedAt:         abandonedAt,
		CensorshipRecord: www.CensorshipRecord{
			Token:     r.CensorshipRecord.Token,
			Merkle:    r.CensorshipRecord.Merkle,
			Signature: r.CensorshipRecord.Signature,
		},
	}
}

func convertNewCommentToDecredPlugin(nc www.NewComment) decredplugin.NewComment {
	return decredplugin.NewComment{
		Token:     nc.Token,
		ParentID:  nc.ParentID,
		Comment:   nc.Comment,
		Signature: nc.Signature,
		PublicKey: nc.PublicKey,
	}
}

func convertLikeCommentToDecred(lc www.LikeComment) decredplugin.LikeComment {
	return decredplugin.LikeComment{
		Token:     lc.Token,
		CommentID: lc.CommentID,
		Action:    lc.Action,
		Signature: lc.Signature,
		PublicKey: lc.PublicKey,
	}
}

func convertLikeCommentFromDecred(lc decredplugin.LikeComment) www.LikeComment {
	return www.LikeComment{
		Token:     lc.Token,
		CommentID: lc.CommentID,
		Action:    lc.Action,
		Signature: lc.Signature,
		PublicKey: lc.PublicKey,
	}
}

func convertCensorCommentToDecred(cc www.CensorComment) decredplugin.CensorComment {
	return decredplugin.CensorComment{
		Token:     cc.Token,
		CommentID: cc.CommentID,
		Reason:    cc.Reason,
		Signature: cc.Signature,
		PublicKey: cc.PublicKey,
	}
}

func convertCommentFromDecred(c decredplugin.Comment) www.Comment {
	// Upvotes, Downvotes, UserID, and Username are filled in as zero
	// values since a cache comment does not contain this data.
	return www.Comment{
		Token:       c.Token,
		ParentID:    c.ParentID,
		Comment:     c.Comment,
		Signature:   c.Signature,
		PublicKey:   c.PublicKey,
		CommentID:   c.CommentID,
		Receipt:     c.Receipt,
		Timestamp:   c.Timestamp,
		ResultVotes: 0,
		Upvotes:     0,
		Downvotes:   0,
		UserID:      "",
		Username:    "",
		Censored:    c.Censored,
	}
}

func convertPluginToCache(p Plugin) cache.Plugin {
	settings := make([]cache.PluginSetting, 0, len(p.Settings))
	for _, s := range p.Settings {
		settings = append(settings, cache.PluginSetting{
			Key:   s.Key,
			Value: s.Value,
		})
	}
	return cache.Plugin{
		ID:       p.ID,
		Version:  p.Version,
		Settings: settings,
	}
}

func convertAuthVoteFromDecred(dav decredplugin.AuthorizeVote) (www.AuthorizeVote, www.AuthorizeVoteReply) {
	av := www.AuthorizeVote{
		Action:    dav.Action,
		Token:     dav.Token,
		Signature: dav.Signature,
		PublicKey: dav.PublicKey,
	}

	avr := www.AuthorizeVoteReply{
		Action:  dav.Action,
		Receipt: dav.Receipt,
	}

	return av, avr
}

func convertStartVoteFromDecred(sv decredplugin.StartVote) www.StartVote {
	opts := make([]www.VoteOption, 0, len(sv.Vote.Options))
	for _, v := range sv.Vote.Options {
		opts = append(opts, www.VoteOption{
			Id:          v.Id,
			Description: v.Description,
			Bits:        v.Bits,
		})
	}
	return www.StartVote{
		PublicKey: sv.PublicKey,
		Vote: www.Vote{
			Token:            sv.Vote.Token,
			Mask:             sv.Vote.Mask,
			Duration:         sv.Vote.Duration,
			QuorumPercentage: sv.Vote.QuorumPercentage,
			PassPercentage:   sv.Vote.PassPercentage,
			Options:          opts,
		},
		Signature: sv.Signature,
	}
}

func convertStartVoteReplyFromDecred(svr decredplugin.StartVoteReply) www.StartVoteReply {
	return www.StartVoteReply{
		StartBlockHeight: svr.StartBlockHeight,
		StartBlockHash:   svr.StartBlockHash,
		EndHeight:        svr.EndHeight,
		EligibleTickets:  svr.EligibleTickets,
	}
}

func convertVoteDetailsReplyFromDecred(vdr decredplugin.VoteDetailsReply) VoteDetails {
	av, avr := convertAuthVoteFromDecred(vdr.AuthorizeVote)
	return VoteDetails{
		AuthorizeVote:      av,
		AuthorizeVoteReply: avr,
		StartVote:          convertStartVoteFromDecred(vdr.StartVote),
		StartVoteReply:     convertStartVoteReplyFromDecred(vdr.StartVoteReply),
	}
}

func convertCastVoteFromDecred(cv decredplugin.CastVote) www.CastVote {
	return www.CastVote{
		Token:     cv.Token,
		Ticket:    cv.Ticket,
		VoteBit:   cv.VoteBit,
		Signature: cv.Signature,
	}
}

func convertCastVotesFromDecred(cv []decredplugin.CastVote) []www.CastVote {
	cvr := make([]www.CastVote, 0, len(cv))
	for _, v := range cv {
		cvr = append(cvr, convertCastVoteFromDecred(v))
	}
	return cvr
}

func convertPluginSettingFromPD(ps pd.PluginSetting) PluginSetting {
	return PluginSetting{
		Key:   ps.Key,
		Value: ps.Value,
	}
}

func convertPluginFromPD(p pd.Plugin) Plugin {
	ps := make([]PluginSetting, 0, len(p.Settings))
	for _, v := range p.Settings {
		ps = append(ps, convertPluginSettingFromPD(v))
	}
	return Plugin{
		ID:       p.ID,
		Version:  p.Version,
		Settings: ps,
	}
}
func convertVoteOptionResultsFromDecred(vor []decredplugin.VoteOptionResult) []www.VoteOptionResult {
	r := make([]www.VoteOptionResult, 0, len(vor))
	for _, v := range vor {
		r = append(r, www.VoteOptionResult{
			Option: www.VoteOption{
				Id:          v.ID,
				Description: v.Description,
				Bits:        v.Bits,
			},
			VotesReceived: v.Votes,
		})
	}
	return r
}

func convertTokenInventoryReplyFromDecred(r decredplugin.TokenInventoryReply) www.TokenInventoryReply {
	return www.TokenInventoryReply{
		Pre:        r.Pre,
		Active:     r.Active,
		Approved:   r.Approved,
		Rejected:   r.Rejected,
		Abandoned:  r.Abandoned,
		Unreviewed: r.Unreviewed,
		Censored:   r.Censored,
	}
}

func convertInvoiceCensorFromWWW(f www.CensorshipRecord) pd.CensorshipRecord {
	return pd.CensorshipRecord{
		Token:     f.Token,
		Merkle:    f.Merkle,
		Signature: f.Signature,
	}
}

func convertRecordFileToWWW(f pd.File) www.File {
	return www.File{
		Name:    f.Name,
		MIME:    f.MIME,
		Digest:  f.Digest,
		Payload: f.Payload,
	}
}

func convertRecordFilesToWWW(f []pd.File) []www.File {
	files := make([]www.File, 0, len(f))
	for _, v := range f {
		files = append(files, convertRecordFileToWWW(v))
	}
	return files
}

func convertDatabaseInvoiceToInvoiceRecord(dbInvoice cmsdatabase.Invoice) *cms.InvoiceRecord {
	invRec := &cms.InvoiceRecord{}
	invRec.Status = dbInvoice.Status
	invRec.Timestamp = dbInvoice.Timestamp
	invRec.UserID = dbInvoice.UserID
	invRec.PublicKey = dbInvoice.PublicKey
	invRec.Version = dbInvoice.Version
	invRec.Signature = dbInvoice.UserSignature
	invRec.CensorshipRecord = www.CensorshipRecord{
		Token: dbInvoice.Token,
	}
	invInput := cms.InvoiceInput{
		ContractorContact:  dbInvoice.ContractorContact,
		ContractorRate:     dbInvoice.ContractorRate,
		ContractorName:     dbInvoice.ContractorName,
		ContractorLocation: dbInvoice.ContractorLocation,
		PaymentAddress:     dbInvoice.PaymentAddress,
		Month:              dbInvoice.Month,
		Year:               dbInvoice.Year,
		ExchangeRate:       dbInvoice.ExchangeRate,
	}
	invInputLineItems := make([]cms.LineItemsInput, 0, len(dbInvoice.LineItems))
	for _, dbLineItem := range dbInvoice.LineItems {
		lineItem := cms.LineItemsInput{
			Type:          dbLineItem.Type,
			Domain:        dbLineItem.Domain,
			Subdomain:     dbLineItem.Subdomain,
			Description:   dbLineItem.Description,
			ProposalToken: dbLineItem.ProposalURL,
			Labor:         dbLineItem.Labor,
			Expenses:      dbLineItem.Expenses,
		}
		invInputLineItems = append(invInputLineItems, lineItem)
	}
	invInput.LineItems = invInputLineItems
	invRec.Input = invInput
	invRec.Input.LineItems = invInputLineItems
	return invRec
}

func convertInvoiceRecordToDatabaseInvoice(invRec *cms.InvoiceRecord) *cmsdatabase.Invoice {
	dbInvoice := &cmsdatabase.Invoice{}
	dbInvoice.Status = invRec.Status
	dbInvoice.Timestamp = invRec.Timestamp
	dbInvoice.UserID = invRec.UserID
	dbInvoice.PublicKey = invRec.PublicKey
	dbInvoice.Version = invRec.Version
	dbInvoice.ContractorContact = invRec.Input.ContractorContact
	dbInvoice.ContractorRate = invRec.Input.ContractorRate
	dbInvoice.ContractorName = invRec.Input.ContractorName
	dbInvoice.ContractorLocation = invRec.Input.ContractorLocation
	dbInvoice.PaymentAddress = invRec.Input.PaymentAddress
	dbInvoice.Month = invRec.Input.Month
	dbInvoice.Year = invRec.Input.Year
	dbInvoice.ExchangeRate = invRec.Input.ExchangeRate

	dbInvoice.LineItems = make([]cmsdatabase.LineItem, 0, len(invRec.Input.LineItems))
	for _, lineItem := range invRec.Input.LineItems {
		dbLineItem := cmsdatabase.LineItem{
			Type:        lineItem.Type,
			Domain:      lineItem.Domain,
			Subdomain:   lineItem.Subdomain,
			Description: lineItem.Description,
			ProposalURL: lineItem.ProposalToken,
			Labor:       lineItem.Labor,
			Expenses:    lineItem.Expenses,
		}
		dbInvoice.LineItems = append(dbInvoice.LineItems, dbLineItem)
	}
	return dbInvoice
}

func convertLineItemsToDatabase(token string, l []cms.LineItemsInput) []cmsdatabase.LineItem {
	dl := make([]cmsdatabase.LineItem, 0, len(l))
	for _, v := range l {
		dl = append(dl, cmsdatabase.LineItem{
			InvoiceToken: token,
			Type:         v.Type,
			Domain:       v.Domain,
			Subdomain:    v.Subdomain,
			Description:  v.Description,
			ProposalURL:  v.ProposalToken,
			Labor:        v.Labor,
			Expenses:     v.Expenses,
		})
	}
	return dl
}

func convertDatabaseToLineItems(dl []cmsdatabase.LineItem) []cms.LineItemsInput {
	l := make([]cms.LineItemsInput, 0, len(dl))
	for _, v := range dl {
		l = append(l, cms.LineItemsInput{
			Type:          v.Type,
			Domain:        v.Domain,
			Subdomain:     v.Subdomain,
			Description:   v.Description,
			ProposalToken: v.ProposalURL,
			Labor:         v.Labor,
			Expenses:      v.Expenses,
		})
	}
	return l
}

func convertRecordToDatabaseInvoice(p pd.Record) (*cmsdatabase.Invoice, error) {
	dbInvoice := cmsdatabase.Invoice{
		Files:           convertRecordFilesToWWW(p.Files),
		Token:           p.CensorshipRecord.Token,
		ServerSignature: p.CensorshipRecord.Signature,
		Version:         p.Version,
	}

	// Decode invoice file
	for _, v := range p.Files {
		if v.Name == invoiceFile {
			b, err := base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				return nil, err
			}

			var ii cms.InvoiceInput
			err = json.Unmarshal(b, &ii)
			if err != nil {
				return nil, www.UserError{
					ErrorCode: www.ErrorStatusInvalidInput,
				}
			}

			dbInvoice.Month = ii.Month
			dbInvoice.Year = ii.Year
			dbInvoice.ExchangeRate = ii.ExchangeRate
			dbInvoice.LineItems = convertLineItemsToDatabase(dbInvoice.Token,
				ii.LineItems)
			dbInvoice.ContractorContact = ii.ContractorContact
			dbInvoice.ContractorLocation = ii.ContractorLocation
			dbInvoice.ContractorRate = ii.ContractorRate
			dbInvoice.ContractorName = ii.ContractorName
			dbInvoice.PaymentAddress = ii.PaymentAddress
		}
	}

	for _, m := range p.Metadata {
		switch m.ID {
		case mdStreamInvoiceGeneral:
			var mdGeneral backendInvoiceMetadata
			err := json.Unmarshal([]byte(m.Payload), &mdGeneral)
			if err != nil {
				return nil, fmt.Errorf("could not decode metadata '%v' token '%v': %v",
					p.Metadata, p.CensorshipRecord.Token, err)
			}

			dbInvoice.Timestamp = mdGeneral.Timestamp
			dbInvoice.PublicKey = mdGeneral.PublicKey
			dbInvoice.UserSignature = mdGeneral.Signature

		case mdStreamInvoiceStatusChanges:
			sc, err := decodeBackendInvoiceStatusChanges([]byte(m.Payload))
			if err != nil {
				return nil, fmt.Errorf("could not decode metadata '%v' token '%v': %v",
					m, p.CensorshipRecord.Token, err)
			}

			// We don't need all of the status changes.
			// Just the most recent one.
			for _, s := range sc {
				dbInvoice.Status = s.NewStatus
			}

		default:
			// Log error but proceed
			log.Errorf("initializeInventory: invalid "+
				"metadata stream ID %v token %v",
				m.ID, p.CensorshipRecord.Token)
		}
	}

	return &dbInvoice, nil
}

func convertInvoiceFromCache(r cache.Record) cms.InvoiceRecord {
	// Decode metadata streams
	var md backendInvoiceMetadata
	var c backendInvoiceStatusChange
	for _, v := range r.Metadata {
		switch v.ID {
		case mdStreamInvoiceGeneral:
			// General invoice metadata
			m, err := decodeBackendInvoiceMetadata([]byte(v.Payload))
			if err != nil {
				log.Errorf("convertInvoiceFromCache: decode md stream: "+
					"token:%v error:%v payload:%v",
					r.CensorshipRecord.Token, err, v)
			}
			md = *m

		case mdStreamInvoiceStatusChanges:
			// Invoice status changes
			m, err := decodeBackendInvoiceStatusChanges([]byte(v.Payload))
			if err != nil {
				log.Errorf("convertInvoiceFromCache: decode md stream: "+
					"token:%v error:%v payload:%v",
					r.CensorshipRecord.Token, err, v)
			}

			// We don't need all of the status changes.
			// Just the most recent one.
			for _, s := range m {
				c = s
			}
		}
	}

	// Convert files
	var ii cms.InvoiceInput
	fs := make([]www.File, 0, len(r.Files))
	for _, v := range r.Files {
		f := www.File{
			Name:    v.Name,
			MIME:    v.MIME,
			Digest:  v.Digest,
			Payload: v.Payload,
		}
		fs = append(fs, f)

		// Parse invoice json
		if f.Name == invoiceFile {
			b, err := base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				log.Errorf("convertInvoiceFromCache: decode invoice: "+
					"token:%v error:%v payload:%v",
					r.CensorshipRecord.Token, err, f.Payload)
				continue
			}

			err = json.Unmarshal(b, &ii)
			if err != nil {
				log.Errorf("convertInvoiceFromCache: unmarshal InvoiceInput: "+
					"token:%v error:%v payload:%v",
					r.CensorshipRecord.Token, err, f.Payload)
				continue
			}
		}
	}

	// UserID and Username are left intentionally blank.
	// These fields not part of a cache record.
	return cms.InvoiceRecord{
		Status:             c.NewStatus,
		StatusChangeReason: c.Reason,
		Timestamp:          r.Timestamp,
		UserID:             "",
		Username:           "",
		PublicKey:          md.PublicKey,
		Signature:          md.Signature,
		Files:              fs,
		Version:            r.Version,
		CensorshipRecord: www.CensorshipRecord{
			Token:     r.CensorshipRecord.Token,
			Merkle:    r.CensorshipRecord.Merkle,
			Signature: r.CensorshipRecord.Signature,
		},
		Input: ii,
	}
}

func convertDCCFromCache(r cache.Record) cms.DCCRecord {
	dcc := cms.DCCRecord{}
	// Decode metadata streams
	var md backendDCCMetadata
	var c backendDCCStatusChange
	for _, v := range r.Metadata {
		switch v.ID {
		case mdStreamDCCGeneral:
			// General invoice metadata
			m, err := decodeBackendDCCMetadata([]byte(v.Payload))
			if err != nil {
				log.Errorf("convertDCCFromCache: decode md stream: "+
					"token:%v error:%v payload:%v",
					r.CensorshipRecord.Token, err, v)
			}
			md = *m

		case mdStreamDCCStatusChanges:
			// Invoice status changes
			m, err := decodeBackendDCCStatusChanges([]byte(v.Payload))
			if err != nil {
				log.Errorf("convertDCCFromCache: decode md stream: "+
					"token:%v error:%v payload:%v",
					r.CensorshipRecord.Token, err, v)
			}

			// We don't need all of the status changes.
			// Just the most recent one.
			for _, s := range m {
				c = s
			}
		case mdStreamDCCSupportOpposition:
			// Support and Opposition
			so, err := decodeBackendDCCSupportOppositionMetadata([]byte(v.Payload))
			if err != nil {
				log.Errorf("convertDCCFromCache: decode md stream: "+
					"token:%v error:%v payload:%v",
					r.CensorshipRecord.Token, err, v)
			}
			supportPubkeys := make([]string, 0, len(so))
			opposePubkeys := make([]string, 0, len(so))
			// Tabulate all support and opposition
			for _, s := range so {
				if s.Vote == supportString {
					supportPubkeys = append(supportPubkeys, s.PublicKey)
				} else if s.Vote == opposeString {
					opposePubkeys = append(opposePubkeys, s.PublicKey)
				}
			}
			dcc.SupportUserIDs = supportPubkeys
			dcc.OppositionUserIDs = opposePubkeys
		}
	}

	// Convert files
	var di cms.DCCInput

	var f www.File

	for _, v := range r.Files {
		f = www.File{
			Name:    v.Name,
			MIME:    v.MIME,
			Digest:  v.Digest,
			Payload: v.Payload,
		}

		// Parse invoice json
		if f.Name == dccFile {
			b, err := base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				log.Errorf("convertDCCFromCache: decode dcc: "+
					"token:%v error:%v payload:%v",
					r.CensorshipRecord.Token, err, f.Payload)
				continue
			}

			err = json.Unmarshal(b, &di)
			if err != nil {
				log.Errorf("convertDCCFromCache: unmarshal DCCInput: "+
					"token:%v error:%v payload:%v",
					r.CensorshipRecord.Token, err, f.Payload)
				continue
			}
		}
	}

	dcc.Status = c.NewStatus
	dcc.StatusChangeReason = c.Reason
	dcc.Timestamp = r.Timestamp
	dcc.SponsorUserID = ""
	dcc.SponsorUsername = ""
	dcc.PublicKey = md.PublicKey
	dcc.Signature = md.Signature
	dcc.File = f
	dcc.CensorshipRecord = www.CensorshipRecord{
		Token:     r.CensorshipRecord.Token,
		Merkle:    r.CensorshipRecord.Merkle,
		Signature: r.CensorshipRecord.Signature,
	}
	dcc.DCC = di

	return dcc
}

func convertRecordToDatabaseDCC(p pd.Record) (*cmsdatabase.DCC, error) {
	dbDCC := cmsdatabase.DCC{
		Files:           convertRecordFilesToWWW(p.Files),
		Token:           p.CensorshipRecord.Token,
		ServerSignature: p.CensorshipRecord.Signature,
	}

	// Decode invoice file
	for _, v := range p.Files {
		if v.Name == dccFile {
			b, err := base64.StdEncoding.DecodeString(v.Payload)
			if err != nil {
				return nil, err
			}

			var dcc cms.DCCInput
			err = json.Unmarshal(b, &dcc)
			if err != nil {
				return nil, fmt.Errorf("could not decode DCC input data: token '%v': %v",
					p.CensorshipRecord.Token, err)
			}
			dbDCC.Type = dcc.Type
			dbDCC.NomineeUserID = dcc.NomineeUserID
			dbDCC.SponsorStatement = dcc.SponsorStatement
			dbDCC.Domain = dcc.Domain
			dbDCC.ContractorType = dcc.ContractorType
		}
	}

	for _, m := range p.Metadata {
		switch m.ID {
		case mdStreamDCCGeneral:
			var mdGeneral backendDCCMetadata
			err := json.Unmarshal([]byte(m.Payload), &mdGeneral)
			if err != nil {
				return nil, fmt.Errorf("could not decode metadata '%v' token '%v': %v",
					p.Metadata, p.CensorshipRecord.Token, err)
			}

			dbDCC.Timestamp = mdGeneral.Timestamp
			dbDCC.PublicKey = mdGeneral.PublicKey
			dbDCC.UserSignature = mdGeneral.Signature

		case mdStreamDCCStatusChanges:
			sc, err := decodeBackendDCCStatusChanges([]byte(m.Payload))
			if err != nil {
				return nil, fmt.Errorf("could not decode metadata '%v' token '%v': %v",
					m, p.CensorshipRecord.Token, err)
			}

			// We don't need all of the status changes.
			// Just the most recent one.
			for _, s := range sc {
				dbDCC.Status = s.NewStatus
				dbDCC.StatusChangeReason = s.Reason
			}
		default:
			// Log error but proceed
			log.Errorf("initializeInventory: invalid "+
				"metadata stream ID %v token %v",
				m.ID, p.CensorshipRecord.Token)
		}
	}

	return &dbDCC, nil
}

func convertDCCDatabaseToRecord(dbDCC *cmsdatabase.DCC) cms.DCCRecord {
	dccRecord := cms.DCCRecord{}

	dccRecord.DCC.Type = dbDCC.Type
	dccRecord.DCC.NomineeUserID = dbDCC.NomineeUserID
	dccRecord.DCC.SponsorStatement = dbDCC.SponsorStatement
	dccRecord.DCC.Domain = dbDCC.Domain
	dccRecord.DCC.ContractorType = dbDCC.ContractorType
	dccRecord.Status = dbDCC.Status
	dccRecord.StatusChangeReason = dbDCC.StatusChangeReason
	dccRecord.Timestamp = dbDCC.Timestamp
	dccRecord.CensorshipRecord = www.CensorshipRecord{
		Token: dbDCC.Token,
	}
	dccRecord.PublicKey = dbDCC.PublicKey
	dccRecord.Signature = dbDCC.ServerSignature
	dccRecord.SponsorUserID = dbDCC.SponsorUserID
	supportUserIDs := strings.Split(dbDCC.SupportUserIDs, ",")
	dccRecord.SupportUserIDs = supportUserIDs
	oppositionUserIDs := strings.Split(dbDCC.OppositionUserIDs, ",")
	dccRecord.OppositionUserIDs = oppositionUserIDs

	return dccRecord
}
