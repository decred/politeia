// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/decred/politeia/decredplugin"
	pd "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/cache"
	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/database"
)

func convertCastVoteReplyFromDecredPlugin(cvr decredplugin.CastVoteReply) www.CastVoteReply {
	return www.CastVoteReply{
		ClientSignature: cvr.ClientSignature,
		Signature:       cvr.Signature,
		Error:           cvr.Error,
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
	var files []www.File
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
	// ResultVotes, UserID, and Username are filled in as zero
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

func convertVoteResultsReplyFromDecred(vrr decredplugin.VoteResultsReply) (www.StartVote, []www.CastVote) {
	sv := convertStartVoteFromDecred(vrr.StartVote)
	cv := convertCastVotesFromDecred(vrr.CastVotes)
	return sv, cv
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

func convertInvoiceFileFromWWW(f *www.File) []pd.File {
	return []pd.File{{
		Name:    "invoice.csv",
		MIME:    "text/plain; charset=utf-8",
		Digest:  f.Digest,
		Payload: f.Payload,
	}}
}

func convertInvoiceCensorFromWWW(f www.CensorshipRecord) pd.CensorshipRecord {
	return pd.CensorshipRecord{
		Token:     f.Token,
		Merkle:    f.Merkle,
		Signature: f.Signature,
	}
}

func convertInvoiceCensorFromPD(f pd.CensorshipRecord) www.CensorshipRecord {
	return www.CensorshipRecord{
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
func convertDatabaseInvoiceToInvoiceRecord(dbInvoice database.Invoice) (*cms.InvoiceRecord, error) {
	invRec := &cms.InvoiceRecord{}
	invRec.Status = dbInvoice.Status
	invRec.Timestamp = dbInvoice.Timestamp
	invRec.UserID = dbInvoice.UserID
	invRec.Month = dbInvoice.Month
	invRec.Year = dbInvoice.Year
	invRec.PublicKey = dbInvoice.PublicKey
	invRec.Version = dbInvoice.Version
	return invRec, nil
}

func convertRecordToDatabaseInvoice(p pd.Record) (*database.Invoice, error) {
	dbInvoice := database.Invoice{
		Files:           convertRecordFilesToWWW(p.Files),
		Token:           p.CensorshipRecord.Token,
		ServerSignature: p.CensorshipRecord.Signature,
		Version:         p.Version,
	}
	for _, m := range p.Metadata {
		switch m.ID {
		case mdStreamGeneral:
			var mdGeneral BackendInvoiceMetadata
			err := json.Unmarshal([]byte(m.Payload), &mdGeneral)
			if err != nil {
				return nil, fmt.Errorf("could not decode metadata '%v' token '%v': %v",
					p.Metadata, p.CensorshipRecord.Token, err)
			}

			dbInvoice.Month = mdGeneral.Month
			dbInvoice.Year = mdGeneral.Year
			dbInvoice.Timestamp = mdGeneral.Timestamp
			dbInvoice.PublicKey = mdGeneral.PublicKey
			dbInvoice.UserSignature = mdGeneral.Signature

			/*dbInvoice.UserID, err = c.db.GetUserIdByPublicKey(mdGeneral.PublicKey)
			if err != nil {
				return nil, fmt.Errorf("could not get user id from public key %v",
					mdGeneral.PublicKey)
			}
			*/
			dbInvoice.LineItems, err = parseCSVFileToLineItems(p.CensorshipRecord.Token, dbInvoice.Files[0])
			if err != nil {
				return nil, fmt.Errorf("could not parse invoice csv data for token '%v': %v",
					p.CensorshipRecord.Token, err)
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

func parseCSVFileToLineItems(invoiceToken string, file www.File) ([]database.LineItem, error) {

	data, err := base64.StdEncoding.DecodeString(file.Payload)
	if err != nil {
		return nil, err
	}

	// Validate that the invoice is CSV-formatted.
	csvReader := csv.NewReader(strings.NewReader(string(data)))
	csvReader.Comma = www.PolicyInvoiceFieldDelimiterChar
	csvReader.Comment = www.PolicyInvoiceCommentChar
	csvReader.TrimLeadingSpace = true

	csvFields, err := csvReader.ReadAll()
	if err != nil {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusMalformedInvoiceFile,
		}
	}
	dbLineItems := []database.LineItem{}
	for lineNum, lineContents := range csvFields {
		dbLineItem := database.LineItem{}
		if len(lineContents) != www.PolicyInvoiceLineItemCount {
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusMalformedInvoiceFile,
			}
		}
		dbLineItem.LineNumber = uint16(lineNum)
		dbLineItem.InvoiceToken = invoiceToken
		dbLineItem.Type = lineContents[0]
		dbLineItem.Subtype = lineContents[1]
		dbLineItem.Description = lineContents[2]
		dbLineItem.ProposalURL = lineContents[3]
		hours, err := strconv.Atoi(lineContents[4])
		if err != nil {
			return nil, err

		}
		dbLineItem.Hours = uint16(hours)
		cost, err := strconv.Atoi(lineContents[5])
		if err != nil {
			return nil, err

		}
		dbLineItem.TotalCost = uint16(cost)
		dbLineItems = append(dbLineItems, dbLineItem)
	}

	return dbLineItems, nil
}
