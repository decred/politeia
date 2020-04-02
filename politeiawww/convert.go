// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/decred/dcrd/dcrutil"
	"github.com/thi4go/politeia/decredplugin"
	"github.com/thi4go/politeia/mdstream"
	pd "github.com/thi4go/politeia/politeiad/api/v1"
	"github.com/thi4go/politeia/politeiad/cache"
	cms "github.com/thi4go/politeia/politeiawww/api/cms/v1"
	www "github.com/thi4go/politeia/politeiawww/api/www/v1"
	www2 "github.com/thi4go/politeia/politeiawww/api/www/v2"
	"github.com/thi4go/politeia/politeiawww/cmsdatabase"
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

func convertAuthorizeVoteFromWWW(av www.AuthorizeVote) decredplugin.AuthorizeVote {
	return decredplugin.AuthorizeVote{
		Action:    av.Action,
		Token:     av.Token,
		PublicKey: av.PublicKey,
		Signature: av.Signature,
	}
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

func convertVoteOptionV2ToDecred(vo www2.VoteOption) decredplugin.VoteOption {
	return decredplugin.VoteOption{
		Id:          vo.Id,
		Description: vo.Description,
		Bits:        vo.Bits,
	}
}

func convertVoteOptionsV2ToDecred(vo []www2.VoteOption) []decredplugin.VoteOption {
	dvo := make([]decredplugin.VoteOption, 0, len(vo))
	for _, v := range vo {
		dvo = append(dvo, convertVoteOptionV2ToDecred(v))
	}
	return dvo
}

func convertVoteTypeV2ToDecred(v www2.VoteT) decredplugin.VoteT {
	var dv decredplugin.VoteT
	switch v {
	case www2.VoteTypeStandard:
		dv = decredplugin.VoteTypeStandard
	}
	return dv
}

func convertVoteV2ToDecred(v www2.Vote) decredplugin.VoteV2 {
	return decredplugin.VoteV2{
		Token:            v.Token,
		ProposalVersion:  v.ProposalVersion,
		Type:             convertVoteTypeV2ToDecred(v.Type),
		Mask:             v.Mask,
		Duration:         v.Duration,
		QuorumPercentage: v.QuorumPercentage,
		PassPercentage:   v.PassPercentage,
		Options:          convertVoteOptionsV2ToDecred(v.Options),
	}
}

func convertStartVoteV2ToDecred(sv www2.StartVote) decredplugin.StartVoteV2 {
	return decredplugin.StartVoteV2{
		PublicKey: sv.PublicKey,
		Vote:      convertVoteV2ToDecred(sv.Vote),
		Signature: sv.Signature,
	}
}

func convertDecredStartVoteV1ToVoteDetailsReplyV2(sv decredplugin.StartVoteV1, svr decredplugin.StartVoteReply) (*www2.VoteDetailsReply, error) {
	startHeight, err := strconv.ParseUint(svr.StartBlockHeight, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("parse start height '%v': %v",
			svr.StartBlockHeight, err)
	}
	endHeight, err := strconv.ParseUint(svr.EndHeight, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("parse end height '%v': %v",
			svr.EndHeight, err)
	}
	voteb, err := decredplugin.EncodeVoteV1(sv.Vote)
	if err != nil {
		return nil, err
	}
	return &www2.VoteDetailsReply{
		Version:          uint32(sv.Version),
		Vote:             string(voteb),
		PublicKey:        sv.PublicKey,
		Signature:        sv.Signature,
		StartBlockHeight: uint32(startHeight),
		StartBlockHash:   svr.StartBlockHash,
		EndBlockHeight:   uint32(endHeight),
		EligibleTickets:  svr.EligibleTickets,
	}, nil
}

func convertDecredStartVoteV2ToVoteDetailsReplyV2(sv decredplugin.StartVoteV2, svr decredplugin.StartVoteReply) (*www2.VoteDetailsReply, error) {
	startHeight, err := strconv.ParseUint(svr.StartBlockHeight, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("parse start height '%v': %v",
			svr.StartBlockHeight, err)
	}
	endHeight, err := strconv.ParseUint(svr.EndHeight, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("parse end height '%v': %v",
			svr.EndHeight, err)
	}
	voteb, err := decredplugin.EncodeVoteV2(sv.Vote)
	if err != nil {
		return nil, err
	}
	return &www2.VoteDetailsReply{
		Version:          uint32(sv.Version),
		Vote:             string(voteb),
		PublicKey:        sv.PublicKey,
		Signature:        sv.Signature,
		StartBlockHeight: uint32(startHeight),
		StartBlockHash:   svr.StartBlockHash,
		EndBlockHeight:   uint32(endHeight),
		EligibleTickets:  svr.EligibleTickets,
	}, nil
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
	var (
		pg         *mdstream.ProposalGeneral
		statusesV1 []mdstream.RecordStatusChangeV1
		statusesV2 []mdstream.RecordStatusChangeV2
		err        error

		token = r.CensorshipRecord.Token
	)
	for _, ms := range r.Metadata {
		switch ms.ID {
		case mdstream.IDProposalGeneral:
			// General metadata
			pg, err = mdstream.DecodeProposalGeneral([]byte(ms.Payload))
			if err != nil {
				log.Errorf("convertPropFromCache: DecodeProposalGeneral: "+
					"err:%v token:%v mdstream:%v", err, token, ms)
			}

		case mdstream.IDRecordStatusChange:
			// Status change metadata
			b := []byte(ms.Payload)
			statusesV1, statusesV2, err = mdstream.DecodeRecordStatusChanges(b)
			if err != nil {
				log.Errorf("convertPropFromCache: DecodeRecordStatusChanges: "+
					"err:%v token:%v mdstream:%v", err, token, ms)
			}

			// Verify the signatures
			for _, v := range statusesV2 {
				err := v.VerifySignature(token)
				if err != nil {
					// This is not good!
					e := fmt.Sprintf("invalid status change signature: "+
						"token:%v status:%v", token, v)
					panic(e)
				}
			}

		case decredplugin.MDStreamAuthorizeVote:
			// Valid proposal mdstream but not needed for a ProposalRecord
			log.Tracef("convertPropFromCache: skipping mdstream %v",
				decredplugin.MDStreamAuthorizeVote)
		case decredplugin.MDStreamVoteBits:
			// Valid proposal mdstream but not needed for a ProposalRecord
			log.Tracef("convertPropFromCache: skipping mdstream %v",
				decredplugin.MDStreamVoteBits)
		case decredplugin.MDStreamVoteSnapshot:
			// Valid proposal mdstream but not needed for a ProposalRecord
			log.Tracef("convertPropFromCache: skipping mdstream %v",
				decredplugin.MDStreamVoteSnapshot)
		default:
			log.Errorf("convertPropFromCache: invalid mdstream ID: "+
				"token:%v mdstream:%v", token, ms)
		}
	}

	// Compile proposal status change metadata
	var (
		changeMsg          string
		changeMsgTimestamp int64
		publishedAt        int64
		censoredAt         int64
		abandonedAt        int64
	)
	for _, v := range statusesV1 {
		// Keep the most recent status change message. This is what
		// will be returned as part of the ProposalRecord.
		if v.Timestamp > changeMsgTimestamp {
			changeMsg = v.StatusChangeMessage
			changeMsgTimestamp = v.Timestamp
		}

		switch convertPropStatusFromPD(v.NewStatus) {
		case www.PropStatusPublic:
			publishedAt = v.Timestamp
		case www.PropStatusCensored:
			censoredAt = v.Timestamp
		case www.PropStatusAbandoned:
			abandonedAt = v.Timestamp
		}
	}
	for _, v := range statusesV2 {
		// Keep the most recent status change message. This is what
		// will be returned as part of the ProposalRecord.
		if v.Timestamp > changeMsgTimestamp {
			changeMsg = v.StatusChangeMessage
			changeMsgTimestamp = v.Timestamp
		}

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
		Name:                pg.Name,
		State:               convertPropStatusToState(status),
		Status:              status,
		Timestamp:           r.Timestamp,
		UserId:              "",
		Username:            "",
		PublicKey:           pg.PublicKey,
		Signature:           pg.Signature,
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

func convertVoteOptionFromDecred(vo decredplugin.VoteOption) www.VoteOption {
	return www.VoteOption{
		Id:          vo.Id,
		Description: vo.Description,
		Bits:        vo.Bits,
	}
}

func convertVoteOptionsFromDecred(options []decredplugin.VoteOption) []www.VoteOption {
	opts := make([]www.VoteOption, 0, len(options))
	for _, v := range options {
		opts = append(opts, convertVoteOptionFromDecred(v))
	}
	return opts
}

func convertVoteOptionV2FromDecred(vo decredplugin.VoteOption) www2.VoteOption {
	return www2.VoteOption{
		Id:          vo.Id,
		Description: vo.Description,
		Bits:        vo.Bits,
	}
}

func convertVoteOptionsV2FromDecred(options []decredplugin.VoteOption) []www2.VoteOption {
	opts := make([]www2.VoteOption, 0, len(options))
	for _, v := range options {
		opts = append(opts, convertVoteOptionV2FromDecred(v))
	}
	return opts
}

func convertStartVoteV1FromDecred(sv decredplugin.StartVoteV1) www.StartVote {
	return www.StartVote{
		PublicKey: sv.PublicKey,
		Vote: www.Vote{
			Token:            sv.Vote.Token,
			Mask:             sv.Vote.Mask,
			Duration:         sv.Vote.Duration,
			QuorumPercentage: sv.Vote.QuorumPercentage,
			PassPercentage:   sv.Vote.PassPercentage,
			Options:          convertVoteOptionsFromDecred(sv.Vote.Options),
		},
		Signature: sv.Signature,
	}
}

func convertVoteTypeFromDecred(v decredplugin.VoteT) www2.VoteT {
	switch v {
	case decredplugin.VoteTypeStandard:
		return www2.VoteTypeStandard
	}
	return www2.VoteTypeInvalid
}

func convertStartVoteV2FromDecred(sv decredplugin.StartVoteV2) www2.StartVote {
	return www2.StartVote{
		PublicKey: sv.PublicKey,
		Vote: www2.Vote{
			Token:            sv.Vote.Token,
			Type:             convertVoteTypeFromDecred(sv.Vote.Type),
			Mask:             sv.Vote.Mask,
			Duration:         sv.Vote.Duration,
			QuorumPercentage: sv.Vote.QuorumPercentage,
			PassPercentage:   sv.Vote.PassPercentage,
			Options:          convertVoteOptionsV2FromDecred(sv.Vote.Options),
		},
		Signature: sv.Signature,
	}
}

func convertVoteOptionsV2ToV1(optsV2 []www2.VoteOption) []www.VoteOption {
	optsV1 := make([]www.VoteOption, 0, len(optsV2))
	for _, v := range optsV2 {
		optsV1 = append(optsV1, www.VoteOption{
			Id:          v.Id,
			Description: v.Description,
			Bits:        v.Bits,
		})
	}
	return optsV1
}

func convertStartVoteV2ToV1(sv www2.StartVote) www.StartVote {
	return www.StartVote{
		PublicKey: sv.PublicKey,
		Vote: www.Vote{
			Token:            sv.Vote.Token,
			Mask:             sv.Vote.Mask,
			Duration:         sv.Vote.Duration,
			QuorumPercentage: sv.Vote.QuorumPercentage,
			PassPercentage:   sv.Vote.PassPercentage,
			Options:          convertVoteOptionsV2ToV1(sv.Vote.Options),
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

func convertStartVoteReplyV2FromDecred(svr decredplugin.StartVoteReply) (*www2.StartVoteReply, error) {
	startHeight, err := strconv.ParseUint(svr.StartBlockHeight, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("parse start height '%v': %v",
			svr.StartBlockHeight, err)
	}
	endHeight, err := strconv.ParseUint(svr.EndHeight, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("parse end height '%v': %v",
			svr.EndHeight, err)
	}
	return &www2.StartVoteReply{
		StartBlockHeight: uint32(startHeight),
		StartBlockHash:   svr.StartBlockHash,
		EndBlockHeight:   uint32(endHeight),
		EligibleTickets:  svr.EligibleTickets,
	}, nil
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
			SubRate:       dbLineItem.ContractorRate,
		}
		invInputLineItems = append(invInputLineItems, lineItem)
	}
	invInput.LineItems = invInputLineItems
	invRec.Input = invInput
	invRec.Input.LineItems = invInputLineItems
	txIDs := strings.Split(dbInvoice.Payments.TxIDs, ",")
	payment := cms.PaymentInformation{
		Token:           dbInvoice.Payments.InvoiceToken,
		Address:         dbInvoice.Payments.Address,
		TxIDs:           txIDs,
		AmountReceived:  dcrutil.Amount(dbInvoice.Payments.AmountReceived),
		TimeLastUpdated: dbInvoice.Payments.TimeLastUpdated,
	}
	invRec.Payment = payment
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
	dbInvoice.Token = invRec.CensorshipRecord.Token
	dbInvoice.ServerSignature = invRec.Signature

	dbInvoice.LineItems = make([]cmsdatabase.LineItem, 0, len(invRec.Input.LineItems))
	for _, lineItem := range invRec.Input.LineItems {
		dbLineItem := cmsdatabase.LineItem{
			Type:           lineItem.Type,
			Domain:         lineItem.Domain,
			Subdomain:      lineItem.Subdomain,
			Description:    lineItem.Description,
			ProposalURL:    lineItem.ProposalToken,
			Labor:          lineItem.Labor,
			Expenses:       lineItem.Expenses,
			ContractorRate: lineItem.SubRate,
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
			// If subrate is populated, use the existing contractor rate field.
			ContractorRate: v.SubRate,
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
	payout, err := calculatePayout(dbInvoice)
	if err != nil {
		return nil, err
	}
	payment := cmsdatabase.Payments{
		Address:      dbInvoice.PaymentAddress,
		AmountNeeded: int64(payout.DCRTotal),
	}
	for _, m := range p.Metadata {
		switch m.ID {
		case mdstream.IDInvoiceGeneral:
			var mdGeneral mdstream.InvoiceGeneral
			err := json.Unmarshal([]byte(m.Payload), &mdGeneral)
			if err != nil {
				return nil, fmt.Errorf("could not decode metadata '%v' token '%v': %v",
					p.Metadata, p.CensorshipRecord.Token, err)
			}

			dbInvoice.Timestamp = mdGeneral.Timestamp
			dbInvoice.PublicKey = mdGeneral.PublicKey
			dbInvoice.UserSignature = mdGeneral.Signature
		case mdstream.IDInvoiceStatusChange:
			sc, err := mdstream.DecodeInvoiceStatusChange([]byte(m.Payload))
			if err != nil {
				return nil, fmt.Errorf("could not decode metadata '%v' token '%v': %v",
					m, p.CensorshipRecord.Token, err)
			}

			invChanges := make([]cmsdatabase.InvoiceChange, 0, len(sc))
			for _, s := range sc {
				invChange := cmsdatabase.InvoiceChange{
					AdminPublicKey: s.AdminPublicKey,
					NewStatus:      s.NewStatus,
					Reason:         s.Reason,
					Timestamp:      s.Timestamp,
				}
				invChanges = append(invChanges, invChange)
				// Capture information about payments
				dbInvoice.Status = s.NewStatus
				if s.NewStatus == cms.InvoiceStatusApproved {
					payment.Status = cms.PaymentStatusWatching
					payment.TimeStarted = s.Timestamp
				} else if s.NewStatus == cms.InvoiceStatusPaid {
					payment.Status = cms.PaymentStatusPaid
				}
			}
			dbInvoice.Changes = invChanges

		case mdstream.IDInvoicePayment:
			ip, err := mdstream.DecodeInvoicePayment([]byte(m.Payload))
			if err != nil {
				return nil, fmt.Errorf("could not decode metadata '%v' token '%v': %v",
					m, p.CensorshipRecord.Token, err)
			}

			// We don't need all of the payments.
			// Just the most recent one.
			for _, s := range ip {
				payment.TxIDs = s.TxIDs
				payment.TimeLastUpdated = s.Timestamp
				payment.AmountReceived = s.AmountReceived
			}
			dbInvoice.Payments = payment
		default:
			// Log error but proceed
			log.Errorf("initializeInventory: invalid "+
				"metadata stream ID %v token %v",
				m.ID, p.CensorshipRecord.Token)
		}
	}

	return &dbInvoice, nil
}

func convertCacheToDatabaseInvoice(p cache.Record) (*cmsdatabase.Invoice, error) {
	dbInvoice := cmsdatabase.Invoice{
		Token:           p.CensorshipRecord.Token,
		ServerSignature: p.CensorshipRecord.Signature,
		Version:         p.Version,
	}

	fs := make([]www.File, 0, len(p.Files))
	for _, v := range p.Files {
		f := www.File{
			Name:    v.Name,
			MIME:    v.MIME,
			Digest:  v.Digest,
			Payload: v.Payload,
		}
		fs = append(fs, f)
	}
	dbInvoice.Files = fs
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
	payout, err := calculatePayout(dbInvoice)
	if err != nil {
		return nil, err
	}
	payment := cmsdatabase.Payments{
		Address:      dbInvoice.PaymentAddress,
		AmountNeeded: int64(payout.DCRTotal),
	}
	for _, m := range p.Metadata {
		switch m.ID {
		case mdstream.IDRecordStatusChange:
			// Ignore initial stream change since it's just the automatic change from
			// unvetted to vetted
			continue
		case mdstream.IDInvoiceGeneral:
			var mdGeneral mdstream.InvoiceGeneral
			err := json.Unmarshal([]byte(m.Payload), &mdGeneral)
			if err != nil {
				return nil, fmt.Errorf("could not decode metadata '%v' token '%v': %v",
					p.Metadata, p.CensorshipRecord.Token, err)
			}

			dbInvoice.Timestamp = mdGeneral.Timestamp
			dbInvoice.PublicKey = mdGeneral.PublicKey
			dbInvoice.UserSignature = mdGeneral.Signature
		case mdstream.IDInvoiceStatusChange:
			sc, err := mdstream.DecodeInvoiceStatusChange([]byte(m.Payload))
			if err != nil {
				return nil, fmt.Errorf("could not decode metadata '%v' token '%v': %v",
					m, p.CensorshipRecord.Token, err)
			}

			invChanges := make([]cmsdatabase.InvoiceChange, 0, len(sc))
			for _, s := range sc {
				invChange := cmsdatabase.InvoiceChange{
					AdminPublicKey: s.AdminPublicKey,
					NewStatus:      s.NewStatus,
					Reason:         s.Reason,
					Timestamp:      s.Timestamp,
				}
				invChanges = append(invChanges, invChange)
				// Capture information about payments
				dbInvoice.Status = s.NewStatus
				if s.NewStatus == cms.InvoiceStatusApproved {
					payment.Status = cms.PaymentStatusWatching
					payment.TimeStarted = s.Timestamp
				} else if s.NewStatus == cms.InvoiceStatusPaid {
					payment.Status = cms.PaymentStatusPaid
				}
			}
			dbInvoice.Changes = invChanges

		case mdstream.IDInvoicePayment:
			ip, err := mdstream.DecodeInvoicePayment([]byte(m.Payload))
			if err != nil {
				return nil, fmt.Errorf("could not decode metadata '%v' token '%v': %v",
					m, p.CensorshipRecord.Token, err)
			}

			// We don't need all of the payments.
			// Just the most recent one.
			for _, s := range ip {
				payment.TxIDs = s.TxIDs
				payment.TimeLastUpdated = s.Timestamp
				payment.AmountReceived = s.AmountReceived
			}
			dbInvoice.Payments = payment
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
	var md mdstream.InvoiceGeneral
	var c mdstream.InvoiceStatusChange
	var p mdstream.InvoicePayment
	var payment cms.PaymentInformation
	for _, v := range r.Metadata {
		switch v.ID {
		case mdstream.IDInvoiceGeneral:
			// General invoice metadata
			m, err := mdstream.DecodeInvoiceGeneral([]byte(v.Payload))
			if err != nil {
				log.Errorf("convertInvoiceFromCache: decode md stream: "+
					"token:%v error:%v payload:%v",
					r.CensorshipRecord.Token, err, v)
				continue
			}
			md = *m

		case mdstream.IDInvoiceStatusChange:
			// Invoice status changes
			m, err := mdstream.DecodeInvoiceStatusChange([]byte(v.Payload))
			if err != nil {
				log.Errorf("convertInvoiceFromCache: decode md stream: "+
					"token:%v error:%v payload:%v",
					r.CensorshipRecord.Token, err, v)
				continue
			}

			// We don't need all of the status changes.
			// Just the most recent one.
			for _, s := range m {
				c = s
				if s.NewStatus == cms.InvoiceStatusApproved {
					payment.Status = cms.PaymentStatusWatching
					payment.TimeStarted = s.Timestamp
				} else if s.NewStatus == cms.InvoiceStatusPaid {
					payment.Status = cms.PaymentStatusPaid
				}
			}
		case mdstream.IDInvoicePayment:
			ip, err := mdstream.DecodeInvoicePayment([]byte(v.Payload))
			if err != nil {
				log.Errorf("convertInvoiceFromCache: decode md stream: "+
					"token:%v error:%v payload:%v",
					r.CensorshipRecord.Token, err, v)
				continue
			}

			// We don't need all of the payments.
			// Just the most recent one.
			for _, s := range ip {
				p = s
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
	invRec := cms.InvoiceRecord{
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

	dbInvoice := convertInvoiceRecordToDatabaseInvoice(&invRec)
	payout, err := calculatePayout(*dbInvoice)
	if err != nil {
		log.Errorf("unable to calculate payout for %v", r.CensorshipRecord.Token)
	}
	txIDs := strings.Split(p.TxIDs, ",")
	payment.TxIDs = txIDs
	payment.TimeLastUpdated = p.Timestamp
	payment.AmountReceived = dcrutil.Amount(p.AmountReceived)
	payment.Address = ii.PaymentAddress
	payment.AmountNeeded = payout.DCRTotal

	invRec.Payment = payment

	return invRec
}

func convertDCCFromCache(r cache.Record) cms.DCCRecord {
	dcc := cms.DCCRecord{}
	// Decode metadata streams
	var md mdstream.DCCGeneral
	var c mdstream.DCCStatusChange
	for _, v := range r.Metadata {
		switch v.ID {
		case mdstream.IDRecordStatusChange:
			// Ignore initial stream change since it's just the automatic change from
			// unvetted to vetted
			continue
		case mdstream.IDDCCGeneral:
			// General invoice metadata
			m, err := mdstream.DecodeDCCGeneral([]byte(v.Payload))
			if err != nil {
				log.Errorf("convertDCCFromCache: decode md stream: "+
					"token:%v error:%v payload:%v",
					r.CensorshipRecord.Token, err, v)
				continue
			}
			md = *m

		case mdstream.IDDCCStatusChange:
			// Invoice status changes
			m, err := mdstream.DecodeDCCStatusChange([]byte(v.Payload))
			if err != nil {
				log.Errorf("convertDCCFromCache: decode md stream: "+
					"token:%v error:%v payload:%v",
					r.CensorshipRecord.Token, err, v)
				continue
			}

			// Calc submission, approval/rejection timestamps
			// Hold the most recent status change.
			for _, s := range m {
				switch s.NewStatus {
				case cms.DCCStatusActive:
					dcc.TimeSubmitted = s.Timestamp
				case cms.DCCStatusApproved, cms.DCCStatusRejected:
					dcc.TimeReviewed = s.Timestamp
				}
				c = s
			}
		case mdstream.IDDCCSupportOpposition:
			// Support and Opposition
			so, err := mdstream.DecodeDCCSupportOpposition([]byte(v.Payload))
			if err != nil {
				log.Errorf("convertDCCFromCache: decode md stream: "+
					"token:%v error:%v payload:%v",
					r.CensorshipRecord.Token, err, v)
				continue
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
		case mdstream.IDRecordStatusChange:
			// Ignore initial stream change since it's just the automatic change from
			// unvetted to vetted
			continue
		case mdstream.IDDCCGeneral:
			var mdGeneral mdstream.DCCGeneral
			err := json.Unmarshal([]byte(m.Payload), &mdGeneral)
			if err != nil {
				return nil, fmt.Errorf("could not decode metadata '%v' token '%v': %v",
					p.Metadata, p.CensorshipRecord.Token, err)
			}

			dbDCC.Timestamp = mdGeneral.Timestamp
			dbDCC.PublicKey = mdGeneral.PublicKey
			dbDCC.UserSignature = mdGeneral.Signature

		case mdstream.IDDCCStatusChange:
			sc, err := mdstream.DecodeDCCStatusChange([]byte(m.Payload))
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

func convertCacheToDatabaseDCC(p cache.Record) (*cmsdatabase.DCC, error) {
	dbDCC := cmsdatabase.DCC{
		Token:           p.CensorshipRecord.Token,
		ServerSignature: p.CensorshipRecord.Signature,
	}

	fs := make([]www.File, 0, len(p.Files))
	for _, v := range p.Files {
		f := www.File{
			Name:    v.Name,
			MIME:    v.MIME,
			Digest:  v.Digest,
			Payload: v.Payload,
		}
		fs = append(fs, f)
	}
	dbDCC.Files = fs

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
		case mdstream.IDRecordStatusChange:
			// Ignore initial stream change since it's just the automatic change from
			// unvetted to vetted
			continue
		case mdstream.IDDCCGeneral:
			var mdGeneral mdstream.DCCGeneral
			err := json.Unmarshal([]byte(m.Payload), &mdGeneral)
			if err != nil {
				return nil, fmt.Errorf("could not decode metadata '%v' token '%v': %v",
					p.Metadata, p.CensorshipRecord.Token, err)
			}

			dbDCC.Timestamp = mdGeneral.Timestamp
			dbDCC.PublicKey = mdGeneral.PublicKey
			dbDCC.UserSignature = mdGeneral.Signature

		case mdstream.IDDCCStatusChange:
			sc, err := mdstream.DecodeDCCStatusChange([]byte(m.Payload))
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

func convertDCCDatabaseFromDCCRecord(dccRecord cms.DCCRecord) cmsdatabase.DCC {
	dbDCC := cmsdatabase.DCC{}

	dbDCC.Type = dccRecord.DCC.Type
	dbDCC.NomineeUserID = dccRecord.DCC.NomineeUserID
	dbDCC.SponsorStatement = dccRecord.DCC.SponsorStatement
	dbDCC.Domain = dccRecord.DCC.Domain
	dbDCC.ContractorType = dccRecord.DCC.ContractorType
	dbDCC.Status = dccRecord.Status
	dbDCC.StatusChangeReason = dccRecord.StatusChangeReason
	dbDCC.Timestamp = dccRecord.Timestamp
	dbDCC.Token = dccRecord.CensorshipRecord.Token
	dbDCC.PublicKey = dccRecord.PublicKey
	dbDCC.ServerSignature = dccRecord.Signature
	dbDCC.SponsorUserID = dccRecord.SponsorUserID
	dbDCC.Token = dccRecord.CensorshipRecord.Token

	supportUserIDs := ""
	for i, s := range dccRecord.SupportUserIDs {
		if i == 0 {
			supportUserIDs += s
		} else {
			supportUserIDs += "," + s
		}
	}
	dbDCC.SupportUserIDs = supportUserIDs

	oppositionUserIDs := ""
	for i, s := range dccRecord.OppositionUserIDs {
		if i == 0 {
			oppositionUserIDs += s
		} else {
			oppositionUserIDs += "," + s
		}
	}
	dbDCC.OppositionUserIDs = oppositionUserIDs

	return dbDCC
}
