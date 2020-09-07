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
	"github.com/decred/politeia/cmsplugin"
	"github.com/decred/politeia/decredplugin"
	"github.com/decred/politeia/mdstream"
	pd "github.com/decred/politeia/politeiad/api/v1"
	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	pi "github.com/decred/politeia/politeiawww/api/pi/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	www2 "github.com/decred/politeia/politeiawww/api/www/v2"
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

func convertAuthorizeVoteToDecred(av www.AuthorizeVote) decredplugin.AuthorizeVote {
	return decredplugin.AuthorizeVote{
		Action:    av.Action,
		Token:     av.Token,
		PublicKey: av.PublicKey,
		Signature: av.Signature,
	}
}

func convertAuthorizeVoteV2ToDecred(av www2.AuthorizeVote) decredplugin.AuthorizeVote {
	return decredplugin.AuthorizeVote{
		Action:    av.Action,
		Token:     av.Token,
		PublicKey: av.PublicKey,
		Signature: av.Signature,
	}
}

func convertAuthorizeVotesV2ToDecred(av []www2.AuthorizeVote) []decredplugin.AuthorizeVote {
	dav := make([]decredplugin.AuthorizeVote, 0, len(av))
	for _, v := range av {
		dav = append(dav, convertAuthorizeVoteV2ToDecred(v))
	}
	return dav
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
	switch v {
	case www2.VoteTypeStandard:
		return decredplugin.VoteTypeStandard
	case www2.VoteTypeRunoff:
		return decredplugin.VoteTypeRunoff
	}
	return decredplugin.VoteTypeInvalid
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

func convertStartVotesV2ToDecred(sv []www2.StartVote) []decredplugin.StartVoteV2 {
	dsv := make([]decredplugin.StartVoteV2, 0, len(sv))
	for _, v := range sv {
		dsv = append(dsv, convertStartVoteV2ToDecred(v))
	}
	return dsv
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
	// values since a decred plugin comment does not contain this data.
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
	case decredplugin.VoteTypeRunoff:
		return www2.VoteTypeRunoff
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

func convertDatabaseInvoiceToInvoiceRecord(dbInvoice cmsdatabase.Invoice) (cms.InvoiceRecord, error) {
	invRec := cms.InvoiceRecord{}
	invRec.Status = dbInvoice.Status
	invRec.Timestamp = dbInvoice.Timestamp
	invRec.UserID = dbInvoice.UserID
	invRec.Username = dbInvoice.Username
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
			SubUserID:     dbLineItem.SubUserID,
		}
		invInputLineItems = append(invInputLineItems, lineItem)
	}

	payout, err := calculatePayout(dbInvoice)
	if err != nil {
		return invRec, err
	}
	invRec.Total = int64(payout.Total)

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
	return invRec, nil
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
			SubUserID:      lineItem.SubUserID,
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

func convertDatabaseInvoiceToProposalLineItems(inv cmsdatabase.Invoice) cms.ProposalLineItems {
	return cms.ProposalLineItems{
		Month:    int(inv.Month),
		Year:     int(inv.Year),
		UserID:   inv.UserID,
		Username: inv.Username,
		LineItem: cms.LineItemsInput{
			Type:          inv.LineItems[0].Type,
			Domain:        inv.LineItems[0].Domain,
			Subdomain:     inv.LineItems[0].Subdomain,
			Description:   inv.LineItems[0].Description,
			ProposalToken: inv.LineItems[0].ProposalURL,
			Labor:         inv.LineItems[0].Labor,
			Expenses:      inv.LineItems[0].Expenses,
			SubRate:       inv.LineItems[0].ContractorRate,
		},
	}
}

func convertCastVoteFromCMS(b cms.CastVote) cmsplugin.CastVote {
	return cmsplugin.CastVote{
		VoteBit:   b.VoteBit,
		Token:     b.Token,
		UserID:    b.UserID,
		Signature: b.Signature,
	}
}

func convertCastVoteReplyToCMS(cv *cmsplugin.CastVoteReply) *cms.CastVoteReply {
	return &cms.CastVoteReply{
		ClientSignature: cv.ClientSignature,
		Signature:       cv.Signature,
		Error:           cv.Error,
		ErrorStatus:     cv.ErrorStatus,
	}
}

func convertUserWeightToCMS(uw []cmsplugin.UserWeight) []cms.DCCWeight {
	dccWeight := make([]cms.DCCWeight, 0, len(uw))
	for _, w := range uw {
		dccWeight = append(dccWeight, cms.DCCWeight{
			UserID: w.UserID,
			Weight: w.Weight,
		})
	}
	return dccWeight
}

func convertVoteOptionResultsToCMS(vr []cmsplugin.VoteOptionResult) []cms.VoteOptionResult {
	votes := make([]cms.VoteOptionResult, 0, len(vr))
	for _, w := range vr {
		votes = append(votes, cms.VoteOptionResult{
			Option: cms.VoteOption{
				Id:          w.ID,
				Description: w.Description,
				Bits:        w.Bits,
			},
			VotesReceived: w.Votes,
		})
	}
	return votes
}
func convertCMSStartVoteToCMSVoteDetailsReply(sv cmsplugin.StartVote, svr cmsplugin.StartVoteReply) (*cms.VoteDetailsReply, error) {
	voteb, err := cmsplugin.EncodeVote(sv.Vote)
	if err != nil {
		return nil, err
	}
	userWeights := make([]string, 0, len(sv.UserWeights))
	for _, weights := range sv.UserWeights {
		userWeight := weights.UserID + "-" + strconv.Itoa(int(weights.Weight))
		userWeights = append(userWeights, userWeight)
	}
	return &cms.VoteDetailsReply{
		Version:          uint32(sv.Version),
		Vote:             string(voteb),
		PublicKey:        sv.PublicKey,
		Signature:        sv.Signature,
		StartBlockHeight: svr.StartBlockHeight,
		StartBlockHash:   svr.StartBlockHash,
		EndBlockHeight:   svr.EndHeight,
		UserWeights:      userWeights,
	}, nil
}

func convertCMSStartVoteToCMS(sv cmsplugin.StartVote) cms.StartVote {
	vote := cms.Vote{
		Token:            sv.Vote.Token,
		Mask:             sv.Vote.Mask,
		Duration:         sv.Vote.Duration,
		QuorumPercentage: sv.Vote.QuorumPercentage,
		PassPercentage:   sv.Vote.PassPercentage,
	}

	voteOptions := make([]cms.VoteOption, 0, len(sv.Vote.Options))
	for _, option := range sv.Vote.Options {
		voteOption := cms.VoteOption{
			Id:          option.Id,
			Description: option.Description,
			Bits:        option.Bits,
		}
		voteOptions = append(voteOptions, voteOption)
	}
	vote.Options = voteOptions

	return cms.StartVote{
		Vote:      vote,
		PublicKey: sv.PublicKey,
		Signature: sv.Signature,
	}
}

func convertCMSStartVoteReplyToCMS(svr cmsplugin.StartVoteReply) cms.StartVoteReply {
	return cms.StartVoteReply{
		StartBlockHeight: svr.StartBlockHeight,
		StartBlockHash:   svr.StartBlockHash,
		EndBlockHeight:   svr.EndHeight,
	}
}

func convertStartVoteToCMS(sv cms.StartVote) cmsplugin.StartVote {
	vote := cmsplugin.Vote{
		Token:            sv.Vote.Token,
		Mask:             sv.Vote.Mask,
		Duration:         sv.Vote.Duration,
		QuorumPercentage: sv.Vote.QuorumPercentage,
		PassPercentage:   sv.Vote.PassPercentage,
	}

	voteOptions := make([]cmsplugin.VoteOption, 0, len(sv.Vote.Options))
	for _, option := range sv.Vote.Options {
		voteOption := cmsplugin.VoteOption{
			Id:          option.Id,
			Description: option.Description,
			Bits:        option.Bits,
		}
		voteOptions = append(voteOptions, voteOption)
	}
	vote.Options = voteOptions

	return cmsplugin.StartVote{
		Token:     sv.Vote.Token,
		Vote:      vote,
		PublicKey: sv.PublicKey,
		Signature: sv.Signature,
	}

}

func filterDomainInvoice(inv *cms.InvoiceRecord) cms.InvoiceRecord {
	inv.Files = nil
	inv.Input.ContractorContact = ""
	inv.Input.ContractorLocation = ""
	inv.Input.ContractorName = ""
	inv.Input.ContractorRate = 0

	for i, li := range inv.Input.LineItems {
		li.Expenses = 0
		li.SubRate = 0
		inv.Input.LineItems[i] = li
	}

	return *inv
}

func convertPiFilesFromWWW(files []www.File) []pi.File {
	f := make([]pi.File, 0, len(files))
	for _, v := range files {
		f = append(f, pi.File{
			Name:    v.Name,
			MIME:    v.MIME,
			Digest:  v.Digest,
			Payload: v.Payload,
		})
	}
	return f
}
