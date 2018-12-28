package main

import (
	"encoding/json"
	"strconv"

	"github.com/decred/politeia/decredplugin"
	pd "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/cache"
	www "github.com/decred/politeia/politeiawww/api/v1"
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

func convertAuthorizeVoteReplyFromDecredplugin(avr decredplugin.AuthorizeVoteReply) www.AuthorizeVoteReply {
	return www.AuthorizeVoteReply{
		Action:  avr.Action,
		Receipt: avr.Receipt,
	}
}

func convertStartVoteFromWWW(sv www.StartVote) decredplugin.StartVote {
	return decredplugin.StartVote{
		PublicKey: sv.PublicKey,
		Vote:      convertVoteFromWWW(sv.Vote),
		Signature: sv.Signature,
	}
}

func convertStartVoteFromDecredplugin(sv decredplugin.StartVote) www.StartVote {
	return www.StartVote{
		PublicKey: sv.PublicKey,
		Vote:      convertVoteFromDecredplugin(sv.Vote),
		Signature: sv.Signature,
	}
}

func convertStartVoteReplyFromDecredplugin(svr decredplugin.StartVoteReply) www.StartVoteReply {
	return www.StartVoteReply{
		StartBlockHeight: svr.StartBlockHeight,
		StartBlockHash:   svr.StartBlockHash,
		EndHeight:        svr.EndHeight,
		EligibleTickets:  svr.EligibleTickets,
	}
}

func convertVoteOptionFromDecredplugin(vo decredplugin.VoteOption) www.VoteOption {
	return www.VoteOption{
		Id:          vo.Id,
		Description: vo.Description,
		Bits:        vo.Bits,
	}
}

func convertVoteOptionsFromDecredplugin(vo []decredplugin.VoteOption) []www.VoteOption {
	vor := make([]www.VoteOption, 0, len(vo))
	for _, v := range vo {
		vor = append(vor, convertVoteOptionFromDecredplugin(v))
	}
	return vor
}

func convertVoteFromDecredplugin(v decredplugin.Vote) www.Vote {
	return www.Vote{
		Token:            v.Token,
		Mask:             v.Mask,
		Duration:         v.Duration,
		QuorumPercentage: v.QuorumPercentage,
		PassPercentage:   v.PassPercentage,
		Options:          convertVoteOptionsFromDecredplugin(v.Options),
	}
}

func convertCastVoteFromDecredplugin(cv decredplugin.CastVote) www.CastVote {
	return www.CastVote{
		Token:     cv.Token,
		Ticket:    cv.Ticket,
		VoteBit:   cv.VoteBit,
		Signature: cv.Signature,
	}
}

func convertCastVotesFromDecredplugin(cv []decredplugin.CastVote) []www.CastVote {
	cvr := make([]www.CastVote, 0, len(cv))
	for _, v := range cv {
		cvr = append(cvr, convertCastVoteFromDecredplugin(v))
	}
	return cvr
}

func convertVoteResultsReplyFromDecredplugin(vrr decredplugin.VoteResultsReply, ir inventoryRecord) www.VoteResultsReply {
	return www.VoteResultsReply{
		StartVote:      convertStartVoteFromDecredplugin(vrr.StartVote),
		CastVotes:      convertCastVotesFromDecredplugin(vrr.CastVotes),
		StartVoteReply: ir.voting,
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

func convertPropCensorFromWWW(f www.CensorshipRecord) pd.CensorshipRecord {
	return pd.CensorshipRecord{
		Token:     f.Token,
		Merkle:    f.Merkle,
		Signature: f.Signature,
	}
}

// convertPropFromWWW converts a www proposal to a politeiad record.  This
// function should only be used in tests. Note that convertPropFromWWW can not
// emulate MD properly.
func convertPropFromWWW(p www.ProposalRecord) pd.Record {
	return pd.Record{
		Status:    convertPropStatusFromWWW(p.Status),
		Timestamp: p.Timestamp,
		Metadata: []pd.MetadataStream{{
			ID:      pd.MetadataStreamsMax + 1, // fail deliberately
			Payload: "invalid payload",
		}},
		Files:            convertPropFilesFromWWW(p.Files),
		CensorshipRecord: convertPropCensorFromWWW(p.CensorshipRecord),
	}
}

func convertPropsFromWWW(p []www.ProposalRecord) []pd.Record {
	pr := make([]pd.Record, 0, len(p))
	for _, v := range p {
		pr = append(pr, convertPropFromWWW(v))
	}
	return pr
}

///////////////////////////////
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

func convertPropFileFromPD(f pd.File) www.File {
	return www.File{
		Name:    f.Name,
		MIME:    f.MIME,
		Digest:  f.Digest,
		Payload: f.Payload,
	}
}

func convertPropFilesFromPD(f []pd.File) []www.File {
	files := make([]www.File, 0, len(f))
	for _, v := range f {
		files = append(files, convertPropFileFromPD(v))
	}
	return files
}

func convertPropCensorFromPD(f pd.CensorshipRecord) www.CensorshipRecord {
	return www.CensorshipRecord{
		Token:     f.Token,
		Merkle:    f.Merkle,
		Signature: f.Signature,
	}
}

func convertPropFromPD(p pd.Record) www.ProposalRecord {
	md := &BackendProposalMetadata{}
	var statusChangeMsg string
	for _, v := range p.Metadata {
		if v.ID == mdStreamGeneral {
			m, err := decodeBackendProposalMetadata([]byte(v.Payload))
			if err != nil {
				log.Errorf("could not decode metadata '%v' token '%v': %v",
					p.Metadata, p.CensorshipRecord.Token, err)
				break
			}
			md = m
		}

		if v.ID == mdStreamChanges {
			var mdc MDStreamChanges
			err := json.Unmarshal([]byte(v.Payload), &mdc)
			if err != nil {
				break
			}
			statusChangeMsg = mdc.StatusChangeMessage
		}
	}

	var state www.PropStateT
	status := convertPropStatusFromPD(p.Status)
	switch status {
	case www.PropStatusNotReviewed, www.PropStatusUnreviewedChanges,
		www.PropStatusCensored:
		state = www.PropStateUnvetted
	case www.PropStatusPublic, www.PropStatusAbandoned:
		state = www.PropStateVetted
	default:
		state = www.PropStateInvalid
	}

	return www.ProposalRecord{
		Name:                md.Name,
		State:               state,
		Status:              status,
		Timestamp:           md.Timestamp,
		PublicKey:           md.PublicKey,
		Signature:           md.Signature,
		Files:               convertPropFilesFromPD(p.Files),
		CensorshipRecord:    convertPropCensorFromPD(p.CensorshipRecord),
		Version:             p.Version,
		StatusChangeMessage: statusChangeMsg,
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

func convertVoteResultsFromDecredplugin(vrr decredplugin.VoteResultsReply) []www.VoteOptionResult {
	// counter of votes received
	var vr uint64
	var ors []www.VoteOptionResult
	for _, o := range vrr.StartVote.Vote.Options {
		vr = 0
		for _, v := range vrr.CastVotes {
			vb, err := strconv.ParseUint(v.VoteBit, 10, 64)
			if err != nil {
				log.Infof("it shouldn't happen")
				continue
			}
			if vb == o.Bits {
				vr++
			}
		}

		// append to vote options result slice
		ors = append(ors, www.VoteOptionResult{
			VotesReceived: vr,
			Option:        convertVoteOptionFromDecredplugin(o),
		})
	}
	return ors
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
	var bpm BackendProposalMetadata
	var msc MDStreamChanges
	for _, ms := range r.Metadata {
		if ms.ID == mdStreamGeneral {
			err := json.Unmarshal([]byte(ms.Payload), &bpm)
			if err != nil {
				log.Errorf("could not unmarshal metadata '%v' token '%v': %v",
					ms, r.CensorshipRecord.Token, err)
			}
		}
		if ms.ID == mdStreamChanges {
			err := json.Unmarshal([]byte(ms.Payload), &msc)
			if err != nil {
				log.Errorf("could not unmarshal metadata '%v' token '%v': %v",
					ms, r.CensorshipRecord.Token, err)
			}
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
		StatusChangeMessage: msc.StatusChangeMessage,
		CensorshipRecord: www.CensorshipRecord{
			Token:     r.CensorshipRecord.Token,
			Merkle:    r.CensorshipRecord.Merkle,
			Signature: r.CensorshipRecord.Signature,
		},
	}
}

func convertCommentFromDecredPlugin(c decredplugin.Comment) www.Comment {
	return www.Comment{
		Token:       c.Token,
		ParentID:    c.ParentID,
		Comment:     c.Comment,
		Signature:   c.Signature,
		PublicKey:   c.PublicKey,
		CommentID:   c.CommentID,
		Receipt:     c.Receipt,
		Timestamp:   c.Timestamp,
		TotalVotes:  c.TotalVotes,
		ResultVotes: c.ResultVotes,
		Censored:    c.Censored,
		UserID:      "",
		Username:    "",
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

func convertNewCommentReplyFromDecredPlugin(ncr decredplugin.NewCommentReply) www.NewCommentReply {
	return www.NewCommentReply{
		Comment: convertCommentFromDecredPlugin(ncr.Comment),
	}
}

func convertCensorCommentToDecredPlugin(cc www.CensorComment) decredplugin.CensorComment {
	return decredplugin.CensorComment{
		Token:     cc.Token,
		CommentID: cc.CommentID,
		Reason:    cc.Reason,
		Signature: cc.Signature,
		PublicKey: cc.PublicKey,
	}
}

func convertCensorCommentReplyFromDecredPlugin(ccr decredplugin.CensorCommentReply) www.CensorCommentReply {
	return www.CensorCommentReply{
		Receipt: ccr.Receipt,
	}
}

func convertLikeCommentToDecredPlugin(lc www.LikeComment) decredplugin.LikeComment {
	return decredplugin.LikeComment{
		Token:     lc.Token,
		CommentID: lc.CommentID,
		Action:    lc.Action,
		Signature: lc.Signature,
		PublicKey: lc.PublicKey,
	}
}

func convertLikeCommentFromDecredPlugin(lc decredplugin.LikeComment) www.LikeComment {
	return www.LikeComment{
		Token:     lc.Token,
		CommentID: lc.CommentID,
		Action:    lc.Action,
		Signature: lc.Signature,
		PublicKey: lc.PublicKey,
	}
}
