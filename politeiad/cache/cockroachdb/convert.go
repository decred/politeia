// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cockroachdb

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/decred/politeia/decredplugin"
	"github.com/decred/politeia/politeiad/cache"
	"github.com/decred/politeia/util"
)

func convertMDStreamFromCache(ms cache.MetadataStream) MetadataStream {
	return MetadataStream{
		ID:      ms.ID,
		Payload: ms.Payload,
	}
}

func convertMDStreamsFromCache(ms []cache.MetadataStream) []MetadataStream {
	m := make([]MetadataStream, 0, len(ms))
	for _, v := range ms {
		m = append(m, convertMDStreamFromCache(v))
	}
	return m
}

func convertRecordFromCache(r cache.Record, version uint64) Record {
	files := make([]File, 0, len(r.Files))
	for _, f := range r.Files {
		files = append(files,
			File{
				Name:    f.Name,
				MIME:    f.MIME,
				Digest:  f.Digest,
				Payload: f.Payload,
			})
	}

	return Record{
		Key:         r.CensorshipRecord.Token + r.Version,
		Token:       r.CensorshipRecord.Token,
		Version:     version,
		Status:      int(r.Status),
		Timestamp:   r.Timestamp,
		Merkle:      r.CensorshipRecord.Merkle,
		Signature:   r.CensorshipRecord.Signature,
		Metadata:    convertMDStreamsFromCache(r.Metadata),
		Files:       files,
		TokenPrefix: util.TokenToPrefix(r.CensorshipRecord.Token),
	}
}

func convertRecordToCache(r Record) cache.Record {
	cr := cache.CensorshipRecord{
		Token:     r.Token,
		Merkle:    r.Merkle,
		Signature: r.Signature,
	}

	metadata := make([]cache.MetadataStream, 0, len(r.Metadata))
	for _, ms := range r.Metadata {
		metadata = append(metadata,
			cache.MetadataStream{
				ID:      ms.ID,
				Payload: ms.Payload,
			})
	}

	files := make([]cache.File, 0, len(r.Files))
	for _, f := range r.Files {
		files = append(files,
			cache.File{
				Name:    f.Name,
				MIME:    f.MIME,
				Digest:  f.Digest,
				Payload: f.Payload,
			})
	}

	return cache.Record{
		Version:          strconv.FormatUint(r.Version, 10),
		Status:           cache.RecordStatusT(r.Status),
		Timestamp:        r.Timestamp,
		CensorshipRecord: cr,
		Metadata:         metadata,
		Files:            files,
	}
}

func convertNewCommentFromDecred(nc decredplugin.NewComment, ncr decredplugin.NewCommentReply) Comment {
	return Comment{
		Key:       nc.Token + ncr.CommentID,
		Token:     nc.Token,
		ParentID:  nc.ParentID,
		Comment:   nc.Comment,
		Signature: nc.Signature,
		PublicKey: nc.PublicKey,
		CommentID: ncr.CommentID,
		Receipt:   ncr.Receipt,
		Timestamp: ncr.Timestamp,
		Censored:  false,
	}
}

func convertCommentFromDecred(c decredplugin.Comment) Comment {
	return Comment{
		Key:       c.Token + c.CommentID,
		Token:     c.Token,
		ParentID:  c.ParentID,
		Comment:   c.Comment,
		Signature: c.Signature,
		PublicKey: c.PublicKey,
		CommentID: c.CommentID,
		Receipt:   c.Receipt,
		Timestamp: c.Timestamp,
		Censored:  false,
	}
}

func convertCommentToDecred(c Comment) decredplugin.Comment {
	return decredplugin.Comment{
		Token:       c.Token,
		ParentID:    c.ParentID,
		Comment:     c.Comment,
		Signature:   c.Signature,
		PublicKey:   c.PublicKey,
		CommentID:   c.CommentID,
		Receipt:     c.Receipt,
		Timestamp:   c.Timestamp,
		TotalVotes:  0,
		ResultVotes: 0,
		Censored:    c.Censored,
	}
}

func convertLikeCommentFromDecred(lc decredplugin.LikeComment) LikeComment {
	return LikeComment{
		Token:     lc.Token,
		CommentID: lc.CommentID,
		Action:    lc.Action,
		Signature: lc.Signature,
		PublicKey: lc.PublicKey,
	}
}

func convertLikeCommentToDecred(lc LikeComment) decredplugin.LikeComment {
	return decredplugin.LikeComment{
		Token:     lc.Token,
		CommentID: lc.CommentID,
		Action:    lc.Action,
		Signature: lc.Signature,
		PublicKey: lc.PublicKey,
	}
}

func convertAuthorizeVoteFromDecred(av decredplugin.AuthorizeVote, avr decredplugin.AuthorizeVoteReply, version uint64) AuthorizeVote {
	return AuthorizeVote{
		Key:       av.Token + avr.RecordVersion,
		Token:     av.Token,
		Version:   version,
		Action:    av.Action,
		Signature: av.Signature,
		PublicKey: av.PublicKey,
		Receipt:   avr.Receipt,
		Timestamp: avr.Timestamp,
	}
}

func convertAuthorizeVoteToDecred(av AuthorizeVote) decredplugin.AuthorizeVote {
	return decredplugin.AuthorizeVote{
		Action:    av.Action,
		Token:     av.Token,
		Signature: av.Signature,
		PublicKey: av.PublicKey,
		Receipt:   av.Receipt,
		Timestamp: av.Timestamp,
	}
}

func convertStartVoteFromDecred(sv decredplugin.StartVote, svr decredplugin.StartVoteReply, endHeight uint64) StartVote {
	opts := make([]VoteOption, 0, len(sv.Vote.Options))
	for _, v := range sv.Vote.Options {
		opts = append(opts, VoteOption{
			Token:       sv.Vote.Token,
			ID:          v.Id,
			Description: v.Description,
			Bits:        v.Bits,
		})
	}
	return StartVote{
		Token:               sv.Vote.Token,
		Mask:                sv.Vote.Mask,
		Duration:            sv.Vote.Duration,
		QuorumPercentage:    sv.Vote.QuorumPercentage,
		PassPercentage:      sv.Vote.PassPercentage,
		Options:             opts,
		PublicKey:           sv.PublicKey,
		Signature:           sv.Signature,
		StartBlockHeight:    svr.StartBlockHeight,
		StartBlockHash:      svr.StartBlockHash,
		EndHeight:           endHeight,
		EligibleTickets:     strings.Join(svr.EligibleTickets, ","),
		EligibleTicketCount: len(svr.EligibleTickets),
	}
}

func convertStartVoteToDecred(sv StartVote) (decredplugin.StartVote, decredplugin.StartVoteReply) {
	opts := make([]decredplugin.VoteOption, 0, len(sv.Options))
	for _, v := range sv.Options {
		opts = append(opts, decredplugin.VoteOption{
			Id:          v.ID,
			Description: v.Description,
			Bits:        v.Bits,
		})
	}

	dsv := decredplugin.StartVote{
		PublicKey: sv.PublicKey,
		Signature: sv.Signature,
		Vote: decredplugin.Vote{
			Token:            sv.Token,
			Mask:             sv.Mask,
			Duration:         sv.Duration,
			QuorumPercentage: sv.QuorumPercentage,
			PassPercentage:   sv.PassPercentage,
			Options:          opts,
		},
	}

	var tix []string
	if sv.EligibleTickets != "" {
		tix = strings.Split(sv.EligibleTickets, ",")
	}
	dsvr := decredplugin.StartVoteReply{
		StartBlockHeight: sv.StartBlockHeight,
		StartBlockHash:   sv.StartBlockHash,
		EndHeight:        fmt.Sprint(sv.EndHeight),
		EligibleTickets:  tix,
	}

	return dsv, dsvr
}

func convertCastVoteFromDecred(cv decredplugin.CastVote) CastVote {
	return CastVote{
		Token:        cv.Token,
		Ticket:       cv.Ticket,
		VoteBit:      cv.VoteBit,
		Signature:    cv.Signature,
		TokenVoteBit: cv.Token + cv.VoteBit,
	}
}

func convertCastVoteToDecred(cv CastVote) decredplugin.CastVote {
	return decredplugin.CastVote{
		Token:     cv.Token,
		Ticket:    cv.Ticket,
		VoteBit:   cv.VoteBit,
		Signature: cv.Signature,
	}
}

func convertVoteOptionResultToDecred(r VoteOptionResult) decredplugin.VoteOptionResult {
	return decredplugin.VoteOptionResult{
		ID:          r.Option.ID,
		Description: r.Option.Description,
		Bits:        r.Option.Bits,
		Votes:       r.Votes,
	}
}

func convertVoteOptionResultsToDecred(r []VoteOptionResult) []decredplugin.VoteOptionResult {
	results := make([]decredplugin.VoteOptionResult, 0, len(r))
	for _, v := range r {
		results = append(results, convertVoteOptionResultToDecred(v))
	}
	return results
}
