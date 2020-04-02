// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cockroachdb

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/thi4go/politeia/decredplugin"
	"github.com/thi4go/politeia/politeiad/cache"
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
		Key:       r.CensorshipRecord.Token + r.Version,
		Token:     r.CensorshipRecord.Token,
		Version:   version,
		Status:    int(r.Status),
		Timestamp: r.Timestamp,
		Merkle:    r.CensorshipRecord.Merkle,
		Signature: r.CensorshipRecord.Signature,
		Metadata:  convertMDStreamsFromCache(r.Metadata),
		Files:     files,
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

func convertStartVoteV1FromDecred(sv decredplugin.StartVoteV1, svr decredplugin.StartVoteReply) (*StartVote, error) {
	opts := make([]VoteOption, 0, len(sv.Vote.Options))
	for _, v := range sv.Vote.Options {
		opts = append(opts, VoteOption{
			Token:       sv.Vote.Token,
			ID:          v.Id,
			Description: v.Description,
			Bits:        v.Bits,
		})
	}
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
	return &StartVote{
		Token:               sv.Vote.Token,
		Version:             sv.Version,
		Type:                int(decredplugin.VoteTypeStandard),
		Mask:                sv.Vote.Mask,
		Duration:            sv.Vote.Duration,
		QuorumPercentage:    sv.Vote.QuorumPercentage,
		PassPercentage:      sv.Vote.PassPercentage,
		Options:             opts,
		PublicKey:           sv.PublicKey,
		Signature:           sv.Signature,
		StartBlockHeight:    uint32(startHeight),
		StartBlockHash:      svr.StartBlockHash,
		EndHeight:           uint32(endHeight),
		EligibleTickets:     strings.Join(svr.EligibleTickets, ","),
		EligibleTicketCount: len(svr.EligibleTickets),
	}, nil
}

func convertStartVoteV2FromDecred(sv decredplugin.StartVoteV2, svr decredplugin.StartVoteReply) (*StartVote, error) {
	opts := make([]VoteOption, 0, len(sv.Vote.Options))
	for _, v := range sv.Vote.Options {
		opts = append(opts, VoteOption{
			Token:       sv.Vote.Token,
			ID:          v.Id,
			Description: v.Description,
			Bits:        v.Bits,
		})
	}
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
	// The version must be pulled from decredplugin because the version
	// is filled in by the politeiad backend and does not travel to the
	// cache. If the cache is being built from scratch the version will
	// be present since the data is being read directly from disk.
	return &StartVote{
		Token:               sv.Vote.Token,
		Version:             decredplugin.VersionStartVoteV2,
		ProposalVersion:     sv.Vote.ProposalVersion,
		Type:                int(sv.Vote.Type),
		Mask:                sv.Vote.Mask,
		Duration:            sv.Vote.Duration,
		QuorumPercentage:    sv.Vote.QuorumPercentage,
		PassPercentage:      sv.Vote.PassPercentage,
		Options:             opts,
		PublicKey:           sv.PublicKey,
		Signature:           sv.Signature,
		StartBlockHeight:    uint32(startHeight),
		StartBlockHash:      svr.StartBlockHash,
		EndHeight:           uint32(endHeight),
		EligibleTickets:     strings.Join(svr.EligibleTickets, ","),
		EligibleTicketCount: len(svr.EligibleTickets),
	}, nil
}

func convertStartVoteToDecredV1(sv StartVote) (*decredplugin.StartVote, error) {
	opts := make([]decredplugin.VoteOption, 0, len(sv.Options))
	for _, v := range sv.Options {
		opts = append(opts, decredplugin.VoteOption{
			Id:          v.ID,
			Description: v.Description,
			Bits:        v.Bits,
		})
	}
	dsv := decredplugin.StartVoteV1{
		Version:   sv.Version,
		PublicKey: sv.PublicKey,
		Vote: decredplugin.VoteV1{
			Token:            sv.Token,
			Mask:             sv.Mask,
			Duration:         sv.Duration,
			QuorumPercentage: sv.QuorumPercentage,
			PassPercentage:   sv.PassPercentage,
			Options:          opts,
		},
		Signature: sv.Signature,
	}
	svb, err := decredplugin.EncodeStartVoteV1(dsv)
	if err != nil {
		return nil, err
	}
	return &decredplugin.StartVote{
		Token:   sv.Token,
		Version: sv.Version,
		Payload: string(svb),
	}, nil
}

func convertStartVoteToDecredV2(sv StartVote) (*decredplugin.StartVote, error) {
	opts := make([]decredplugin.VoteOption, 0, len(sv.Options))
	for _, v := range sv.Options {
		opts = append(opts, decredplugin.VoteOption{
			Id:          v.ID,
			Description: v.Description,
			Bits:        v.Bits,
		})
	}
	dsv := decredplugin.StartVoteV2{
		Version:   sv.Version,
		PublicKey: sv.PublicKey,
		Vote: decredplugin.VoteV2{
			Token:            sv.Token,
			ProposalVersion:  sv.ProposalVersion,
			Type:             decredplugin.VoteT(sv.Type),
			Mask:             sv.Mask,
			Duration:         sv.Duration,
			QuorumPercentage: sv.QuorumPercentage,
			PassPercentage:   sv.PassPercentage,
			Options:          opts,
		},
		Signature: sv.Signature,
	}
	svb, err := decredplugin.EncodeStartVoteV2(dsv)
	if err != nil {
		return nil, err
	}
	return &decredplugin.StartVote{
		Token:   sv.Token,
		Version: sv.Version,
		Payload: string(svb),
	}, nil
}

func convertStartVoteToDecred(sv StartVote) (*decredplugin.StartVote, *decredplugin.StartVoteReply, error) {
	var (
		dsv *decredplugin.StartVote
		err error
	)
	switch sv.Version {
	case decredplugin.VersionStartVoteV1:
		dsv, err = convertStartVoteToDecredV1(sv)
		if err != nil {
			return nil, nil, err
		}
	case decredplugin.VersionStartVoteV2:
		dsv, err = convertStartVoteToDecredV2(sv)
		if err != nil {
			return nil, nil, err
		}
	default:
		return nil, nil, fmt.Errorf("invalid StartVote version %v %v",
			sv.Token, sv.Version)
	}

	var tix []string
	if sv.EligibleTickets != "" {
		tix = strings.Split(sv.EligibleTickets, ",")
	}
	dsvr := &decredplugin.StartVoteReply{
		StartBlockHeight: strconv.FormatUint(uint64(sv.StartBlockHeight), 10),
		StartBlockHash:   sv.StartBlockHash,
		EndHeight:        strconv.FormatUint(uint64(sv.EndHeight), 10),
		EligibleTickets:  tix,
	}

	return dsv, dsvr, nil
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
