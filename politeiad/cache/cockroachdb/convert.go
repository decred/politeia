// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cockroachdb

import (
	"github.com/decred/politeia/decredplugin"
	"github.com/decred/politeia/politeiad/cache"
)

func convertMDStreamFromCache(ms cache.MetadataStream) MetadataStream {
	return MetadataStream{
		ID:      ms.ID,
		Payload: ms.Payload,
	}
}

func convertRecordFromCache(r cache.Record) Record {
	metadata := make([]MetadataStream, 0, len(r.Metadata))
	for _, ms := range r.Metadata {
		metadata = append(metadata, convertMDStreamFromCache(ms))
	}

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
		Version:   r.Version,
		Status:    int(r.Status),
		Timestamp: r.Timestamp,
		Merkle:    r.CensorshipRecord.Merkle,
		Signature: r.CensorshipRecord.Signature,
		Metadata:  metadata,
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
		Version:          r.Version,
		Status:           cache.RecordStatusT(r.Status),
		Timestamp:        r.Timestamp,
		CensorshipRecord: cr,
		Metadata:         metadata,
		Files:            files,
	}
}

func convertCommentFromDecred(nc decredplugin.NewComment, ncr decredplugin.NewCommentReply) Comment {
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

func convertLikeCommentFromDecred(lc decredplugin.LikeComment, lcr decredplugin.LikeCommentReply) LikeComment {
	return LikeComment{
		Token:     lc.Token,
		CommentID: lc.CommentID,
		Action:    lc.Action,
		Signature: lc.Signature,
		PublicKey: lc.PublicKey,
		Receipt:   lcr.Receipt,
		Timestamp: lcr.Timestamp,
	}
}

func convertLikeCommentToDecred(lc LikeComment) decredplugin.LikeComment {
	return decredplugin.LikeComment{
		Token:     lc.Token,
		CommentID: lc.CommentID,
		Action:    lc.Action,
		Signature: lc.Signature,
		PublicKey: lc.PublicKey,
		Receipt:   lc.Receipt,
		Timestamp: lc.Timestamp,
	}
}
