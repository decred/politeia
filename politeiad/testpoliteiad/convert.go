// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package testpoliteiad

import (
	v1 "github.com/thi4go/politeia/politeiad/api/v1"
	"github.com/thi4go/politeia/politeiad/cache"
)

func convertRecordStatusToCache(status v1.RecordStatusT) cache.RecordStatusT {
	s := cache.RecordStatusInvalid
	switch status {
	case v1.RecordStatusInvalid:
		s = cache.RecordStatusInvalid
	case v1.RecordStatusNotReviewed:
		s = cache.RecordStatusNotReviewed
	case v1.RecordStatusPublic:
		s = cache.RecordStatusPublic
	case v1.RecordStatusCensored:
		s = cache.RecordStatusCensored
	case v1.RecordStatusUnreviewedChanges:
		s = cache.RecordStatusUnreviewedChanges
	case v1.RecordStatusArchived:
		s = cache.RecordStatusArchived
	}
	return s
}

func convertCensorshipRecordToCache(r v1.CensorshipRecord) cache.CensorshipRecord {
	return cache.CensorshipRecord{
		Token:     r.Token,
		Merkle:    r.Merkle,
		Signature: r.Signature,
	}
}

func convertMetadataStreamsToCache(m []v1.MetadataStream) []cache.MetadataStream {
	cm := make([]cache.MetadataStream, 0, len(m))
	for _, v := range m {
		cm = append(cm, cache.MetadataStream{
			ID:      v.ID,
			Payload: v.Payload,
		})
	}
	return cm
}

func convertFileToCache(f v1.File) cache.File {
	return cache.File{
		Name:    f.Name,
		MIME:    f.MIME,
		Digest:  f.Digest,
		Payload: f.Payload,
	}
}

func convertFilesToCache(f []v1.File) []cache.File {
	files := make([]cache.File, 0, len(f))
	for _, v := range f {
		files = append(files, convertFileToCache(v))
	}
	return files
}

func convertRecordToCache(r v1.Record) cache.Record {
	return cache.Record{
		Version:          r.Version,
		Status:           convertRecordStatusToCache(r.Status),
		Timestamp:        r.Timestamp,
		CensorshipRecord: convertCensorshipRecordToCache(r.CensorshipRecord),
		Metadata:         convertMetadataStreamsToCache(r.Metadata),
		Files:            convertFilesToCache(r.Files),
	}
}
