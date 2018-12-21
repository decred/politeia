package cockroachdb

import "github.com/decred/politeia/politeiad/cache"

func convertMDStreamFromCache(ms cache.MetadataStream) MetadataStream {
	return MetadataStream{
		ID:      ms.ID,
		Payload: ms.Payload,
	}
}

func convertRecordFromCache(r cache.Record) Record {
	cr := CensorshipRecord{
		Token:     r.CensorshipRecord.Token,
		Merkle:    r.CensorshipRecord.Merkle,
		Signature: r.CensorshipRecord.Signature,
	}

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
		Version:          r.Version,
		Status:           int(r.Status),
		Timestamp:        r.Timestamp,
		CensorshipRecord: cr,
		Metadata:         metadata,
		Files:            files,
	}
}

func convertRecordToCache(r Record) cache.Record {
	cr := cache.CensorshipRecord{
		Token:     r.CensorshipRecord.Token,
		Merkle:    r.CensorshipRecord.Merkle,
		Signature: r.CensorshipRecord.Signature,
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
