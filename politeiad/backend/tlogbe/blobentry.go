// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlogbe

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"

	"github.com/decred/politeia/util"
)

const (
	// blobEntryVersion is encoded in the sbox header of encrypted
	// blobs.
	blobEntryVersion uint32 = 1

	// Data descriptor types. These may be freely edited since they are
	// solely hints to the application.
	dataTypeStructure = "struct" // Descriptor contains a structure

	dataDescriptorAnchor = "anchor"
)

// dataDescriptor provides hints about a data blob. In practise we JSON encode
// this struture and stuff it into blobEntry.DataHint.
type dataDescriptor struct {
	Type       string `json:"type"`                // Type of data
	Descriptor string `json:"descriptor"`          // Description of the data
	ExtraData  string `json:"extradata,omitempty"` // Value to be freely used
}

// blobEntry is the structure used to store data in the Blob key-value store.
// All data in the Blob key-value store will be encoded as a blobEntry.
type blobEntry struct {
	Hash     string `json:"hash"`     // SHA256 hash of data payload, hex encoded
	DataHint string `json:"datahint"` // Hint that describes data, base64 encoded
	Data     string `json:"data"`     // Data payload, base64 encoded
}

func blobify(be blobEntry) ([]byte, error) {
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	enc := gob.NewEncoder(zw)
	err := enc.Encode(be)
	if err != nil {
		return nil, err
	}
	err = zw.Close() // we must flush gzip buffers
	if err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func deblob(blob []byte) (*blobEntry, error) {
	zr, err := gzip.NewReader(bytes.NewReader(blob))
	if err != nil {
		return nil, err
	}
	r := gob.NewDecoder(zr)
	var be blobEntry
	err = r.Decode(&be)
	if err != nil {
		return nil, err
	}
	return &be, nil
}

func blobEntryNew(dataHint, data []byte) blobEntry {
	return blobEntry{
		Hash:     hex.EncodeToString(util.Digest(data)),
		DataHint: base64.StdEncoding.EncodeToString(dataHint),
		Data:     base64.StdEncoding.EncodeToString(data),
	}
}
