// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package records

import (
	"context"

	pdv1 "github.com/decred/politeia/politeiad/api/v1"
	v1 "github.com/decred/politeia/politeiawww/api/records/v1"
)

func (r *Records) processTimestamps(ctx context.Context, t v1.Timestamps, isAdmin bool) (*v1.TimestampsReply, error) {
	log.Tracef("processTimestamps: %v %v %v", t.State, t.Token, t.Version)

	// Get record timestamps
	var (
		rt  *pdv1.RecordTimestamps
		err error
	)
	switch t.State {
	case v1.RecordStateUnvetted:
		rt, err = r.politeiad.GetUnvettedTimestamps(ctx, t.Token, t.Version)
		if err != nil {
			return nil, err
		}
	case v1.RecordStateVetted:
		rt, err = r.politeiad.GetVettedTimestamps(ctx, t.Token, t.Version)
		if err != nil {
			return nil, err
		}
	default:
		return nil, v1.UserErrorReply{
			ErrorCode: v1.ErrorCodeRecordStateInvalid,
		}
	}

	var (
		recordMD = convertTimestampToV1(rt.RecordMetadata)
		metadata = make(map[uint64]v1.Timestamp, len(rt.Files))
		files    = make(map[string]v1.Timestamp, len(rt.Files))
	)
	for k, v := range rt.Metadata {
		metadata[k] = convertTimestampToV1(v)
	}
	for k, v := range rt.Files {
		files[k] = convertTimestampToV1(v)
	}

	// Unvetted data blobs are stripped if the user is not an admin.
	// The rest of the timestamp is still returned.
	if t.State == v1.RecordStateUnvetted && !isAdmin {
		recordMD.Data = ""
		for k, v := range files {
			v.Data = ""
			files[k] = v
		}
		for k, v := range metadata {
			v.Data = ""
			metadata[k] = v
		}
	}

	return &v1.TimestampsReply{
		RecordMetadata: recordMD,
		Files:          files,
		Metadata:       metadata,
	}, nil
}

func convertProofToV1(p pdv1.Proof) v1.Proof {
	return v1.Proof{
		Type:       p.Type,
		Digest:     p.Digest,
		MerkleRoot: p.MerkleRoot,
		MerklePath: p.MerklePath,
		ExtraData:  p.ExtraData,
	}
}

func convertTimestampToV1(t pdv1.Timestamp) v1.Timestamp {
	proofs := make([]v1.Proof, 0, len(t.Proofs))
	for _, v := range t.Proofs {
		proofs = append(proofs, convertProofToV1(v))
	}
	return v1.Timestamp{
		Data:       t.Data,
		Digest:     t.Digest,
		TxID:       t.TxID,
		MerkleRoot: t.MerkleRoot,
		Proofs:     proofs,
	}
}
