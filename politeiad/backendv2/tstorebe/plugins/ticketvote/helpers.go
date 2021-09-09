// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
	"github.com/decred/politeia/politeiad/plugins/dcrdata"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	"github.com/decred/politeia/util"
	"github.com/pkg/errors"
)

// bestBlock fetches the best block from the dcrdata plugin and returns it. If
// the dcrdata connection is not active, an error will be returned.
func bestBlock(backend backend.Backend) (uint32, error) {
	// Get best block
	payload, err := json.Marshal(dcrdata.BestBlock{})
	if err != nil {
		return 0, err
	}
	reply, err := backend.PluginRead(nil, dcrdata.PluginID,
		dcrdata.CmdBestBlock, string(payload))
	if err != nil {
		return 0, errors.Errorf("PluginRead %v %v: %v",
			dcrdata.PluginID, dcrdata.CmdBestBlock, err)
	}

	// Handle response
	var bbr dcrdata.BestBlockReply
	err = json.Unmarshal([]byte(reply), &bbr)
	if err != nil {
		return 0, err
	}
	if bbr.Status != dcrdata.StatusConnected {
		// The dcrdata connection is down. The best block cannot be
		// trusted as being accurate.
		return 0, errors.Errorf("dcrdata connection is down")
	}
	if bbr.Height == 0 {
		return 0, errors.Errorf("invalid best block height 0")
	}

	return bbr.Height, nil
}

// bestBlockUnsafe fetches the best block from the dcrdata plugin and returns
// it. If the dcrdata connection is not active, an error WILL NOT be returned.
// The dcrdata cached best block height will be returned even though it may be
// stale. Use bestBlock() if the caller requires a guarantee that the best
// block is not stale.
func bestBlockUnsafe(backend backend.Backend) (uint32, error) {
	// Get best block
	payload, err := json.Marshal(dcrdata.BestBlock{})
	if err != nil {
		return 0, err
	}
	reply, err := backend.PluginRead(nil, dcrdata.PluginID,
		dcrdata.CmdBestBlock, string(payload))
	if err != nil {
		return 0, errors.Errorf("PluginRead %v %v: %v",
			dcrdata.PluginID, dcrdata.CmdBestBlock, err)
	}

	// Handle response
	var bbr dcrdata.BestBlockReply
	err = json.Unmarshal([]byte(reply), &bbr)
	if err != nil {
		return 0, err
	}
	if bbr.Height == 0 {
		return 0, errors.Errorf("invalid best block height 0")
	}

	return bbr.Height, nil
}

// authDetailsEncode encodes a AuthDetails into a BlobEntry.
func authDetailsEncode(ad ticketvote.AuthDetails) (*store.BlobEntry, error) {
	data, err := json.Marshal(ad)
	if err != nil {
		return nil, err
	}
	dh := store.DataHint{
		Type:       store.DataTypeStructure,
		Descriptor: dataDescriptorAuthDetails,
	}
	return store.NewBlobEntry(dh, data)
}

// authDetailsDecode decodes a BlobEntry into a AuthDetails.
func authDetailsDecode(be store.BlobEntry) (*ticketvote.AuthDetails, error) {
	b, err := store.Decode(be, dataDescriptorAuthDetails)
	if err != nil {
		return nil, err
	}
	var ad ticketvote.AuthDetails
	err = json.Unmarshal(b, &ad)
	if err != nil {
		return nil, err
	}
	return &ad, nil
}

// authDetailsSave saves a AuthDetails to the backend.
func authDetailsSave(tstore plugins.TstoreClient, token []byte, ad ticketvote.AuthDetails) error {
	// Prepare blob
	be, err := authDetailsEncode(ad)
	if err != nil {
		return err
	}

	// Save blob
	return tstore.BlobSave(token, *be)
}

// authDetails returns all AuthDetails for a record.
func authDetails(tstore plugins.TstoreClient, token []byte) ([]ticketvote.AuthDetails, error) {
	// Retrieve blobs
	blobs, err := tstore.BlobsByDataDesc(token,
		[]string{dataDescriptorAuthDetails})
	if err != nil {
		return nil, err
	}

	// Decode blobs
	auths := make([]ticketvote.AuthDetails, 0, len(blobs))
	for _, v := range blobs {
		a, err := authDetailsDecode(v)
		if err != nil {
			return nil, err
		}
		auths = append(auths, *a)
	}

	// Sanity check. They should already be sorted from
	// oldest to newest.
	sort.SliceStable(auths, func(i, j int) bool {
		return auths[i].Timestamp < auths[j].Timestamp
	})

	return auths, nil
}

// voteDetailsEncode encodes a VoteDetails into a BlobEntry.
func voteDetailsEncode(vd ticketvote.VoteDetails) (*store.BlobEntry, error) {
	data, err := json.Marshal(vd)
	if err != nil {
		return nil, err
	}
	dh := store.DataHint{
		Type:       store.DataTypeStructure,
		Descriptor: dataDescriptorVoteDetails,
	}
	return store.NewBlobEntry(dh, data)
}

// voteDetailsDecode decodes a BlobEntry into a VoteDetails.
func voteDetailsDecode(be store.BlobEntry) (*ticketvote.VoteDetails, error) {
	b, err := store.Decode(be, dataDescriptorVoteDetails)
	if err != nil {
		return nil, err
	}
	var vd ticketvote.VoteDetails
	err = json.Unmarshal(b, &vd)
	if err != nil {
		return nil, err
	}
	return &vd, nil
}

// voteDetailsSave saves a VoteDetails to the backend.
func voteDetailsSave(tstore plugins.TstoreClient, token []byte, vd ticketvote.VoteDetails) error {
	// Prepare blob
	be, err := voteDetailsEncode(vd)
	if err != nil {
		return err
	}

	// Save blob
	return tstore.BlobSave(token, *be)
}

// voteDetails returns the VoteDetails for a record. nil is returned if a
// VoteDetails is not found.
func voteDetails(tstore plugins.TstoreClient, token []byte) (*ticketvote.VoteDetails, error) {
	// Retrieve blobs
	blobs, err := tstore.BlobsByDataDesc(token,
		[]string{dataDescriptorVoteDetails})
	if err != nil {
		return nil, err
	}
	switch len(blobs) {
	case 0:
		// A vote details does not exist
		return nil, nil
	case 1:
		// A vote details exists; continue
	default:
		// This should not happen. There should only ever be a max of
		// one vote details.
		return nil, errors.Errorf("multiple vote details found (%v) on %x",
			len(blobs), token)
	}

	// Decode blob
	vd, err := voteDetailsDecode(blobs[0])
	if err != nil {
		return nil, err
	}

	return vd, nil
}

// voteDetailsForRecord uses the backend interface to fetch and return the
// VoteDetails for a record. nil is returned if a VoteDetails is not found.
func voteDetailsForRecord(backend backend.Backend, token []byte) (*ticketvote.VoteDetails, error) {
	reply, err := backend.PluginRead(token, ticketvote.PluginID,
		ticketvote.CmdDetails, "")
	if err != nil {
		return nil, err
	}
	var dr ticketvote.DetailsReply
	err = json.Unmarshal([]byte(reply), &dr)
	if err != nil {
		return nil, err
	}
	return dr.Vote, nil
}

// voteResults returns the votes that were cast during a ticket vote.
func voteResults(tstore plugins.TstoreClient, token []byte) ([]ticketvote.CastVoteDetails, error) {
	/* TODO
	// Retrieve the blobs for the cast votes and the vote
	// colliders. A cast vote is not valid unless there is a
	// corresponding vote collider. If there are multiple
	// votes that use the same ticket, the valid vote is the
	// one that immediately precedes the vote collider entry.
	desc := []string{
		dataDescriptorCastVoteDetails,
		dataDescriptorVoteCollider,
	}
	blobs, err := tstore.BlobsByDataDesc(token, desc)
	if err != nil {
		return nil, err
	}
	var (
		// map[ticket]CastVoteDetails
		votes = make(map[string]ticketvote.CastVoteDetails, len(blobs))

		// map[ticket][]index
		voteIndexes = make(map[string][]int, len(blobs))

		// map[ticket]index
		colliderIndexes = make(map[string]int, len(blobs))
	)
	for i, v := range blobs {
		// Decode data hint
		b, err := base64.StdEncoding.DecodeString(v.DataHint)
		if err != nil {
			return nil, err
		}
		var dh store.DataHint
		err = json.Unmarshal(b, &dh)
		if err != nil {
			return nil, err
		}
		switch dh.Descriptor {
		case dataDescriptorCastVoteDetails:
			// Decode cast vote
			cv, err := convertCastVoteDetailsFromBlobEntry(v)
			if err != nil {
				return nil, err
			}

			// Save index of the cast vote
			idx, ok := voteIndexes[cv.Ticket]
			if !ok {
				idx = make([]int, 0, 32)
			}
			idx = append(idx, i)
			voteIndexes[cv.Ticket] = idx

			// Save the cast vote
			votes[cv.Ticket] = *cv

		case dataDescriptorVoteCollider:
			// Decode vote collider
			vc, err := convertVoteColliderFromBlobEntry(v)
			if err != nil {
				return nil, err
			}

			// Sanity check
			_, ok := colliderIndexes[vc.Ticket]
			if ok {
				return nil, errors.Errorf("duplicate vote "+
					"colliders found %v", vc.Ticket)
			}

			// Save the ticket and index for the collider
			colliderIndexes[vc.Ticket] = i

		default:
			return nil, errors.Errorf("invalid data descriptor: %v",
				dh.Descriptor)
		}
	}

	for ticket, indexes := range voteIndexes {
		// Remove any votes that do not have a
		// corresponding vote collider.
		colliderIndex, ok := colliderIndexes[ticket]
		if !ok {
			// This is not a valid vote
			delete(votes, ticket)
			continue
		}

		// If multiple votes have been cast using the
		// same ticket then we must manually determine
		// which vote is valid.
		if len(indexes) == 1 {
			// Only one cast vote exists for
			// this ticket. This is correct.
			continue
		}

		// Sanity check
		if len(indexes) == 0 {
			return nil, errors.Errorf("cast vote index not found %v", ticket)
		}

		log.Tracef("Multiple votes found for a single vote collider %v", ticket)

		// Multiple votes exist for this ticket. The valid vote
		// vote is the one that immediately precedes the vote
		// collider. Start at the end of the vote indexes and
		// find the first vote index that precedes the collider
		// index.
		var validVoteIndex int
		for i := len(indexes) - 1; i >= 0; i-- {
			voteIndex := indexes[i]
			if voteIndex < colliderIndex {
				// This is the valid vote
				validVoteIndex = voteIndex
				break
			}
		}

		// Save the valid vote
		b := blobs[validVoteIndex]
		cv, err := convertCastVoteDetailsFromBlobEntry(b)
		if err != nil {
			return nil, err
		}
		votes[cv.Ticket] = *cv
	}

	// Put votes into an array
	cvotes := make([]ticketvote.CastVoteDetails, 0, len(blobs))
	for _, v := range votes {
		cvotes = append(cvotes, v)
	}

	// Sort by ticket hash
	sort.SliceStable(cvotes, func(i, j int) bool {
		return cvotes[i].Ticket < cvotes[j].Ticket
	})

	return cvotes, nil
	*/
	return nil, nil
}

// caseVoteDetailsEncode encodes a CastVoteDetails into a BlobEntry.
func castVoteDetailsEncode(cv ticketvote.CastVoteDetails) (*store.BlobEntry, error) {
	data, err := json.Marshal(cv)
	if err != nil {
		return nil, err
	}
	dh := store.DataHint{
		Type:       store.DataTypeStructure,
		Descriptor: dataDescriptorCastVoteDetails,
	}
	return store.NewBlobEntry(dh, data)
}

// castVoteDetailsDecode decodes a BlobEntry into a CastVoteDetails.
func castVoteDetailsDecode(be store.BlobEntry) (*ticketvote.CastVoteDetails, error) {
	b, err := store.Decode(be, dataDescriptorCastVoteDetails)
	if err != nil {
		return nil, err
	}
	var cvd ticketvote.CastVoteDetails
	err = json.Unmarshal(b, &cvd)
	if err != nil {
		return nil, err
	}
	return &cvd, nil
}

// recordAbridged returns a record where the only record file returned is the
// vote metadata file if one exists.
func recordAbridged(b backend.Backend, token []byte) (*backend.Record, error) {
	reqs := []backend.RecordRequest{
		{
			Token: token,
			Filenames: []string{
				ticketvote.FileNameVoteMetadata,
			},
		},
	}
	rs, err := b.Records(reqs)
	if err != nil {
		return nil, err
	}
	r, ok := rs[encodeToken(token)]
	if !ok {
		return nil, backend.ErrRecordNotFound
	}
	return &r, nil
}

// encodeToken encodes the provided byte slice into a hex encoded record token.
func encodeToken(token []byte) string {
	return util.TokenEncode(token)
}

// decodeToken decodes a record token. This function will return an error if
// the token is not a full length token.
func decodeToken(token string) ([]byte, error) {
	return util.TokenDecode(util.TokenTypeTstore, token)
}

// tokenMatches verifies that the command token (the token for the record that
// this plugin command is being executed on) matches the payload token (the
// token that the plugin command payload contains that is typically used in the
// payload signature). The payload token must be the full length token.
func tokenMatches(cmdToken []byte, payloadToken string) error {
	pt, err := decodeToken(payloadToken)
	if err != nil {
		return backend.PluginError{
			PluginID:     ticketvote.PluginID,
			ErrorCode:    uint32(ticketvote.ErrorCodeTokenInvalid),
			ErrorContext: util.TokenRegexp(),
		}
	}
	if !bytes.Equal(cmdToken, pt) {
		return backend.PluginError{
			PluginID:  ticketvote.PluginID,
			ErrorCode: uint32(ticketvote.ErrorCodeTokenInvalid),
			ErrorContext: fmt.Sprintf("payload token does not "+
				"match cmd token: got %x, want %x", pt, cmdToken),
		}
	}
	return nil
}

// verifySignature provides a wrapper around the util VerifySignature method
// that converts any returned errors into ticketvote plugin errors.
func verifySignature(signature, pubkey, msg string) error {
	err := util.VerifySignature(signature, pubkey, msg)
	if err != nil {
		return convertSignatureError(err)
	}
	return nil
}

// convertSignatureError converts a util SignatureError to a backend
// PluginError with a ticketvote plugin error.
func convertSignatureError(err error) backend.PluginError {
	var e util.SignatureError
	var s ticketvote.ErrorCodeT
	if errors.As(err, &e) {
		switch e.ErrorCode {
		case util.ErrorStatusPublicKeyInvalid:
			s = ticketvote.ErrorCodePublicKeyInvalid
		case util.ErrorStatusSignatureInvalid:
			s = ticketvote.ErrorCodeSignatureInvalid
		}
	}
	return backend.PluginError{
		PluginID:     ticketvote.PluginID,
		ErrorCode:    uint32(s),
		ErrorContext: e.ErrorContext,
	}
}

// decodeVoteMetadata decodes and returns the VoteMetadata from the
// provided backend files. nil is returned if a VoteMetadata is not found.
func decodeVoteMetadata(files []backend.File) (*ticketvote.VoteMetadata, error) {
	var voteMD *ticketvote.VoteMetadata
	for _, v := range files {
		if v.Name != ticketvote.FileNameVoteMetadata {
			continue
		}
		b, err := base64.StdEncoding.DecodeString(v.Payload)
		if err != nil {
			return nil, err
		}
		var m ticketvote.VoteMetadata
		err = json.Unmarshal(b, &m)
		if err != nil {
			return nil, err
		}
		voteMD = &m
		break
	}
	return voteMD, nil
}
