// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import (
	"bytes"
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

// tokenDecode decodes a record token. This function will return an error if
// the token is not a full length token.
func tokenDecode(token string) ([]byte, error) {
	return util.TokenDecode(util.TokenTypeTstore, token)
}

// tokenMatches verifies that the command token (the token for the record that
// this plugin command is being executed on) matches the payload token (the
// token that the plugin command payload contains that is typically used in the
// payload signature). The payload token must be the full length token.
func tokenMatches(cmdToken []byte, payloadToken string) error {
	pt, err := tokenDecode(payloadToken)
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
	dd := store.DataDescriptor{
		Type:       store.DataTypeStructure,
		Descriptor: dataDescriptorAuthDetails,
	}
	return store.NewBlobEntry(dd, data)
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
	dd := store.DataDescriptor{
		Type:       store.DataTypeStructure,
		Descriptor: dataDescriptorVoteDetails,
	}
	return store.NewBlobEntry(dd, data)
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
// VoteDetails for a record. nil is returned if the vote details are not found.
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
