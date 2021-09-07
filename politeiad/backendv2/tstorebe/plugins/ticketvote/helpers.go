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

// authEncode encodes a AuthDetails into a BlobEntry.
func authEncode(ad ticketvote.AuthDetails) (*store.BlobEntry, error) {
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

// authDecode decodes a BlobEntry into a AuthDetails.
func authDecode(be store.BlobEntry) (*ticketvote.AuthDetails, error) {
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

// authSave saves a AuthDetails to the backend.
func authSave(tstore plugins.TstoreClient, token []byte, ad ticketvote.AuthDetails) error {
	// Prepare blob
	be, err := authEncode(ad)
	if err != nil {
		return err
	}

	// Save blob
	return tstore.BlobSave(token, *be)
}

// auths returns all AuthDetails for a record.
func auths(tstore plugins.TstoreClient, token []byte) ([]ticketvote.AuthDetails, error) {
	// Retrieve blobs
	blobs, err := tstore.BlobsByDataDesc(token,
		[]string{dataDescriptorAuthDetails})
	if err != nil {
		return nil, err
	}

	// Decode blobs
	auths := make([]ticketvote.AuthDetails, 0, len(blobs))
	for _, v := range blobs {
		a, err := authDecode(v)
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
