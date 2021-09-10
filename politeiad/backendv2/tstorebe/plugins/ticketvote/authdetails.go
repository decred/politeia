// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import (
	"encoding/json"
	"sort"

	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
)

// authDetails is the local representation of the v1 AuthDetails structure.
// This is done so that it can be extended with struct methods and additional
// functionality. See the v1 AuthDetails for struct documentation.
type authDetails struct {
	Token     string `json:"token"`
	Version   uint32 `json:"version"`
	Action    string `json:"action"`
	PublicKey string `json:"publickey"`
	Signature string `json:"signature"`
	Timestamp int64  `json:"timestamp"`
	Receipt   string `json:"receipt"`
}

// convert converts the authDetails to a v1 AuthDetails.
func (a *authDetails) convert() ticketvote.AuthDetails {
	return ticketvote.AuthDetails{
		Token:     a.Token,
		Version:   a.Version,
		Action:    a.Action,
		PublicKey: a.PublicKey,
		Signature: a.Signature,
		Timestamp: a.Timestamp,
		Receipt:   a.Receipt,
	}
}

// encode encodes the ticketvote AuthDetails into a BlobEntry.
func (a *authDetails) encode() (*store.BlobEntry, error) {
	data, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	dh := store.DataHint{
		Type:       store.DataTypeStructure,
		Descriptor: dataDescriptorAuthDetails,
	}
	return store.NewBlobEntry(dh, data)
}

// authDetailsSave saves the authDetails to the database as a BlobEntry.
func (a *authDetails) save(tstore plugins.TstoreClient, token []byte) error {
	be, err := a.encode()
	if err != nil {
		return err
	}
	return tstore.BlobSave(token, *be)
}

// decodeAuthDetails decodes a BlobEntry into a authDetails.
func decodeAuthDetails(be store.BlobEntry) (*authDetails, error) {
	b, err := store.Decode(be, dataDescriptorAuthDetails)
	if err != nil {
		return nil, err
	}
	var ad authDetails
	err = json.Unmarshal(b, &ad)
	if err != nil {
		return nil, err
	}
	return &ad, nil
}

// getAllAuthDetails returns all authDetails for a record.
func getAllAuthDetails(tstore plugins.TstoreClient, token []byte) ([]authDetails, error) {
	// Retrieve blobs
	blobs, err := tstore.BlobsByDataDesc(token,
		[]string{dataDescriptorAuthDetails})
	if err != nil {
		return nil, err
	}

	// Decode blobs
	auths := make([]authDetails, 0, len(blobs))
	for _, v := range blobs {
		a, err := decodeAuthDetails(v)
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
