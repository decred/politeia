// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import (
	"encoding/json"

	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
)

// voteCollider is used to prevent duplicate votes at the tlog level. The
// database saves a digest of the data to the trillian log (tlog). tlog does
// not allow leaves with duplicate values, so once a vote colider is saved to
// the database for a ticket it should be impossible for another vote collider
// to be saved to the backend that is voting with the same ticket on the same
// record, regardless of what the vote bits are. The vote collider and the full
// cast vote are saved to the backend at the same time. A cast vote is not
// considered valid unless a corresponding vote collider is present.
type voteCollider struct {
	Token  string `json:"token"`  // Record token
	Ticket string `json:"ticket"` // Ticket hash
}

// encode encodes the voteCollider into a BlobEntry.
func (c *voteCollider) encode() (*store.BlobEntry, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	dh := store.DataHint{
		Type:       store.DataTypeStructure,
		Descriptor: dataDescriptorVoteCollider,
	}
	return store.NewBlobEntry(dh, data)
}

// save saves the vote collider to the database.
func (c *voteCollider) save(tstore plugins.TstoreClient) error {
	be, err := c.encode()
	if err != nil {
		return err
	}
	tokenb, err := decodeToken(c.Token)
	if err != nil {
		return err
	}
	return tstore.BlobSave(tokenb, *be)
}

// decodeVoteCollider decodes a BlobEntry into a voteCollider.
func decodeVoteCollider(be store.BlobEntry) (*voteCollider, error) {
	b, err := store.Decode(be, dataDescriptorVoteCollider)
	if err != nil {
		return nil, err
	}
	var vc voteCollider
	err = json.Unmarshal(b, &vc)
	if err != nil {
		return nil, err
	}
	return &vc, nil
}
