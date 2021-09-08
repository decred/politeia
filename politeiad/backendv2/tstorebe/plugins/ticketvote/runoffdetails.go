// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import (
	"encoding/json"

	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
	"github.com/pkg/errors"
)

// runoffDetails contains the vote params for a runoff vote. This structure is
// saved to the runoff vote's parent record as the first step in starting a
// runoff vote. Plugins are not able to update multiple records atomically, so
// if the start runoff vote call gets interrupted before it can start the
// voting period on all runoff vote submissions, subsequent calls will use this
// record to pick up where the previous call left off. This allows us to
// recover from unexpected errors, such as network errors, and not leave a
// runoff vote in a weird state.
type runoffDetails struct {
	Submissions      []string `json:"submissions"`
	Mask             uint64   `json:"mask"`
	Duration         uint32   `json:"duration"`
	QuorumPercentage uint32   `json:"quorumpercentage"`
	PassPercentage   uint32   `json:"passpercentage"`
	StartBlockHeight uint32   `json:"startblockheight"`
	StartBlockHash   string   `json:"startblockhash"`
	EndBlockHeight   uint32   `json:"endblockheight"`
	EligibleTickets  []string `json:"eligibletickets"`
}

// encode encodes the runoffDetails into a BlobEntry.
func (r *runoffDetails) encode() (*store.BlobEntry, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	dd := store.DataDescriptor{
		Type:       store.DataTypeStructure,
		Descriptor: dataDescriptorRunoffDetails,
	}
	return store.NewBlobEntry(dd, data)
}

// save saves the runoff details record to the database.
func (r *runoffDetails) save(tstore plugins.TstoreClient, token []byte) error {
	be, err := r.encode()
	if err != nil {
		return err
	}
	return tstore.BlobSave(token, *be)
}

// decodeRunoffDetails decodes a BlobEntry into a runoffDetails.
func decodeRunoffDetails(be store.BlobEntry) (*runoffDetails, error) {
	b, err := store.Decode(be, dataDescriptorRunoffDetails)
	if err != nil {
		return nil, err
	}
	var rd runoffDetails
	err = json.Unmarshal(b, &rd)
	if err != nil {
		return nil, err
	}
	return &rd, nil
}

// getRunoffDetails returns the runoffDetails for a record. nil is returned if
// a runoffDetails is not found.
func getRunoffDetails(tstore plugins.TstoreClient, token []byte) (*runoffDetails, error) {
	blobs, err := tstore.BlobsByDataDesc(token,
		[]string{dataDescriptorRunoffDetails})
	if err != nil {
		return nil, err
	}

	switch len(blobs) {
	case 0:
		// Nothing found
		return nil, nil
	case 1:
		// This is expected; continue
	default:
		// This should not be possible
		return nil, errors.Errorf("multiple (%v) runoff details found",
			len(blobs))
	}

	return decodeRunoffDetails(blobs[0])
}
