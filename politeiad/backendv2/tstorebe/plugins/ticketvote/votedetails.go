// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import (
	"encoding/json"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	"github.com/pkg/errors"
)

// voteDetails is the local representation of the v1 VoteDetails structure.
// This is done so that it can be extended with struct methods and additional
// functionality. See the v1 VoteDetails for struct documentation.
type voteDetails struct {
	Params           voteParams `json:"params"`
	PublicKey        string     `json:"publickey"`
	Signature        string     `json:"signature"`
	Receipt          string     `json:"receipt"`
	StartBlockHeight uint32     `json:"startblockheight"`
	StartBlockHash   string     `json:"startblockhash"`
	EndBlockHeight   uint32     `json:"endblockheight"`
	EligibleTickets  []string   `json:"eligibletickets"`
}

// convert converts the voteDetails into a v1 VoteDetails.
func (d *voteDetails) convert() ticketvote.VoteDetails {
	return ticketvote.VoteDetails{
		Params:           d.Params.convert(),
		PublicKey:        d.PublicKey,
		Signature:        d.Signature,
		Receipt:          d.Receipt,
		StartBlockHeight: d.StartBlockHeight,
		StartBlockHash:   d.StartBlockHash,
		EndBlockHeight:   d.EndBlockHeight,
		EligibleTickets:  d.EligibleTickets,
	}
}

// encode encodes the voteDetails into a BlobEntry.
func (d *voteDetails) encode() (*store.BlobEntry, error) {
	data, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	dh := store.DataHint{
		Type:       store.DataTypeStructure,
		Descriptor: dataDescriptorVoteDetails,
	}
	return store.NewBlobEntry(dh, data)
}

// save saves the voteDetails to the database.
func (d *voteDetails) save(tstore plugins.TstoreClient, token []byte) error {
	be, err := d.encode()
	if err != nil {
		return err
	}
	return tstore.BlobSave(token, *be)
}

// decodeVoteDetails decodes a BlobEntry into a voteDetails.
func decodeVoteDetails(be store.BlobEntry) (*voteDetails, error) {
	b, err := store.Decode(be, dataDescriptorVoteDetails)
	if err != nil {
		return nil, err
	}
	var vd voteDetails
	err = json.Unmarshal(b, &vd)
	if err != nil {
		return nil, err
	}
	return &vd, nil
}

// getVoteDetails returns the voteDetails for a record. nil is returned if a
// voteDetails is not found.
func getVoteDetails(tstore plugins.TstoreClient, token []byte) (*voteDetails, error) {
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
		// This should not happen. There should only ever
		// be one vote details object.
		return nil, errors.Errorf("multiple vote details "+
			"found (%v) on %x", len(blobs), token)
	}

	// Decode blob
	vd, err := decodeVoteDetails(blobs[0])
	if err != nil {
		return nil, err
	}

	return vd, nil
}

// getVoteDetailsForRecord uses the backend interface to fetch and return the
// VoteDetails for a record. nil is returned if a VoteDetails is not found.
func getVoteDetailsForRecord(backend backend.Backend, token []byte) (*ticketvote.VoteDetails, error) {
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

// voteParams is the local representation of the v1 VoteParams structure. See
// the v1 VoteParams for struct documentation.
type voteParams struct {
	Token            string       `json:"token"`
	Version          uint32       `json:"version"`
	Type             uint32       `json:"type"`
	Mask             uint64       `json:"mask"`
	Duration         uint32       `json:"duration"`
	QuorumPercentage uint32       `json:"quorumpercentage"`
	PassPercentage   uint32       `json:"passpercentage"`
	Options          []voteOption `json:"options"`
	Parent           string       `json:"parent,omitempty"`
}

// convertVoteParamsToLocal converts a v1 VoteParams to a local voteParams.
func convertVoteParamsToLocal(p ticketvote.VoteParams) voteParams {
	options := make([]voteOption, 0, len(p.Options))
	for _, v := range p.Options {
		options = append(options, convertVoteOptionToLocal(v))
	}
	return voteParams{
		Token:            p.Token,
		Version:          p.Version,
		Type:             uint32(p.Type),
		Mask:             p.Mask,
		Duration:         p.Duration,
		QuorumPercentage: p.QuorumPercentage,
		PassPercentage:   p.PassPercentage,
		Options:          options,
		Parent:           p.Parent,
	}
}

// convert converts the voteParams to a v1 VoteParams.
func (p *voteParams) convert() ticketvote.VoteParams {
	options := make([]ticketvote.VoteOption, 0, len(p.Options))
	for _, v := range p.Options {
		options = append(options, v.convert())
	}
	return ticketvote.VoteParams{
		Token:            p.Token,
		Version:          p.Version,
		Type:             ticketvote.VoteT(p.Type),
		Mask:             p.Mask,
		Duration:         p.Duration,
		QuorumPercentage: p.QuorumPercentage,
		PassPercentage:   p.PassPercentage,
		Options:          options,
		Parent:           p.Parent,
	}
}

// voteOption is the local representation of the v1 VoteOption structure. See
// the v1 VoteOption for struct documentation.
type voteOption struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Bit         uint64 `json:"bit"`
}

// convertVoteOptionToLocal converts a v1 VoteOption to a local voteOption.
func convertVoteOptionToLocal(o ticketvote.VoteOption) voteOption {
	return voteOption{
		ID:          o.ID,
		Description: o.Description,
		Bit:         o.Bit,
	}
}

// convert converts the voteOption to a v1 VoteOption.
func (o *voteOption) convert() ticketvote.VoteOption {
	return ticketvote.VoteOption{
		ID:          o.ID,
		Description: o.Description,
		Bit:         o.Bit,
	}
}
