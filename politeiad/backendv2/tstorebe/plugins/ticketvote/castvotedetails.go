// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"sort"

	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	"github.com/decred/politeia/util"
	"github.com/pkg/errors"
)

// castVoteDetails is the local representation of the v1 CastVoteDetails
// structure. This is done so that it can be extended with struct methods and
// additional functionality. See the v1 CastVoteDetails for struct
// documentation.
type castVoteDetails struct {
	Token     string `json:"token"`
	Ticket    string `json:"ticket"`
	VoteBit   string `json:"votebit"`
	Signature string `json:"signature"`
	Address   string `json:"address"`
	Receipt   string `json:"receipt"`
	Timestamp int64  `json:"timestamp"`
}

// convert converts the castVoteDetails into a v1 CastVoteDetails.
func (c *castVoteDetails) convert() ticketvote.CastVoteDetails {
	return ticketvote.CastVoteDetails{
		Token:     c.Token,
		Ticket:    c.Ticket,
		VoteBit:   c.VoteBit,
		Signature: c.Signature,
		Address:   c.Address,
		Timestamp: c.Timestamp,
	}
}

// encode encodes the castVoteDetails into a BlobEntry.
func (c *castVoteDetails) encode() (*store.BlobEntry, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	dh := store.DataHint{
		Type:       store.DataTypeStructure,
		Descriptor: dataDescriptorCastVoteDetails,
	}
	return store.NewBlobEntry(dh, data)
}

// save saves the castVoteDetails to the database.
func (c *castVoteDetails) save(tstore plugins.TstoreClient) error {
	token, err := decodeToken(c.Token)
	if err != nil {
		return err
	}
	be, err := c.encode()
	if err != nil {
		return err
	}
	return tstore.BlobSave(token, *be)
}

// decodeCastVoteDetails decodes a BlobEntry into a castVoteDetails.
func decodeCastVoteDetails(be store.BlobEntry) (*castVoteDetails, error) {
	b, err := store.Decode(be, dataDescriptorCastVoteDetails)
	if err != nil {
		return nil, err
	}
	var cvd castVoteDetails
	err = json.Unmarshal(b, &cvd)
	if err != nil {
		return nil, err
	}
	return &cvd, nil
}

// getAllCastVoteDetails returns the castVoteDetails for all votes that were
// cast during a ticket vote.
func getAllCastVoteDetails(tstore plugins.TstoreClient, token []byte) ([]castVoteDetails, error) {
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
		votes = make(map[string]castVoteDetails, len(blobs))

		// map[ticket][]index
		voteIndexes = make(map[string][]int, len(blobs))

		// map[ticket]index
		colliderIndexes = make(map[string]int, len(blobs))
	)
	for i, v := range blobs {
		// Decode data hint
		dh, err := store.DecodeDataHint(v)
		if err != nil {
			return nil, err
		}
		switch dh.Descriptor {
		case dataDescriptorCastVoteDetails:
			// Decode cast vote
			cv, err := decodeCastVoteDetails(v)
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
			vc, err := decodeVoteCollider(v)
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
		cv, err := decodeCastVoteDetails(b)
		if err != nil {
			return nil, err
		}
		votes[cv.Ticket] = *cv
	}

	// Put votes into an array
	cvotes := make([]castVoteDetails, 0, len(blobs))
	for _, v := range votes {
		cvotes = append(cvotes, v)
	}

	// Sort by ticket hash
	sort.SliceStable(cvotes, func(i, j int) bool {
		return cvotes[i].Ticket < cvotes[j].Ticket
	})

	return cvotes, nil
}

// verifyCastVoteSignature verifies the signature of a CastVote. The signature
// must be created using the largest commitment address from the ticket that is
// casting a vote.
func verifyCastVoteSignature(cv ticketvote.CastVote, addr string, net *chaincfg.Params) error {
	msg := cv.Token + cv.Ticket + cv.VoteBit

	// Convert hex signature to base64. This is
	// what the verify message function expects.
	b, err := hex.DecodeString(cv.Signature)
	if err != nil {
		return errors.Errorf("invalid hex")
	}
	sig := base64.StdEncoding.EncodeToString(b)

	// Verify message
	validated, err := util.VerifyMessage(addr, msg, sig, net)
	if err != nil {
		return err
	}
	if !validated {
		return errors.Errorf("could not verify message")
	}

	return nil
}
