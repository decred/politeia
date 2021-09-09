// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import (
	"encoding/json"

	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
)

// cmdDetails returns the vote details for a record.
func (p *plugin) cmdDetails(tstore plugins.TstoreClient, token []byte) (string, error) {
	// Get vote authorizations
	auths, err := authDetails(tstore, token)
	if err != nil {
		return "", err
	}

	// Get vote details
	vd, err := voteDetails(tstore, token)
	if err != nil {
		return "", err
	}

	// Prepare rely
	dr := ticketvote.DetailsReply{
		Auths: auths,
		Vote:  vd,
	}
	reply, err := json.Marshal(dr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// cmdResults returns the votes that were cast during a ticket vote.
func (p *plugin) cmdResults(tstore plugins.TstoreClient, token []byte) (string, error) {
	// Get vote results
	votes, err := voteResults(tstore, token)
	if err != nil {
		return "", err
	}

	// Prepare reply
	rr := ticketvote.ResultsReply{
		Votes: votes,
	}
	reply, err := json.Marshal(rr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}
