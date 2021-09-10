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
	allAuths, err := getAllAuthDetails(tstore, token)
	if err != nil {
		return "", err
	}

	// Get vote details
	vd, err := getVoteDetails(tstore, token)
	if err != nil {
		return "", err
	}

	// Prepare rely
	auths := make([]ticketvote.AuthDetails, 0, len(allAuths))
	for _, v := range allAuths {
		auths = append(auths, v.convert())
	}
	var vote *ticketvote.VoteDetails
	if vd != nil {
		v := vd.convert()
		vote = &v
	}
	dr := ticketvote.DetailsReply{
		Auths: auths,
		Vote:  vote,
	}
	reply, err := json.Marshal(dr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// cmdResults returns the votes that were cast during a ticket vote.
func (p *plugin) cmdResults(tstore plugins.TstoreClient, token []byte) (string, error) {
	// Get all votes that were cast
	castVotes, err := getAllCastVoteDetails(tstore, token)
	if err != nil {
		return "", err
	}

	// Prepare reply
	votes := make([]ticketvote.CastVoteDetails, 0, len(castVotes))
	for _, v := range castVotes {
		votes = append(votes, v.convert())
	}
	rr := ticketvote.ResultsReply{
		Votes: votes,
	}
	reply, err := json.Marshal(rr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// cmdSummary requests the vote summary for a record.
func (p *plugin) cmdSummary(tstore plugins.TstoreClient, token []byte) (string, error) {
	/* TODO
	// Get the best block. This cmd does not write
	// any data so we can use the unsafe best block
	// function.
	bb, err := bestBlockUnsafe(p.backend)
	if err != nil {
		return "", err
	}

	// Get the vote summary
	sr, err := summary(token, bb)
	if err != nil {
		return "", err
	}

	// Prepare the reply
	reply, err := json.Marshal(sr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
	*/

	return "", nil
}
