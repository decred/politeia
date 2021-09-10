// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import (
	"encoding/json"
	"strings"

	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
	v1 "github.com/decred/politeia/politeiad/plugins/ticketvote"
	"github.com/decred/politeia/util"
)

const (
	// voteSummaryKey is the key-value store key for a record's vote
	// summary.
	//
	// {shorttoken} is replaced by the record's short token. This
	// allows the vote summary to still be retrieved if the client
	// only provides the short token.
	voteSummaryKey = pluginID + "-{shorttoken}-summary-v1"
)

// voteSummary is the local representation of the v1 VoteSummaryReply
// structure. This is done so that it can be extended with struct methods
// and additional functionality. See the v1 VoteSummaryReply for struct
// documentation.
type voteSummary struct {
	Status           v1.VoteStatusT        `json:"status"`
	Type             v1.VoteT              `json:"type,omitempty"`
	Duration         uint32                `json:"duration,omitempty"`
	StartBlockHeight uint32                `json:"startblockheight,omitempty"`
	StartBlockHash   string                `json:"startblockhash,omitempty"`
	EndBlockHeight   uint32                `json:"endblockheight,omitempty"`
	EligibleTickets  uint32                `json:"eligibletickets,omitempty"`
	QuorumPercentage uint32                `json:"quorumpercentage,omitempty"`
	PassPercentage   uint32                `json:"passpercentage,omitempty"`
	Results          []v1.VoteOptionResult `json:"results,omitempty"`
	BestBlock        uint32                `json:"bestblock"`
}

// convert converts the voteSummary into a v1 SummaryReply.
func (s *voteSummary) convert() v1.SummaryReply {
	return v1.SummaryReply{
		Status:           s.Status,
		Type:             s.Type,
		Duration:         s.Duration,
		StartBlockHeight: s.StartBlockHeight,
		StartBlockHash:   s.StartBlockHash,
		EndBlockHeight:   s.EndBlockHeight,
		EligibleTickets:  s.EligibleTickets,
		QuorumPercentage: s.QuorumPercentage,
		PassPercentage:   s.PassPercentage,
		Results:          s.Results,
		BestBlock:        s.BestBlock,
	}
}

// save saves the voteSummary to the cache.
func (s *voteSummary) save(tstore plugins.TstoreClient, token []byte) error {
	// Encode payload
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}

	// Get kv store key
	k, err := getVoteSummaryKey(token)
	if err != nil {
		return err
	}

	// Save vote summary
	c := tstore.CacheClient(false)
	kv := map[string][]byte{k: b}
	err = c.Update(kv)
	if err == store.ErrNotFound {
		// This is the first time the summary
		// is being saved. Insert it.
		err = c.Insert(kv)
	}
	if err != nil {
		return err
	}

	log.Debugf("Vote summary cached: %v", token)

	return nil
}

// getVoteSummary returns the cached voteSummary for the provided token. An
// ErrNotFound error is returned if a summary is not found.
func getVoteSummary(tstore plugins.TstoreClient, token []byte) (*voteSummary, error) {
	k, err := getVoteSummaryKey(token)
	if err != nil {
		return nil, err
	}
	c := tstore.CacheClient(false)
	b, err := c.Get(k)
	if err != nil {
		return nil, err
	}
	var vs voteSummary
	err = json.Unmarshal(b, &vs)
	if err != nil {
		return nil, err
	}
	return &vs, nil
}

/*
// TODO
// getVoteSummaryForBlock returns a record's vote summary after updating it for
// the provided block height.
func getVoteSummaryForBlock(token []byte, bestBlock uint32) (*voteSummary, error) {
	// Get cached vote summary if one exists
	s, err := getVoteSummary(token)
	switch {
	case errors.Is(err, store.ErrNotFound):
		// A vote summary has not been cached for
		// this record yet. Continue below to build
		// one manually.

	case err == nil:
		// A cached vote summary was found for this
		// record. Update the best block and return
		// it.
		s.BestBlock = bestBlock
		return s, nil

	default:
		// All other errors
		return nil, err
	}

	// Assume that the vote is unauthorized. The
	// status is only updated once the appropriate
	// data has been found that proves otherwise.
	status := v1.VoteStatusUnauthorized

	// Get the vote authorizations for this record.
	// The most recent authorization is the one that
	// should be checked. Note, not all vote types
	// require a vote authorization.
	auths, err := getAllAuthDetails(tstore, token)
	if err != nil {
		return nil, err
	}
	if len(auths) > 0 {
		auth := auths[len(auths)-1]
		switch v1.AuthActionT(auth.Action) {
		case v1.AuthActionAuthorize:
			// Vote has been authorized; continue
			status = v1.VoteStatusAuthorized
		case v1.AuthActionRevoke:
			// The vote authorization has been revoked.
			// It's not possible for the vote to have
			// been started. We can stop looking.
			return &voteSummary{
				Status:    status,
				Results:   []voteOptionResult{},
				BestBlock: bestBlock,
			}, nil
		}
	}

	// Check if the vote has been started
	vd, err := getVoteDetails(tstore, token)
	if err != nil {
		return nil, err
	}
	if vd == nil {
		// Vote has not been started yet
		return &summaryReply{
			Status:    status,
			Results:   []v1.VoteOptionResult{},
			BestBlock: bestBlock,
		}, nil
	}

	// Vote has been started. We need to check
	// if the vote has ended yet and if it can
	// be considered approved or rejected.
	status = v1.VoteStatusStarted

	// Tally vote results
	results, err := p.voteOptionResults(token, vd.Params.Options)
	if err != nil {
		return nil, err
	}

	// Prepare summary
	summary := voteSummary{
		Type:             vd.Params.Type,
		Status:           status,
		Duration:         vd.Params.Duration,
		StartBlockHeight: vd.StartBlockHeight,
		StartBlockHash:   vd.StartBlockHash,
		EndBlockHeight:   vd.EndBlockHeight,
		EligibleTickets:  uint32(len(vd.EligibleTickets)),
		QuorumPercentage: vd.Params.QuorumPercentage,
		PassPercentage:   vd.Params.PassPercentage,
		Results:          results,
		BestBlock:        bestBlock,
	}

	// If the vote has not finished yet then we are done for now.
	if !voteHasEnded(bestBlock, vd.EndBlockHeight) {
		return &summary, nil
	}

	// The vote has finished. Find whether the vote was approved and cache
	// the vote summary.
	switch vd.Params.Type {
	case v1.VoteTypeStandard:
		// Standard vote uses a simple approve/reject result
		if voteIsApproved(*vd, results) {
			summary.Status = v1.VoteStatusApproved
		} else {
			summary.Status = v1.VoteStatusRejected
		}

		// Cache summary
		err = p.summaryCacheSave(vd.Params.Token, summary)
		if err != nil {
			return nil, err
		}

		// Remove record from the active votes cache
		p.activeVotes.Del(vd.Params.Token)

	case v1.VoteTypeRunoff:
		// A runoff vote requires that we pull all other runoff vote
		// submissions to determine if the vote actually passed.
		summaries, err := p.summariesForRunoff(vd.Params.Parent)
		if err != nil {
			return nil, err
		}
		for k, v := range summaries {
			// Cache summary
			err = p.summaryCacheSave(k, v)
			if err != nil {
				return nil, err
			}

			// Remove record from active votes cache
			p.activeVotes.Del(k)
		}

		summary = summaries[vd.Params.Token]

	default:
		return nil, errors.Errorf("unknown vote type")
	}

	return &summary, nil
}

type voteOptionResult struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	VoteBit     uint64 `json:"votebit"`
	Votes       uint64 `json:"votes"`
}

// getVoteOptionResults tallies the results of a ticket vote and returns a
// voteOptionResult for each vote option.
func getVoteOptionResults(token []byte, options []ticketvote.VoteOption) ([]ticketvote.VoteOptionResult, error) {
	// Ongoing votes will have the cast votes cached. Calculate the results
	// using the cached votes if we can since it will be much faster.
	var (
		tally  = make(map[string]uint32, len(options))
		t      = hex.EncodeToString(token)
		ctally = p.activeVotes.Tally(t)
	)
	switch {
	case len(ctally) > 0:
		// Votes are in the cache. Use the cached results.
		tally = ctally

	default:
		// Votes are not in the cache. Pull them from the backend.
		reply, err := p.backend.PluginRead(token, ticketvote.PluginID,
			ticketvote.CmdResults, "")
		if err != nil {
			return nil, err
		}
		var rr ticketvote.ResultsReply
		err = json.Unmarshal([]byte(reply), &rr)
		if err != nil {
			return nil, err
		}

		// Tally the results
		for _, v := range rr.Votes {
			tally[v.VoteBit]++
		}
	}

	// Prepare reply
	results := make([]ticketvote.VoteOptionResult, 0, len(options))
	for _, v := range options {
		bit := strconv.FormatUint(v.Bit, 16)
		results = append(results, ticketvote.VoteOptionResult{
			ID:          v.ID,
			Description: v.Description,
			VoteBit:     v.Bit,
			Votes:       uint64(tally[bit]),
		})
	}

	return results, nil
}
*/

// getVoteSummaryKey returns the key-value store key for a record's vote
// summary. This function accepts both full length tokens and short tokens.
func getVoteSummaryKey(token []byte) (string, error) {
	tokenb, err := util.ShortToken(token)
	if err != nil {
		return "", err
	}
	t := encodeToken(tokenb)
	k := strings.Replace(voteSummaryKey, "{shorttoken}", t, 1)
	return k, nil
}
