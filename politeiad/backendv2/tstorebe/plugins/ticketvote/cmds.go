// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

/*
import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/decred/dcrd/chaincfg/v3"
	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
	"github.com/decred/politeia/politeiad/plugins/dcrdata"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	"github.com/decred/politeia/util"
)

// cmdRunoffDetails is an internal plugin command that requests the details of
// a runoff vote.
func (p *plugin) cmdRunoffDetails(token []byte) (string, error) {
	// Get start runoff record
	srs, err := p.startRunoffRecord(token)
	if err != nil {
		return "", err
	}

	// Prepare reply
	r := runoffDetailsReply{
		Runoff: *srs,
	}
	reply, err := json.Marshal(r)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// cmdInventory requests a page of tokens for the provided status. If no status
// is provided then a page for each status will be returned.
func (p *plugin) cmdInventory(payload string) (string, error) {
	var i ticketvote.Inventory
	err := json.Unmarshal([]byte(payload), &i)
	if err != nil {
		return "", err
	}

	// Get best block. This command does not write any data so we can
	// use the unsafe best block.
	bb, err := p.bestBlockUnsafe()
	if err != nil {
		return "", errors.Errorf("bestBlockUnsafe: %v", err)
	}

	// Get the inventory
	ibs, err := p.inventoryByStatus(bb, i.Status, i.Page)
	if err != nil {
		return "", errors.Errorf("invByStatus: %v", err)
	}

	// Prepare reply
	tokens := make(map[string][]string, len(ibs.Tokens))
	for k, v := range ibs.Tokens {
		vs := ticketvote.VoteStatuses[k]
		tokens[vs] = v
	}
	ir := ticketvote.InventoryReply{
		Tokens:    tokens,
		BestBlock: ibs.BestBlock,
	}
	reply, err := json.Marshal(ir)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// cmdTimestamps requests the timestamps for a ticket vote.
func (p *plugin) cmdTimestamps(token []byte, payload string) (string, error) {
	// Decode payload
	var t ticketvote.Timestamps
	err := json.Unmarshal([]byte(payload), &t)
	if err != nil {
		return "", err
	}

	var (
		auths   = make([]ticketvote.Timestamp, 0, 32)
		details *ticketvote.Timestamp

		pageSize = ticketvote.VoteTimestampsPageSize
		votes    = make([]ticketvote.Timestamp, 0, pageSize)
	)
	switch {
	case t.VotesPage > 0:
		// Return a page of vote timestamps
		digests, err := tstore.DigestsByDataDesc(token,
			[]string{dataDescriptorCastVoteDetails})
		if err != nil {
			return "", errors.Errorf("digestsByKeyPrefix %x %v: %v",
				token, dataDescriptorVoteDetails, err)
		}

		startAt := (t.VotesPage - 1) * pageSize
		for i, v := range digests {
			if i < int(startAt) {
				continue
			}
			ts, err := p.timestamp(token, v)
			if err != nil {
				return "", errors.Errorf("timestamp %x %x: %v",
					token, v, err)
			}
			votes = append(votes, *ts)
			if len(votes) == int(pageSize) {
				// We have a full page. We're done.
				break
			}
		}

	default:
		// Return authorization timestamps and the vote details
		// timestamp.

		// Auth timestamps
		digests, err := tstore.DigestsByDataDesc(token,
			[]string{dataDescriptorAuthDetails})
		if err != nil {
			return "", errors.Errorf("DigestByDataDesc %x %v: %v",
				token, dataDescriptorAuthDetails, err)
		}
		auths = make([]ticketvote.Timestamp, 0, len(digests))
		for _, v := range digests {
			ts, err := p.timestamp(token, v)
			if err != nil {
				return "", errors.Errorf("timestamp %x %x: %v",
					token, v, err)
			}
			auths = append(auths, *ts)
		}

		// Vote details timestamp
		digests, err = tstore.DigestsByDataDesc(token,
			[]string{dataDescriptorVoteDetails})
		if err != nil {
			return "", errors.Errorf("DigestsByDataDesc %x %v: %v",
				token, dataDescriptorVoteDetails, err)
		}
		// There should never be more than a one vote details
		if len(digests) > 1 {
			return "", errors.Errorf("invalid vote details count: "+
				"got %v, want 1", len(digests))
		}
		for _, v := range digests {
			ts, err := p.timestamp(token, v)
			if err != nil {
				return "", errors.Errorf("timestamp %x %x: %v",
					token, v, err)
			}
			details = ts
		}
	}

	// Prepare reply
	tr := ticketvote.TimestampsReply{
		Auths:   auths,
		Details: details,
		Votes:   votes,
	}
	reply, err := json.Marshal(tr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// Submissions requests the submissions of a runoff vote. The only records that
// will have a submissions list are the parent records in a runoff vote. The
// list will contain all public runoff vote submissions, i.e. records that have
// linked to the parent record using the VoteMetadata.LinkTo field.
func (p *plugin) cmdSubmissions(token []byte) (string, error) {
	// Get submissions list
	lf, err := p.submissionsCache(token)
	if err != nil {
		return "", err
	}

	// Prepare reply
	tokens := make([]string, 0, len(lf.Tokens))
	for k := range lf.Tokens {
		tokens = append(tokens, k)
	}
	lfr := ticketvote.SubmissionsReply{
		Submissions: tokens,
	}
	reply, err := json.Marshal(lfr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// voteSummariesForRunoff calculates and returns the vote summaries of all
// submissions in a runoff vote. This should only be called once the vote has
// finished.
func (p *plugin) summariesForRunoff(parentToken string) (map[string]ticketvote.SummaryReply, error) {
	// Get runoff vote details
	parent, err := decodeToken(parentToken)
	if err != nil {
		return nil, err
	}
	reply, err := p.backend.PluginRead(parent, ticketvote.PluginID,
		cmdRunoffDetails, "")
	if err != nil {
		return nil, errors.Errorf("PluginRead %x %v %v: %v",
			parent, ticketvote.PluginID, cmdRunoffDetails, err)
	}
	var rdr runoffDetailsReply
	err = json.Unmarshal([]byte(reply), &rdr)
	if err != nil {
		return nil, err
	}

	// Verify submissions exist
	subs := rdr.Runoff.Submissions
	if len(subs) == 0 {
		return map[string]ticketvote.SummaryReply{}, nil
	}

	// Compile summaries for all submissions
	var (
		summaries = make(map[string]ticketvote.SummaryReply,
			len(subs))

		// Net number of approve votes of the winner
		winnerNetApprove int

		// Token of the winner
		winnerToken string
	)
	for _, v := range subs {
		token, err := decodeToken(v)
		if err != nil {
			return nil, err
		}

		// Get vote details
		vd, err := p.voteDetailsByToken(token)
		if err != nil {
			return nil, err
		}

		// Get vote options results
		results, err := p.voteOptionResults(token, vd.Params.Options)
		if err != nil {
			return nil, err
		}

		// Add summary to the reply
		s := ticketvote.SummaryReply{
			Type:             vd.Params.Type,
			Status:           ticketvote.VoteStatusRejected,
			Duration:         vd.Params.Duration,
			StartBlockHeight: vd.StartBlockHeight,
			StartBlockHash:   vd.StartBlockHash,
			EndBlockHeight:   vd.EndBlockHeight,
			EligibleTickets:  uint32(len(vd.EligibleTickets)),
			QuorumPercentage: vd.Params.QuorumPercentage,
			PassPercentage:   vd.Params.PassPercentage,
			Results:          results,
		}
		summaries[v] = s

		// We now check if this record has the most net yes votes.

		// Verify the vote met quorum and pass requirements
		approved := voteIsApproved(*vd, results)
		if !approved {
			// Vote did not meet quorum and pass requirements.
			// Nothing else to do. Record vote is not approved.
			continue
		}

		// Check if this record has more net approved votes then
		// current highest.
		var (
			votesApprove uint64 // Number of approve votes
			votesReject  uint64 // Number of reject votes
		)
		for _, vor := range s.Results {
			switch vor.ID {
			case ticketvote.VoteOptionIDApprove:
				votesApprove = vor.Votes
			case ticketvote.VoteOptionIDReject:
				votesReject = vor.Votes
			default:
				// Runoff vote options can only be
				// approve/reject
				return nil, errors.Errorf("unknown runoff vote "+
					"option %v", vor.ID)
			}

			netApprove := int(votesApprove) - int(votesReject)
			if netApprove > winnerNetApprove {
				// New winner!
				winnerToken = v
				winnerNetApprove = netApprove
			}

			// This function doesn't handle the unlikely case that
			// the runoff vote results in a tie. If this happens
			// then we need to have a debate about how this should
			// be handled before implementing anything. The cached
			// vote summary would need to be removed and recreated
			// using whatever methodology is decided upon.
		}
	}
	if winnerToken != "" {
		// A winner was found. Mark their summary as approved.
		s := summaries[winnerToken]
		s.Status = ticketvote.VoteStatusApproved
		summaries[winnerToken] = s
	}

	return summaries, nil
}

// summaryByToken returns the vote summary for a record.
func (p *plugin) summaryByToken(token []byte) (*ticketvote.SummaryReply, error) {
	reply, err := p.backend.PluginRead(token, ticketvote.PluginID,
		ticketvote.CmdSummary, "")
	if err != nil {
		return nil, errors.Errorf("PluginRead %x %v %v: %v",
			token, ticketvote.PluginID, ticketvote.CmdSummary, err)
	}
	var sr ticketvote.SummaryReply
	err = json.Unmarshal([]byte(reply), &sr)
	if err != nil {
		return nil, err
	}
	return &sr, nil
}

// timestamp returns the timestamp for a specific piece of data.
func (p *plugin) timestamp(token []byte, digest []byte) (*ticketvote.Timestamp, error) {
	t, err := tstore.Timestamp(token, digest)
	if err != nil {
		return nil, errors.Errorf("timestamp %x %x: %v",
			token, digest, err)
	}

	// Convert response
	proofs := make([]ticketvote.Proof, 0, len(t.Proofs))
	for _, v := range t.Proofs {
		proofs = append(proofs, ticketvote.Proof{
			Type:       v.Type,
			Digest:     v.Digest,
			MerkleRoot: v.MerkleRoot,
			MerklePath: v.MerklePath,
			ExtraData:  v.ExtraData,
		})
	}
	return &ticketvote.Timestamp{
		Data:       t.Data,
		Digest:     t.Digest,
		TxID:       t.TxID,
		MerkleRoot: t.MerkleRoot,
		Proofs:     proofs,
	}, nil
}

// voteIsApproved returns whether the provided vote option results met the
// provided quorum and pass percentage requirements. This function can only be
// called on votes that use VoteOptionIDApprove and VoteOptionIDReject. Any
// other vote option IDs will cause this function to panic.
func voteIsApproved(vd ticketvote.VoteDetails, results []ticketvote.VoteOptionResult) bool {
	// Tally the total votes
	var total uint64
	for _, v := range results {
		total += v.Votes
	}

	// Calculate required thresholds
	var (
		eligible   = float64(len(vd.EligibleTickets))
		quorumPerc = float64(vd.Params.QuorumPercentage)
		passPerc   = float64(vd.Params.PassPercentage)
		quorum     = uint64(quorumPerc / 100 * eligible)
		pass       = uint64(passPerc / 100 * float64(total))

		approvedVotes uint64
	)

	// Tally approve votes
	for _, v := range results {
		switch v.ID {
		case ticketvote.VoteOptionIDApprove:
			// Valid vote option
			approvedVotes = v.Votes
		case ticketvote.VoteOptionIDReject:
			// Valid vote option
		default:
			// Invalid vote option
			e := fmt.Sprintf("invalid vote option id found: %v",
				v.ID)
			panic(e)
		}
	}

	// Check tally against thresholds
	var approved bool
	switch {
	case total < quorum:
		// Quorum not met
		approved = false

		log.Infof("Quorum not met %v: votes cast %v, quorum required %v",
			vd.Params.Token, total, quorum)

	case approvedVotes < pass:
		// Pass percentage not met
		approved = false

		log.Infof("Vote rejected %v: required %v approval votes, received %v/%v",
			vd.Params.Token, pass, approvedVotes, total)

	default:
		// Vote was approved
		approved = true

		log.Infof("Vote approved %v: required %v approval votes, received %v/%v",
			vd.Params.Token, pass, approvedVotes, total)
	}

	return approved
}


*/
