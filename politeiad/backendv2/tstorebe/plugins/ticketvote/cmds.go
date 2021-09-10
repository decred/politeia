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

// ballotResults is used to aggregate data for votes that are cast
// concurrently.
type ballotResults struct {
	sync.RWMutex
	addrs   map[string]string                   // [ticket]commitmentAddr
	replies map[string]ticketvote.CastVoteReply // [ticket]CastVoteReply
}

// newBallotResults returns a new ballotResults context.
func newBallotResults() ballotResults {
	return ballotResults{
		addrs:   make(map[string]string, 40960),
		replies: make(map[string]ticketvote.CastVoteReply, 40960),
	}
}

// addrSet sets the largest commitment addresss for a ticket.
func (r *ballotResults) addrSet(ticket, commitmentAddr string) {
	r.Lock()
	defer r.Unlock()

	r.addrs[ticket] = commitmentAddr
}

// addrGet returns the largest commitment address for a ticket.
func (r *ballotResults) addrGet(ticket string) (string, bool) {
	r.RLock()
	defer r.RUnlock()

	a, ok := r.addrs[ticket]
	return a, ok
}

// replySet sets the CastVoteReply for a ticket.
func (r *ballotResults) replySet(ticket string, cvr ticketvote.CastVoteReply) {
	r.Lock()
	defer r.Unlock()

	r.replies[ticket] = cvr
}

// replyGet returns the CastVoteReply for a ticket.
func (r *ballotResults) replyGet(ticket string) (ticketvote.CastVoteReply, bool) {
	r.RLock()
	defer r.RUnlock()

	cvr, ok := r.replies[ticket]
	return cvr, ok
}

// repliesLen returns the number of replies in the ballot results.
func (r *ballotResults) repliesLen() int {
	r.RLock()
	defer r.RUnlock()

	return len(r.replies)
}

// TODO what happens if the database tx times out? These need to be single
// op database writes. How are we going to do this?
//
// castBallot casts a ballot of votes. The ballot is split up into individual
// votes and cast concurrently. We do it this way because tstore only allows
// one blob to be saved at a time. The vote results are passed back to the
// calling function using the ballotResults pointer.  This function waits until
// all provided votes have been cast before returning.
func (p *plugin) castBallot(token []byte, votes []ticketvote.CastVote, br *ballotResults) {
	// Cast the votes concurrently
	var wg sync.WaitGroup
	for _, v := range votes {
		// Increment the wait group counter
		wg.Add(1)

		go func(v ticketvote.CastVote, br *ballotResults) {
			// Decrement wait group counter once vote is cast
			defer wg.Done()

			// Declare here to prevent goto errors
			var (
				cvd ticketvote.CastVoteDetails
				cvr ticketvote.CastVoteReply
				vc  voteCollider
				err error

				receipt = p.identity.SignMessage([]byte(v.Signature))
			)

			addr, ok := br.addrGet(v.Ticket)
			if !ok || addr == "" {
				// Something went wrong. The largest commitment
				// address could not be found for this ticket.
				t := time.Now().Unix()
				log.Errorf("cmdCastBallot: commitment addr not "+
					"found %v", t)
				e := ticketvote.VoteErrorInternalError
				cvr.Ticket = v.Ticket
				cvr.ErrorCode = e
				cvr.ErrorContext = fmt.Sprintf("%v: %v",
					ticketvote.VoteErrors[e], t)
				goto saveReply
			}

			// Setup cast vote details
			cvd = ticketvote.CastVoteDetails{
				Token:     v.Token,
				Ticket:    v.Ticket,
				VoteBit:   v.VoteBit,
				Signature: v.Signature,
				Address:   addr,
				Receipt:   hex.EncodeToString(receipt[:]),
				Timestamp: time.Now().Unix(),
			}

			// Save cast vote details
			err = p.castVoteDetailsSave(token, cvd)
			if errors.Is(err, backend.ErrDuplicatePayload) {
				// This cast vote has already been saved. Its
				// possible that a previous attempt to vote
				// with this ticket failed before the vote
				// collider could be saved. Continue execution
				// so that we re-attempt to save the vote
				// collider.
			} else if err != nil {
				t := time.Now().Unix()
				log.Errorf("cmdCastBallot: castVoteSave %v: "+
					"%v", t, err)
				e := ticketvote.VoteErrorInternalError
				cvr.Ticket = v.Ticket
				cvr.ErrorCode = e
				cvr.ErrorContext = fmt.Sprintf("%v: %v",
					ticketvote.VoteErrors[e], t)
				goto saveReply
			}

			// Save vote collider
			vc = voteCollider{
				Token:  v.Token,
				Ticket: v.Ticket,
			}
			err = p.voteColliderSave(token, vc)
			if err != nil {
				t := time.Now().Unix()
				log.Errorf("cmdCastBallot: voteColliderSave %v: %v", t, err)
				e := ticketvote.VoteErrorInternalError
				cvr.Ticket = v.Ticket
				cvr.ErrorCode = e
				cvr.ErrorContext = fmt.Sprintf("%v: %v",
					ticketvote.VoteErrors[e], t)
				goto saveReply
			}

			// Update receipt
			cvr.Ticket = v.Ticket
			cvr.Receipt = cvd.Receipt

			// Update cast votes cache
			p.activeVotes.AddCastVote(v.Token, v.Ticket, v.VoteBit)

		saveReply:
			// Save the reply
			br.replySet(v.Ticket, cvr)
		}(v, br)
	}

	// Wait for the full ballot to be cast before returning.
	wg.Wait()
}

// cmdCastBallot casts a ballot of votes. This function will not return a user
// error if one occurs for an individual vote. It will instead return the
// ballot reply with the error included in the individual cast vote reply.
func (p *plugin) cmdCastBallot(token []byte, payload string) (string, error) {
	// Decode payload
	var cb ticketvote.CastBallot
	err := json.Unmarshal([]byte(payload), &cb)
	if err != nil {
		return "", err
	}
	votes := cb.Ballot

	// Verify there is work to do
	if len(votes) == 0 {
		log.Infof("No votes found")

		cbr := ticketvote.CastBallotReply{
			Receipts: []ticketvote.CastVoteReply{},
		}
		reply, err := json.Marshal(cbr)
		if err != nil {
			return "", err
		}

		return string(reply), nil
	}

	// Get the data that we need to validate the votes
	eligible := p.activeVotes.EligibleTickets(token)
	voteDetails := p.activeVotes.VoteDetails(token)
	bestBlock, err := p.bestBlock()
	if err != nil {
		return "", err
	}

	// Perform all validation that does not require fetching the
	// commitment addresses.
	receipts := make([]ticketvote.CastVoteReply, len(votes))
	for k, v := range votes {
		// Verify token is a valid token
		t, err := decodeToken(v.Token)
		if err != nil {
			e := ticketvote.VoteErrorTokenInvalid
			receipts[k].Ticket = v.Ticket
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = fmt.Sprintf("%v: not hex",
				ticketvote.VoteErrors[e])
			continue
		}

		// Verify vote token and command token are the same
		if !bytes.Equal(t, token) {
			e := ticketvote.VoteErrorMultipleRecordVotes
			receipts[k].Ticket = v.Ticket
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = ticketvote.VoteErrors[e]
			continue
		}

		// Verify vote is still active
		if voteDetails == nil {
			e := ticketvote.VoteErrorVoteStatusInvalid
			receipts[k].Ticket = v.Ticket
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = fmt.Sprintf("%v: vote is "+
				"not active", ticketvote.VoteErrors[e])
			continue
		}
		if voteHasEnded(bestBlock, voteDetails.EndBlockHeight) {
			e := ticketvote.VoteErrorVoteStatusInvalid
			receipts[k].Ticket = v.Ticket
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = fmt.Sprintf("%v: vote has "+
				"ended", ticketvote.VoteErrors[e])
			continue
		}

		// Verify vote bit
		bit, err := strconv.ParseUint(v.VoteBit, 16, 64)
		if err != nil {
			e := ticketvote.VoteErrorVoteBitInvalid
			receipts[k].Ticket = v.Ticket
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = ticketvote.VoteErrors[e]
			continue
		}
		err = voteBitVerify(voteDetails.Params.Options,
			voteDetails.Params.Mask, bit)
		if err != nil {
			e := ticketvote.VoteErrorVoteBitInvalid
			receipts[k].Ticket = v.Ticket
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = fmt.Sprintf("%v: %v",
				ticketvote.VoteErrors[e], err)
			continue
		}

		// Verify ticket is eligible to vote
		_, ok := eligible[v.Ticket]
		if !ok {
			e := ticketvote.VoteErrorTicketNotEligible
			receipts[k].Ticket = v.Ticket
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = ticketvote.VoteErrors[e]
			continue
		}

		// Verify ticket has not already voted
		isActive, isDup := p.activeVotes.VoteIsDuplicate(v.Token, v.Ticket)
		if !isActive {
			e := ticketvote.VoteErrorVoteStatusInvalid
			receipts[k].Ticket = v.Ticket
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = fmt.Sprintf("%v: vote is "+
				"not active", ticketvote.VoteErrors[e])
		}
		if isDup {
			e := ticketvote.VoteErrorTicketAlreadyVoted
			receipts[k].Ticket = v.Ticket
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = ticketvote.VoteErrors[e]
			continue
		}
	}

	// Setup a ballotResults context. This is used to aggregate the
	// cast vote results when votes are cast concurrently.
	br := newBallotResults()

	// Get the largest commitment address for each ticket and verify
	// that the vote was signed using the private key from this
	// address. We first check the active votes cache to see if the
	// commitment addresses have already been fetched. Any tickets
	// that are not found in the cache are fetched manually.
	tickets := make([]string, 0, len(cb.Ballot))
	for k, v := range votes {
		if receipts[k].ErrorCode != ticketvote.VoteErrorInvalid {
			// Vote has an error. Skip it.
			continue
		}
		tickets = append(tickets, v.Ticket)
	}
	if len(tickets) == 0 {
		log.Infof("No valid votes found in ballot of %v votes", len(votes))

		// There are no valid votes. All attempted
		// votes have an error. Nothing else to do.
		cbr := ticketvote.CastBallotReply{
			Receipts: receipts,
		}
		reply, err := json.Marshal(cbr)
		if err != nil {
			return "", err
		}

		return string(reply), nil
	}

	addrs := p.activeVotes.CommitmentAddrs(token, tickets)
	notInCache := make([]string, 0, len(tickets))
	for _, v := range tickets {
		_, ok := addrs[v]
		if !ok {
			notInCache = append(notInCache, v)
		}
	}

	log.Debugf("%v/%v commitment addresses found in cache",
		len(tickets)-len(notInCache), len(tickets))

	if len(notInCache) > 0 {
		// Get commitment addresses from dcrdata
		caddrs, err := p.largestCommitmentAddrs(tickets)
		if err != nil {
			return "", errors.Errorf("largestCommitmentAddrs: %v", err)
		}

		// Add addresses to the existing map
		for k, v := range caddrs {
			addrs[k] = v
		}
	}

	// Verify the signatures
	for k, v := range votes {
		if receipts[k].ErrorCode != ticketvote.VoteErrorInvalid {
			// Vote has an error. Skip it.
			continue
		}

		// Verify vote signature
		commitmentAddr, ok := addrs[v.Ticket]
		if !ok {
			t := time.Now().Unix()
			log.Errorf("cmdCastBallot: commitment addr not found "+
				"%v: %v", t, v.Ticket)
			e := ticketvote.VoteErrorInternalError
			receipts[k].Ticket = v.Ticket
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = fmt.Sprintf("%v: %v",
				ticketvote.VoteErrors[e], t)
			continue
		}
		if commitmentAddr.err != nil {
			t := time.Now().Unix()
			log.Errorf("cmdCastBallot: commitment addr error %v: "+
				"%v %v", t, v.Ticket, commitmentAddr.err)
			e := ticketvote.VoteErrorInternalError
			receipts[k].Ticket = v.Ticket
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = fmt.Sprintf("%v: %v",
				ticketvote.VoteErrors[e], t)
			continue
		}
		err = castVoteVerifySignature(v, commitmentAddr.addr, p.activeNetParams)
		if err != nil {
			e := ticketvote.VoteErrorSignatureInvalid
			receipts[k].Ticket = v.Ticket
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = fmt.Sprintf("%v: %v",
				ticketvote.VoteErrors[e], err)
			continue
		}

		// Stash the commitment address. This will be added to the
		// CastVoteDetails before the vote is written to disk.
		br.addrSet(v.Ticket, commitmentAddr.addr)
	}

	// The votes that have passed validation will be cast in batches of
	// size batchSize. Each batch of votes is cast concurrently in order to
	// accommodate the trillian log signer bottleneck. The log signer picks
	// up queued leaves and appends them onto the trillian tree every xxx
	// ms, where xxx is a configurable value on the log signer, but is
	// typically a few hundred milliseconds. Lets use 200ms as an example.
	// If we don't cast the votes in batches then every vote in the ballot
	// will take 200 milliseconds since we wait for the leaf to be fully
	// appended before considering the trillian call successful. A person
	// casting hundreds of votes in a single ballot would cause UX issues
	// for all the voting clients since the backend locks the record during
	// any plugin write calls. Only one ballot can be cast at a time.
	//
	// The second variable that we must watch out for is the max trillian
	// queued leaf batch size. This is also a configurable trillian value
	// that represents the maximum number of leaves that can be waiting in
	// the queue for all trees in the trillian instance. This value is
	// typically around the order of magnitude of 1000s of queued leaves.
	//
	// The third variable that can cause errors is reaching the trillian
	// datastore max connection limits. Each vote being cast creates a
	// trillian connection. Overloading the trillian connections can cause
	// max connection exceeded errors. The max allowed connections is a
	// configurable trillian value, but should also be adjusted on the
	// key-value store database itself as well.
	//
	// This is why a vote batch size of 10 was chosen. It is large enough
	// to alleviate performance bottlenecks from the log signer interval,
	// but small enough to still allow multiple records votes to be held
	// concurrently without running into the queued leaf batch size limit.

	// Prepare work
	var (
		batchSize = 10
		batch     = make([]ticketvote.CastVote, 0, batchSize)
		queue     = make([][]ticketvote.CastVote, 0,
			len(votes)/batchSize)

		// ballotCount is the number of votes that have passed
		// validation and are being cast in this ballot.
		ballotCount int
	)
	for k, v := range votes {
		if receipts[k].ErrorCode != ticketvote.VoteErrorInvalid {
			// Vote has an error. Skip it.
			continue
		}

		// Add vote to the current batch
		batch = append(batch, v)
		ballotCount++

		if len(batch) == batchSize {
			// This batch is full. Add the batch to the queue and
			// start a new batch.
			queue = append(queue, batch)
			batch = make([]ticketvote.CastVote, 0, batchSize)
		}
	}
	if len(batch) != 0 {
		// Add leftover batch to the queue
		queue = append(queue, batch)
	}

	log.Infof("Casting %v/%v votes in %v batches of size %v",
		ballotCount, len(votes), len(queue), batchSize)

	// Cast ballot in batches
	for i, batch := range queue {
		log.Debugf("Casting %v votes in batch %v/%v", len(batch), i+1,
			len(queue))

		p.castBallot(token, batch, &br)
	}
	if br.repliesLen() != ballotCount {
		log.Errorf("Missing results: got %v, want %v",
			br.repliesLen(), ballotCount)
	}

	// Fill in the receipts
	for k, v := range votes {
		if receipts[k].ErrorCode != ticketvote.VoteErrorInvalid {
			// Vote has an error. Skip it.
			continue
		}
		cvr, ok := br.replyGet(v.Ticket)
		if !ok {
			t := time.Now().Unix()
			log.Errorf("cmdCastBallot: vote result not found %v: "+
				"%v", t, v.Ticket)
			e := ticketvote.VoteErrorInternalError
			receipts[k].Ticket = v.Ticket
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = fmt.Sprintf("%v: %v",
				ticketvote.VoteErrors[e], t)
			continue
		}

		// Fill in receipt
		receipts[k] = cvr
	}

	// Prepare reply
	cbr := ticketvote.CastBallotReply{
		Receipts: receipts,
	}
	reply, err := json.Marshal(cbr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

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

// cmdSummary requests the vote summary for a record.
func (p *plugin) cmdSummary(token []byte) (string, error) {
	// Get best block. This cmd does not write any data so we do not
	// have to use the safe best block.
	bb, err := p.bestBlockUnsafe()
	if err != nil {
		return "", errors.Errorf("bestBlockUnsafe: %v", err)
	}

	// Get summary
	sr, err := p.summary(token, bb)
	if err != nil {
		return "", errors.Errorf("summary: %v", err)
	}

	// Prepare reply
	reply, err := json.Marshal(sr)
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

// voteOptionResults tallies the results of a ticket vote and returns a
// VoteOptionResult for each vote option in the ticket vote.
func (p *plugin) voteOptionResults(token []byte, options []ticketvote.VoteOption) ([]ticketvote.VoteOptionResult, error) {
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

// summary returns the vote summary for a record.
func (p *plugin) summary(token []byte, bestBlock uint32) (*ticketvote.SummaryReply, error) {
	// Check if the summary has been cached
	s, err := p.summaryCache(hex.EncodeToString(token))
	switch {
	case errors.Is(err, errSummaryNotFound):
		// Cached summary not found. Continue.
	case err != nil:
		// Some other error
		return nil, errors.Errorf("summaryCache: %v", err)
	default:
		// Cached summary was found. Update the best block and return it.
		s.BestBlock = bestBlock
		return s, nil
	}

	// Summary has not been cached. Get it manually.

	// Assume vote is unauthorized. Only update the status when the
	// appropriate record has been found that proves otherwise.
	status := ticketvote.VoteStatusUnauthorized

	// Check if the vote has been authorized. Not all vote types
	// require an authorization.
	auths, err := p.auths(token)
	if err != nil {
		return nil, errors.Errorf("auths: %v", err)
	}
	if len(auths) > 0 {
		lastAuth := auths[len(auths)-1]
		switch ticketvote.AuthActionT(lastAuth.Action) {
		case ticketvote.AuthActionAuthorize:
			// Vote has been authorized; continue
			status = ticketvote.VoteStatusAuthorized
		case ticketvote.AuthActionRevoke:
			// Vote authorization has been revoked. Its not
			// possible for the vote to have been started. We can
			// stop looking.
			return &ticketvote.SummaryReply{
				Status:    status,
				Results:   []ticketvote.VoteOptionResult{},
				BestBlock: bestBlock,
			}, nil
		}
	}

	// Check if the vote has been started
	vd, err := p.voteDetails(token)
	if err != nil {
		return nil, errors.Errorf("startDetails: %v", err)
	}
	if vd == nil {
		// Vote has not been started yet
		return &ticketvote.SummaryReply{
			Status:    status,
			Results:   []ticketvote.VoteOptionResult{},
			BestBlock: bestBlock,
		}, nil
	}

	// Vote has been started. We need to check if the vote has ended yet
	// and if it can be considered approved or rejected.
	status = ticketvote.VoteStatusStarted

	// Tally vote results
	results, err := p.voteOptionResults(token, vd.Params.Options)
	if err != nil {
		return nil, err
	}

	// Prepare summary
	summary := ticketvote.SummaryReply{
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
	case ticketvote.VoteTypeStandard:
		// Standard vote uses a simple approve/reject result
		if voteIsApproved(*vd, results) {
			summary.Status = ticketvote.VoteStatusApproved
		} else {
			summary.Status = ticketvote.VoteStatusRejected
		}

		// Cache summary
		err = p.summaryCacheSave(vd.Params.Token, summary)
		if err != nil {
			return nil, err
		}

		// Remove record from the active votes cache
		p.activeVotes.Del(vd.Params.Token)

	case ticketvote.VoteTypeRunoff:
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

// voteHasEnded returns whether the vote has ended.
func voteHasEnded(bestBlock, endHeight uint32) bool {
	return bestBlock >= endHeight
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
