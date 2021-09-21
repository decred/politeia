// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/plugins/dcrdata"
	v1 "github.com/decred/politeia/politeiad/plugins/ticketvote"
	"github.com/decred/politeia/util"
	"github.com/pkg/errors"
)

const (
	pluginID = v1.PluginID

	// Blob entry data descriptors
	dataDescriptorAuthDetails     = pluginID + "-auth-v1"
	dataDescriptorVoteDetails     = pluginID + "-vote-v1"
	dataDescriptorCastVoteDetails = pluginID + "-castvote-v1"
	dataDescriptorVoteCollider    = pluginID + "-vcollider-v1"
	dataDescriptorRunoffDetails   = pluginID + "-startrunoff-v1"
)

// cmdAuthorize authorizes a ticket vote or revokes a previous authorization.
func (p *plugin) cmdAuthorize(tstore plugins.TstoreClient, token []byte, payload string) (string, error) {
	// Decode payload
	var a v1.Authorize
	err := json.Unmarshal([]byte(payload), &a)
	if err != nil {
		return "", err
	}

	// Verify token
	err = tokenMatches(token, a.Token)
	if err != nil {
		return "", err
	}

	// Verify signature
	version := strconv.FormatUint(uint64(a.Version), 10)
	msg := a.Token + version + string(a.Action)
	err = verifySignature(a.Signature, a.PublicKey, msg)
	if err != nil {
		return "", err
	}

	// Verify action
	switch a.Action {
	case v1.AuthActionAuthorize, v1.AuthActionRevoke:
		// These are allowed
	default:
		return "", backend.PluginError{
			PluginID:     v1.PluginID,
			ErrorCode:    uint32(v1.ErrorCodeAuthorizationInvalid),
			ErrorContext: fmt.Sprintf("%v not a valid action", a.Action),
		}
	}

	// Verify record status and version
	r, err := tstore.RecordPartial(token, 0, nil, true)
	if err != nil {
		return "", err
	}
	if r.RecordMetadata.Status != backend.StatusPublic {
		return "", backend.PluginError{
			PluginID:     v1.PluginID,
			ErrorCode:    uint32(v1.ErrorCodeRecordStatusInvalid),
			ErrorContext: "record is not public",
		}
	}
	if a.Version != r.RecordMetadata.Version {
		return "", backend.PluginError{
			PluginID:  v1.PluginID,
			ErrorCode: uint32(v1.ErrorCodeRecordVersionInvalid),
			ErrorContext: fmt.Sprintf("version is not latest: "+
				"got %v, want %v", a.Version, r.RecordMetadata.Version),
		}
	}

	// Get any previous authorizations to verify that the
	// new action is allowed based on the previous action.
	auths, err := getAllAuthDetails(tstore, token)
	if err != nil {
		return "", err
	}
	var prevAction v1.AuthActionT
	if len(auths) > 0 {
		prevAction = v1.AuthActionT(auths[len(auths)-1].Action)
	}
	switch {
	case len(auths) == 0:
		// No previous actions. New action must be an authorize.
		if a.Action != v1.AuthActionAuthorize {
			return "", backend.PluginError{
				PluginID:     v1.PluginID,
				ErrorCode:    uint32(v1.ErrorCodeAuthorizationInvalid),
				ErrorContext: "no prev action; action must be authorize",
			}
		}
	case prevAction == v1.AuthActionAuthorize &&
		a.Action != v1.AuthActionRevoke:
		// Previous action was a authorize. This action must be revoke.
		return "", backend.PluginError{
			PluginID:     v1.PluginID,
			ErrorCode:    uint32(v1.ErrorCodeAuthorizationInvalid),
			ErrorContext: "prev action was authorize",
		}
	case prevAction == v1.AuthActionRevoke &&
		a.Action != v1.AuthActionAuthorize:
		// Previous action was a revoke. This action must be authorize.
		return "", backend.PluginError{
			PluginID:     v1.PluginID,
			ErrorCode:    uint32(v1.ErrorCodeAuthorizationInvalid),
			ErrorContext: "prev action was revoke",
		}
	}

	// Save authorization
	receipt := p.identity.SignMessage([]byte(a.Signature))
	auth := authDetails{
		Token:     a.Token,
		Version:   a.Version,
		Action:    string(a.Action),
		PublicKey: a.PublicKey,
		Signature: a.Signature,
		Timestamp: time.Now().Unix(),
		Receipt:   hex.EncodeToString(receipt[:]),
	}
	err = auth.save(tstore, token)
	if err != nil {
		return "", err
	}

	// Update the inventory
	var status v1.VoteStatusT
	switch a.Action {
	case v1.AuthActionAuthorize:
		status = v1.VoteStatusAuthorized
	case v1.AuthActionRevoke:
		status = v1.VoteStatusUnauthorized
	default:
		// Action has already been validated. This should not happen.
		return "", errors.Errorf("invalid action %v", a.Action)
	}
	err = updateInv(tstore, a.Token, status, auth.Timestamp, nil)
	if err != nil {
		return "", err
	}

	// Prepare reply
	ar := v1.AuthorizeReply{
		Timestamp: auth.Timestamp,
		Receipt:   auth.Receipt,
	}
	reply, err := json.Marshal(ar)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// cmdStart starts a ticket vote.
func (p *plugin) cmdStart(tstore plugins.TstoreClient, token []byte, payload string) (string, error) {
	// Decode payload
	var s v1.Start
	err := json.Unmarshal([]byte(payload), &s)
	if err != nil {
		return "", err
	}

	// Parse vote type
	if len(s.Starts) == 0 {
		return "", backend.PluginError{
			PluginID:     v1.PluginID,
			ErrorCode:    uint32(v1.ErrorCodeStartDetailsMissing),
			ErrorContext: "no start details found",
		}
	}
	vtype := s.Starts[0].Params.Type

	// Start vote
	var sr *v1.StartReply
	switch vtype {
	case v1.VoteTypeStandard:
		sr, err = p.startStandardVote(tstore, token, s)
		if err != nil {
			return "", err
		}
	case v1.VoteTypeRunoff:
		sr, err = p.startRunoffVote(tstore, token, s)
		if err != nil {
			return "", err
		}
	default:
		return "", backend.PluginError{
			PluginID:  v1.PluginID,
			ErrorCode: uint32(v1.ErrorCodeVoteTypeInvalid),
		}
	}

	// Prepare reply
	reply, err := json.Marshal(*sr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// cmdStartRunoffSub is an internal plugin command that is used to start the
// voting period on a runoff vote submission.
func (p *plugin) cmdStartRunoffSub(tstore plugins.TstoreClient, token []byte, payload string) (string, error) {
	// Decode payload
	var srs startRunoffSub
	err := json.Unmarshal([]byte(payload), &srs)
	if err != nil {
		return "", err
	}

	// Start the voting period on the runoff vote
	// submission.
	err = p.startRunoffVoteForSub(tstore, token, srs)
	if err != nil {
		return "", err
	}

	// Prepare reply
	reply, err := json.Marshal(startRunoffSubReply{})
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// TODO I think I may need to remove the vote collider leaf. There are two
// options:
// 1. Remove the vote collider leaf
// 2. Allow plugins to save data outside of the tx (needs to include cached
//    data too).
//
// cmdCastBallot casts a ballot of votes. This function will not return a user
// error if one occurs for an individual vote. It will instead return the
// ballot reply with the error included in the individual cast vote reply.
func (p *plugin) cmdCastBallot(tstore plugins.TstoreClient, token []byte, payload string) (string, error) {
	// Decode payload
	var cb v1.CastBallot
	err := json.Unmarshal([]byte(payload), &cb)
	if err != nil {
		return "", err
	}
	votes := cb.Ballot

	// Verify there is work to do
	if len(votes) == 0 {
		log.Infof("No votes found in ballot")

		cbr := v1.CastBallotReply{
			Receipts: []v1.CastVoteReply{},
		}
		reply, err := json.Marshal(cbr)
		if err != nil {
			return "", err
		}

		return string(reply), nil
	}

	// Get the data that we need to validate the votes.
	// It's possible for a vote details to not exist if
	// the vote has not been started yet.
	bestBlock, err := bestBlock(p.backend)
	if err != nil {
		return "", err
	}
	voteDetails, err := getVoteDetails(tstore, token)
	if err != nil {
		return "", err
	}
	eligible := make(map[string]struct{}, 50000)
	if voteDetails != nil {
		for _, v := range voteDetails.EligibleTickets {
			eligible[v] = struct{}{}
		}
	}

	// Perform all validation that does not require
	// fetching the commitment addresses.
	receipts := make([]v1.CastVoteReply, len(votes))
	dups := make(map[string]struct{}, len(votes)) // [ticket]struct{}
	for k, v := range votes {
		// Verify token is valid
		t, err := decodeToken(v.Token)
		if err != nil {
			e := v1.VoteErrorTokenInvalid
			receipts[k].Ticket = v.Ticket
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = fmt.Sprintf("%v: not hex",
				v1.VoteErrors[e])
			continue
		}

		// Verify that the vote is being cast on the same
		// record that the command is being executed on.
		if !bytes.Equal(t, token) {
			e := v1.VoteErrorMultipleRecordVotes
			receipts[k].Ticket = v.Ticket
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = v1.VoteErrors[e]
			continue
		}

		// Verify vote is active
		if voteDetails == nil {
			e := v1.VoteErrorVoteStatusInvalid
			receipts[k].Ticket = v.Ticket
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = fmt.Sprintf("%v: vote is "+
				"not active", v1.VoteErrors[e])
			continue
		}
		if voteHasEnded(bestBlock, voteDetails.EndBlockHeight) {
			e := v1.VoteErrorVoteStatusInvalid
			receipts[k].Ticket = v.Ticket
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = fmt.Sprintf("%v: vote has "+
				"ended", v1.VoteErrors[e])
			continue
		}

		// Verify vote bit
		bit, err := strconv.ParseUint(v.VoteBit, 16, 64)
		if err != nil {
			e := v1.VoteErrorVoteBitInvalid
			receipts[k].Ticket = v.Ticket
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = v1.VoteErrors[e]
			continue
		}
		err = verifyVoteBit(voteDetails.Params.Options,
			voteDetails.Params.Mask, bit)
		if err != nil {
			e := v1.VoteErrorVoteBitInvalid
			receipts[k].Ticket = v.Ticket
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = fmt.Sprintf("%v: %v",
				v1.VoteErrors[e], err)
			continue
		}

		// Verify ticket is eligible to vote
		_, ok := eligible[v.Ticket]
		if !ok {
			e := v1.VoteErrorTicketNotEligible
			receipts[k].Ticket = v.Ticket
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = v1.VoteErrors[e]
			continue
		}

		// Verify that the ballot does not contain
		// multiple votes that use the same ticket.
		_, ok = dups[v.Ticket]
		if ok {
			e := v1.VoteErrorTicketAlreadyVoted
			receipts[k].Ticket = v.Ticket
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = v1.VoteErrors[e]
			continue
		}
		dups[v.Ticket] = struct{}{}

		// Verify that the ticket has not already voted
		// in a previously cast ballot.
		isDup, err := voteIsDuplicate(tstore, v.Token, v.Ticket)
		if err != nil {
			t := time.Now().Unix()
			log.Errorf("cmdCastBallot: voteIsDuplicate %v %v: %v",
				t, v.Ticket, err)
			e := v1.VoteErrorInternalError
			receipts[k].Ticket = v.Ticket
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = fmt.Sprintf("%v: %v",
				v1.VoteErrors[e], t)
			continue
		}
		if isDup {
			e := v1.VoteErrorTicketAlreadyVoted
			receipts[k].Ticket = v.Ticket
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = v1.VoteErrors[e]
			continue
		}
	}

	// Setup a ballotResults context. This is used to
	// aggregate the cast vote results when votes are
	// cast concurrently.
	br := newBallotResults()

	// Get the largest commitment address for each ticket and
	// verify that the vote was signed using the private key
	// from this address.
	//
	// The commitment addresses are retreived and cached when
	// a vote is started, so we may be able to look them up
	// from the cache. Any tickets that are not found in the
	// cache are retrieved manually.
	tickets := make([]string, 0, len(cb.Ballot))
	for k, v := range votes {
		if receipts[k].ErrorCode != v1.VoteErrorInvalid {
			// Vote has an error. Skip it.
			continue
		}
		tickets = append(tickets, v.Ticket)
	}
	if len(tickets) == 0 {
		log.Infof("No valid votes found in ballot of %v votes", len(votes))

		// There are no valid votes. All attempted
		// votes have an error. Nothing else to do.
		cbr := v1.CastBallotReply{
			Receipts: receipts,
		}
		reply, err := json.Marshal(cbr)
		if err != nil {
			return "", err
		}

		return string(reply), nil
	}

	// TODO add back in
	addrs := map[string]commitmentAddr{}
	// addrs, err := getCommitmentAddrs(token, tickets)
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
		/* TODO add back in
		caddrs, err := p.largestCommitmentAddrs(tickets)
		if err != nil {
			return "", err
		}

		// Add addresses to the existing map
		for k, v := range caddrs {
			addrs[k] = v
		}
		*/
	}

	// Verify the signatures
	for k, v := range votes {
		if receipts[k].ErrorCode != v1.VoteErrorInvalid {
			// Vote has an error. Skip it.
			continue
		}

		// Verify vote signature
		commitmentAddr, ok := addrs[v.Ticket]
		if !ok {
			t := time.Now().Unix()
			log.Errorf("cmdCastBallot: commitment "+
				"addr not found %v: %v", t, v.Ticket)
			e := v1.VoteErrorInternalError
			receipts[k].Ticket = v.Ticket
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = fmt.Sprintf("%v: %v",
				v1.VoteErrors[e], t)
			continue
		}
		if commitmentAddr.err != nil {
			t := time.Now().Unix()
			log.Errorf("cmdCastBallot: commitment addr error "+
				"%v: %v %v", t, v.Ticket, commitmentAddr.err)
			e := v1.VoteErrorInternalError
			receipts[k].Ticket = v.Ticket
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = fmt.Sprintf("%v: %v",
				v1.VoteErrors[e], t)
			continue
		}
		err = verifyCastVoteSignature(v, commitmentAddr.addr, p.net)
		if err != nil {
			e := v1.VoteErrorSignatureInvalid
			receipts[k].Ticket = v.Ticket
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = fmt.Sprintf("%v: %v",
				v1.VoteErrors[e], err)
			continue
		}

		// Stash the commitment address. This will
		// be added to the CastVoteDetails before
		// the vote is written to disk.
		br.setAddr(v.Ticket, commitmentAddr.addr)
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
		batch     = make([]v1.CastVote, 0, batchSize)
		queue     = make([][]v1.CastVote, 0, len(votes)/batchSize)

		// ballotCount is the number of votes that have
		// passed validation and are being cast in this
		// ballot.
		ballotCount int
	)
	for k, v := range votes {
		if receipts[k].ErrorCode != v1.VoteErrorInvalid {
			// Vote has an error. Skip it.
			continue
		}

		// Add vote to the current batch
		batch = append(batch, v)
		ballotCount++

		if len(batch) == batchSize {
			// This batch is full. Add the batch
			// to the queue and start a new one.
			queue = append(queue, batch)
			batch = make([]v1.CastVote, 0, batchSize)
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

		p.castBallot(tstore, token, batch, br)
	}
	if br.repliesLen() != ballotCount {
		log.Errorf("Missing results: got %v, want %v",
			br.repliesLen(), ballotCount)
	}

	// Fill in the receipts
	for k, v := range votes {
		if receipts[k].ErrorCode != v1.VoteErrorInvalid {
			// Vote has an error. Skip it.
			continue
		}
		cvr, ok := br.reply(v.Ticket)
		if !ok {
			t := time.Now().Unix()
			log.Errorf("cmdCastBallot: vote result not found %v: %v",
				t, v.Ticket)
			e := v1.VoteErrorInternalError
			receipts[k].Ticket = v.Ticket
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = fmt.Sprintf("%v: %v",
				v1.VoteErrors[e], t)
			continue
		}

		// Fill in receipt
		receipts[k] = cvr

		// Cache the votes so that duplicates can be validated in
		// future ballots.
		err = saveVoteToDupsCache(tstore, v.Token, v.Ticket)
		if err != nil {
			log.Errorf("cmdCastBallot: saveVoteToDupsCache: %v ", err)
		}
	}

	// Prepare reply
	cbr := v1.CastBallotReply{
		Receipts: receipts,
	}
	reply, err := json.Marshal(cbr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// castBallot casts a ballot of votes. The ballot is split up into individual
// votes and cast concurrently. We do it this way because the database only
// allows one blob to be saved at a time. The vote results are passed back to
// the calling function using the ballotResults pointer. This function waits
// until all provided votes have been cast before returning.
func (p *plugin) castBallot(tstore plugins.TstoreClient, token []byte, votes []v1.CastVote, br *ballotResults) {
	// Cast the votes concurrently
	var wg sync.WaitGroup
	for _, v := range votes {
		// Increment the wait group counter
		wg.Add(1)

		// Cast the vote
		go p.castVote(tstore, &wg, v, br)
	}

	// Wait for the full ballot to be cast
	wg.Wait()
}

// castVote casts a ticket vote. This includes saving the vote to the database
// as well as a vote collider. See the vote collider documentation for more
// details on why this is needed.
func (p *plugin) castVote(tstore plugins.TstoreClient, wg *sync.WaitGroup, cv v1.CastVote, results *ballotResults) {
	// Decrement the wait group counter
	// once the vote is cast or errors.
	defer wg.Done()

	// Declare here to prevent goto errors
	var (
		vote     castVoteDetails
		reply    v1.CastVoteReply
		collider voteCollider
		err      error

		receipt = p.identity.SignMessage([]byte(cv.Signature))
	)

	// Get the commitment address that was used to
	// sign the vote.
	addr, ok := results.addr(cv.Ticket)
	if !ok || addr == "" {
		// Something went wrong. The commitment address
		// could not be found for this ticket.
		t := time.Now().Unix()
		log.Errorf("cmdCastBallot: commitment address "+
			"not found %v", t)
		e := v1.VoteErrorInternalError
		reply.Ticket = cv.Ticket
		reply.ErrorCode = e
		reply.ErrorContext = fmt.Sprintf("%v: %v",
			v1.VoteErrors[e], t)
		goto saveReply
	}

	// Save the cast vote
	vote = castVoteDetails{
		Token:     cv.Token,
		Ticket:    cv.Ticket,
		VoteBit:   cv.VoteBit,
		Signature: cv.Signature,
		Address:   addr,
		Receipt:   hex.EncodeToString(receipt[:]),
		Timestamp: time.Now().Unix(),
	}
	err = vote.save(tstore)
	if errors.Is(err, backend.ErrDuplicatePayload) {
		// This cast vote has already been saved. Its
		// possible that a previous attempt to vote
		// with this ticket failed before the vote
		// collider could be saved. Continue execution
		// so that we re-attempt to save the vote
		// collider.
	} else if err != nil {
		t := time.Now().Unix()
		log.Errorf("cmdCastBallot: could not save "+
			"the cast vote details %v: %v", t, err)
		e := v1.VoteErrorInternalError
		reply.Ticket = cv.Ticket
		reply.ErrorCode = e
		reply.ErrorContext = fmt.Sprintf("%v: %v",
			v1.VoteErrors[e], t)
		goto saveReply
	}

	// Save the vote collider
	collider = voteCollider{
		Token:  vote.Token,
		Ticket: vote.Ticket,
	}
	err = collider.save(tstore)
	if err != nil {
		t := time.Now().Unix()
		log.Errorf("cmdCastBallot: could not save "+
			"the vote collider %v: %v", t, err)
		e := v1.VoteErrorInternalError
		reply.Ticket = cv.Ticket
		reply.ErrorCode = e
		reply.ErrorContext = fmt.Sprintf("%v: %v",
			v1.VoteErrors[e], t)
		goto saveReply
	}

	// Update the reply
	reply.Ticket = vote.Ticket
	reply.Receipt = vote.Receipt

saveReply:
	// Save the reply in the ballot results so that
	// the calling function has access to it.
	results.setReply(reply)
}

// startStandardVote starts a standard vote.
func (p *plugin) startStandardVote(tstore plugins.TstoreClient, token []byte, s v1.Start) (*v1.StartReply, error) {
	// Verify there is only one start details
	if len(s.Starts) != 1 {
		return nil, backend.PluginError{
			PluginID:  v1.PluginID,
			ErrorCode: uint32(v1.ErrorCodeStartDetailsInvalid),
			ErrorContext: "more than one start details found for " +
				"standard vote",
		}
	}
	sd := s.Starts[0]

	// Verify token
	err := tokenMatches(token, sd.Params.Token)
	if err != nil {
		return nil, err
	}

	// Verify signature
	vb, err := json.Marshal(sd.Params)
	if err != nil {
		return nil, err
	}
	msg := hex.EncodeToString(util.Digest(vb))
	err = verifySignature(sd.Signature, sd.PublicKey, msg)
	if err != nil {
		return nil, err
	}

	// Verify vote options and params
	err = verifyVoteParams(sd.Params, p.settings.voteDurationMin,
		p.settings.voteDurationMax)
	if err != nil {
		return nil, err
	}

	// Verify record status and version
	r, err := tstore.RecordPartial(token, 0, nil, true)
	if err != nil {
		return nil, err
	}
	if r.RecordMetadata.Status != backend.StatusPublic {
		return nil, backend.PluginError{
			PluginID:     v1.PluginID,
			ErrorCode:    uint32(v1.ErrorCodeRecordStatusInvalid),
			ErrorContext: "record is not public",
		}
	}
	if sd.Params.Version != r.RecordMetadata.Version {
		return nil, backend.PluginError{
			PluginID:  v1.PluginID,
			ErrorCode: uint32(v1.ErrorCodeRecordVersionInvalid),
			ErrorContext: fmt.Sprintf("version is not latest: got %v, "+
				"want %v", sd.Params.Version, r.RecordMetadata.Version),
		}
	}

	// Get dcr blockchain data
	vcp, err := getVoteChainParams(p.backend, sd.Params.Duration,
		uint32(p.net.TicketMaturity))
	if err != nil {
		return nil, err
	}

	// Verify the vote authorization status. Multiple
	// authorization objects may exist. The most recent
	// object is the one that should be checked.
	auths, err := getAllAuthDetails(tstore, token)
	if err != nil {
		return nil, err
	}
	if len(auths) == 0 {
		return nil, backend.PluginError{
			PluginID:     v1.PluginID,
			ErrorCode:    uint32(v1.ErrorCodeVoteStatusInvalid),
			ErrorContext: "not authorized",
		}
	}
	action := v1.AuthActionT(auths[len(auths)-1].Action)
	if action != v1.AuthActionAuthorize {
		return nil, backend.PluginError{
			PluginID:     v1.PluginID,
			ErrorCode:    uint32(v1.ErrorCodeVoteStatusInvalid),
			ErrorContext: "not authorized",
		}
	}

	// Verify vote has not already been started
	vdp, err := getVoteDetails(tstore, token)
	if err != nil {
		return nil, err
	}
	if vdp != nil {
		// Vote has already been started
		return nil, backend.PluginError{
			PluginID:     v1.PluginID,
			ErrorCode:    uint32(v1.ErrorCodeVoteStatusInvalid),
			ErrorContext: "vote already started",
		}
	}

	// Save the vote details
	receipt := p.identity.SignMessage([]byte(sd.Signature + vcp.StartBlockHash))
	vd := voteDetails{
		Params:           convertVoteParamsToLocal(sd.Params),
		PublicKey:        sd.PublicKey,
		Signature:        sd.Signature,
		Receipt:          hex.EncodeToString(receipt[:]),
		StartBlockHeight: vcp.StartBlockHeight,
		StartBlockHash:   vcp.StartBlockHash,
		EndBlockHeight:   vcp.EndBlockHeight,
		EligibleTickets:  vcp.EligibleTickets,
	}
	err = vd.save(tstore, token)
	if err != nil {
		return nil, err
	}

	// Update the inventory
	eed := entryExtraData{
		EndHeight: vd.EndBlockHeight,
	}
	err = updateInv(tstore, vd.Params.Token, v1.VoteStatusStarted,
		time.Now().Unix(), &eed)
	if err != nil {
		return nil, err
	}

	/* TODO active votes
	// Update the active votes cache
	p.activeVotesAdd(vd)
	*/
	// TODO fetch commitment addresses

	return &v1.StartReply{
		Receipt:          vd.Receipt,
		StartBlockHeight: vd.StartBlockHeight,
		StartBlockHash:   vd.StartBlockHash,
		EndBlockHeight:   vd.EndBlockHeight,
		EligibleTickets:  vd.EligibleTickets,
	}, nil
}

// startRunoff starts the voting period for all submissions in a runoff vote.
// It does this by first saving a startRunoffRecord to the runoff vote parent
// record. Once this has been successfully saved the runoff vote is considered
// to have started. The voting period must now be started on all of the runoff
// vote submissions individually. If any of these calls fail, they can be
// retried.  This function will pick up where it left off.
func (p *plugin) startRunoffVote(tstore plugins.TstoreClient, token []byte, s v1.Start) (*v1.StartReply, error) {
	// Sanity check
	if len(s.Starts) == 0 {
		return nil, errors.Errorf("no start details found")
	}

	// Perform validation that can be done without fetching
	// any records from the backend.
	var (
		mask     = s.Starts[0].Params.Mask
		duration = s.Starts[0].Params.Duration
		quorum   = s.Starts[0].Params.QuorumPercentage
		pass     = s.Starts[0].Params.PassPercentage
		parent   = s.Starts[0].Params.Parent
	)
	for _, v := range s.Starts {
		// Verify vote params are the same for all submissions
		switch {
		case v.Params.Type != v1.VoteTypeRunoff:
			return nil, backend.PluginError{
				PluginID:  v1.PluginID,
				ErrorCode: uint32(v1.ErrorCodeVoteTypeInvalid),
				ErrorContext: fmt.Sprintf("%v got %v, want %v",
					v.Params.Token, v.Params.Type,
					v1.VoteTypeRunoff),
			}
		case v.Params.Mask != mask:
			return nil, backend.PluginError{
				PluginID:  v1.PluginID,
				ErrorCode: uint32(v1.ErrorCodeVoteBitsInvalid),
				ErrorContext: fmt.Sprintf("%v mask invalid: "+
					"all must be the same", v.Params.Token),
			}
		case v.Params.Duration != duration:
			return nil, backend.PluginError{
				PluginID:  v1.PluginID,
				ErrorCode: uint32(v1.ErrorCodeVoteDurationInvalid),
				ErrorContext: fmt.Sprintf("%v duration does not match; "+
					"all must be the same", v.Params.Token),
			}
		case v.Params.QuorumPercentage != quorum:
			return nil, backend.PluginError{
				PluginID:  v1.PluginID,
				ErrorCode: uint32(v1.ErrorCodeVoteQuorumInvalid),
				ErrorContext: fmt.Sprintf("%v quorum does not match; "+
					"all must be the same", v.Params.Token),
			}
		case v.Params.PassPercentage != pass:
			return nil, backend.PluginError{
				PluginID:  v1.PluginID,
				ErrorCode: uint32(v1.ErrorCodeVotePassRateInvalid),
				ErrorContext: fmt.Sprintf("%v pass rate does not match; "+
					"all must be the same", v.Params.Token),
			}
		case v.Params.Parent != parent:
			return nil, backend.PluginError{
				PluginID:  v1.PluginID,
				ErrorCode: uint32(v1.ErrorCodeVoteParentInvalid),
				ErrorContext: fmt.Sprintf("%v parent does not match; "+
					"all must be the same", v.Params.Token),
			}
		}

		// Verify token
		_, err := decodeToken(v.Params.Token)
		if err != nil {
			return nil, backend.PluginError{
				PluginID:     v1.PluginID,
				ErrorCode:    uint32(v1.ErrorCodeTokenInvalid),
				ErrorContext: v.Params.Token,
			}
		}

		// Verify parent token
		_, err = decodeToken(v.Params.Parent)
		if err != nil {
			return nil, backend.PluginError{
				PluginID:  v1.PluginID,
				ErrorCode: uint32(v1.ErrorCodeTokenInvalid),
				ErrorContext: fmt.Sprintf("parent token %v invalid",
					v.Params.Parent),
			}
		}

		// Verify signature
		vb, err := json.Marshal(v.Params)
		if err != nil {
			return nil, err
		}
		msg := hex.EncodeToString(util.Digest(vb))
		err = verifySignature(v.Signature, v.PublicKey, msg)
		if err != nil {
			return nil, err
		}

		// Verify vote options and params. Vote options
		// are required to be approve and reject.
		err = verifyVoteParams(v.Params, p.settings.voteDurationMin,
			p.settings.voteDurationMax)
		if err != nil {
			return nil, err
		}
	}

	// Verify that this plugin command is being executed
	// on the parent record.
	if hex.EncodeToString(token) != parent {
		return nil, backend.PluginError{
			PluginID:  v1.PluginID,
			ErrorCode: uint32(v1.ErrorCodeVoteParentInvalid),
			ErrorContext: fmt.Sprintf("runoff vote must be started "+
				"on the parent record %v", parent),
		}
	}

	// Save a runoff details record to the parent record.
	// Once this has been saved the runoff vote is considered
	// to be officially started.
	rd, err := p.startRunoffVoteForParent(tstore, token, s)
	if err != nil {
		return nil, err
	}

	// Start the voting period on each runoff vote
	// submissions. This is done using the internal
	// plugin command startRunoffSub.
	for _, v := range s.Starts {
		token, err = decodeToken(v.Params.Token)
		if err != nil {
			return nil, err
		}
		srs := startRunoffSub{
			ParentToken:  v.Params.Parent,
			StartDetails: v,
		}
		b, err := json.Marshal(srs)
		if err != nil {
			return nil, err
		}
		_, err = p.backend.PluginWrite(token, v1.PluginID,
			cmdStartRunoffSub, string(b))
		if err != nil {
			var ue backend.PluginError
			if errors.As(err, &ue) {
				return nil, err
			}
			return nil, errors.Errorf("PluginWrite %x %v %v: %v",
				token, v1.PluginID, cmdStartRunoffSub, err)
		}
	}

	return &v1.StartReply{
		StartBlockHeight: rd.StartBlockHeight,
		StartBlockHash:   rd.StartBlockHash,
		EndBlockHeight:   rd.EndBlockHeight,
		EligibleTickets:  rd.EligibleTickets,
	}, nil
}

// startRunoffVoteForParent saves a runoffDetails to the parent record and
// returns it. Once this has been saved the runoff vote is considered to be
// started and the voting period on individual runoff vote submissions can be
// started.
func (p *plugin) startRunoffVoteForParent(tstore plugins.TstoreClient, token []byte, s v1.Start) (*runoffDetails, error) {
	// Verify that the runoff details record does
	// not already exist. A runoff details record
	// will exist if the runoff vote has already
	// been started.
	rd, err := getRunoffDetails(tstore, token)
	if err != nil {
		return nil, err
	}
	if rd != nil {
		// The runoff vote has already been started. This
		// can heppen if the prvious call failed due to an
		// unexpected error. Return the runoff details so
		// that we can pick up where we left off.
		return rd, nil
	}

	// Get the blockchain data for the vote
	var (
		mask     = s.Starts[0].Params.Mask
		duration = s.Starts[0].Params.Duration
		quorum   = s.Starts[0].Params.QuorumPercentage
		pass     = s.Starts[0].Params.PassPercentage
	)
	vcp, err := getVoteChainParams(p.backend, duration,
		uint32(p.net.TicketMaturity))
	if err != nil {
		return nil, err
	}

	// Verify that the parent record has its LinkBy field
	// set and that the LinkBy deadline has expired.
	files := []string{
		v1.FileNameVoteMetadata,
	}
	r, err := tstore.RecordPartial(token, 0, files, false)
	if err != nil {
		if errors.Is(err, backend.ErrRecordNotFound) {
			return nil, backend.PluginError{
				PluginID:     v1.PluginID,
				ErrorCode:    uint32(v1.ErrorCodeVoteParentInvalid),
				ErrorContext: fmt.Sprintf("record not found %x", token),
			}
		}
		return nil, err
	}
	if r.RecordMetadata.State != backend.StateVetted {
		// Should not be possible
		return nil, errors.Errorf("record is unvetted")
	}
	vm, err := decodeVoteMetadata(r.Files)
	if err != nil {
		return nil, err
	}
	if vm == nil || vm.LinkBy == 0 {
		return nil, backend.PluginError{
			PluginID:     v1.PluginID,
			ErrorCode:    uint32(v1.ErrorCodeVoteParentInvalid),
			ErrorContext: fmt.Sprintf("parent %x is not an rfp", token),
		}
	}
	if vm.LinkBy > time.Now().Unix() {
		return nil, backend.PluginError{
			PluginID:  v1.PluginID,
			ErrorCode: uint32(v1.ErrorCodeLinkByNotExpired),
			ErrorContext: fmt.Sprintf("parent %x linkby deadline "+
				"(%v) has not expired yet", token, vm.LinkBy),
		}
	}

	// Compile a list of expected submissions that should be
	// included in the runoff vote. This will include all
	// public records that have linked to the parent record.
	// The submission list will include abandoned proposals
	// that need to be filtered out.
	rs, err := getRunoffSubs(tstore, encodeToken(token))
	if err != nil {
		return nil, err
	}
	// map[token]struct{}
	expected := make(map[string]struct{}, len(rs.Subs))
	for k := range rs.Subs {
		token, err := decodeToken(k)
		if err != nil {
			return nil, err
		}
		r, err := recordAbridged(p.backend, token)
		if err != nil {
			return nil, err
		}
		if r.RecordMetadata.Status != backend.StatusPublic {
			// This record is not public and should
			// not be included in the runoff vote.
			continue
		}

		// This is a public record that is part of
		// the parent record's submission list. It
		// is required to be in the runoff vote.
		expected[k] = struct{}{}
	}

	// Verify that there are no extra submissions
	for _, v := range s.Starts {
		_, ok := expected[v.Params.Token]
		if !ok {
			// This submission should not be here
			return nil, backend.PluginError{
				PluginID:  v1.PluginID,
				ErrorCode: uint32(v1.ErrorCodeStartDetailsInvalid),
				ErrorContext: fmt.Sprintf("record %v should "+
					"not be included", v.Params.Token),
			}
		}
	}

	// Verify that no submissions are missing
	subs := make(map[string]struct{}, len(s.Starts))
	for _, v := range s.Starts {
		subs[v.Params.Token] = struct{}{}
	}
	for k := range expected {
		_, ok := subs[k]
		if !ok {
			// This records is missing from the runoff vote
			return nil, backend.PluginError{
				PluginID:     v1.PluginID,
				ErrorCode:    uint32(v1.ErrorCodeStartDetailsMissing),
				ErrorContext: k,
			}
		}
	}

	// Save a runoff details record
	submissions := make([]string, 0, len(subs))
	for k := range subs {
		submissions = append(submissions, k)
	}
	rd = &runoffDetails{
		Submissions:      submissions,
		Mask:             mask,
		Duration:         duration,
		QuorumPercentage: quorum,
		PassPercentage:   pass,
		StartBlockHeight: vcp.StartBlockHeight,
		StartBlockHash:   vcp.StartBlockHash,
		EndBlockHeight:   vcp.EndBlockHeight,
		EligibleTickets:  vcp.EligibleTickets,
	}
	err = rd.save(tstore, token)
	if err != nil {
		return nil, err
	}

	return rd, nil
}

// startRunoffVoteForSub starts the voting period on a runoff vote submission.
func (p *plugin) startRunoffVoteForSub(tstore plugins.TstoreClient, token []byte, srs startRunoffSub) error {
	// Sanity check
	sd := srs.StartDetails
	t, err := decodeToken(sd.Params.Token)
	if err != nil {
		return err
	}
	if !bytes.Equal(token, t) {
		return errors.Errorf("invalid token")
	}

	// Get the runoff details record. This will
	// be saved to the parent record.
	parent, err := decodeToken(srs.ParentToken)
	if err != nil {
		return err
	}
	rd, err := getRunoffDetails(tstore, parent)
	if err != nil {
		return err
	}

	// Sanity check. Verify token is part of
	// the start runoff record submissions.
	var found bool
	for _, v := range rd.Submissions {
		if hex.EncodeToString(token) == v {
			found = true
			break
		}
	}
	if !found {
		// This submission should not be here
		return errors.Errorf("record not in submission list")
	}

	// If the vote has already been started, exit gracefully.
	// This allows us to recover from unexpected errors to
	// the start runoff vote call as it updates the state of
	// multiple records. If the call were to fail before
	// completing, we can simply call the command again with
	// the same arguments and it will pick up where it left
	// off.
	vdp, err := getVoteDetails(tstore, token)
	if err != nil {
		return err
	}
	if vdp != nil {
		// Vote has already been started. Exit gracefully.
		return nil
	}

	// Verify record version
	r, err := tstore.RecordPartial(token, 0, nil, true)
	if err != nil {
		return err
	}
	if r.RecordMetadata.State != backend.StateVetted {
		// This should not be possible
		return errors.Errorf("record is unvetted")
	}
	if sd.Params.Version != r.RecordMetadata.Version {
		return backend.PluginError{
			PluginID:  v1.PluginID,
			ErrorCode: uint32(v1.ErrorCodeRecordVersionInvalid),
			ErrorContext: fmt.Sprintf("version is not the latest %v: "+
				"got %v, want %v", sd.Params.Token, sd.Params.Version,
				r.RecordMetadata.Version),
		}
	}

	// Save vote details
	receipt := p.identity.SignMessage([]byte(sd.Signature + rd.StartBlockHash))
	vd := voteDetails{
		Params:           convertVoteParamsToLocal(sd.Params),
		PublicKey:        sd.PublicKey,
		Signature:        sd.Signature,
		Receipt:          hex.EncodeToString(receipt[:]),
		StartBlockHeight: rd.StartBlockHeight,
		StartBlockHash:   rd.StartBlockHash,
		EndBlockHeight:   rd.EndBlockHeight,
		EligibleTickets:  rd.EligibleTickets,
	}
	err = vd.save(tstore, token)
	if err != nil {
		return err
	}

	// Update the inventory
	eed := entryExtraData{
		EndHeight: vd.EndBlockHeight,
	}
	err = updateInv(tstore, vd.Params.Token, v1.VoteStatusStarted,
		time.Now().Unix(), &eed)
	if err != nil {
		return err
	}

	/* TODO active votes
	// Update active votes cache
	p.activeVotesAdd(vd)
	*/
	// TODO fetch commitment addresses

	return nil
}

// voteChainParams represent the dcr blockchain parameters for a ticket vote.
type voteChainParams struct {
	StartBlockHeight uint32   `json:"startblockheight"`
	StartBlockHash   string   `json:"startblockhash"`
	EndBlockHeight   uint32   `json:"endblockheight"`
	EligibleTickets  []string `json:"eligibletickets"` // Ticket hashes
}

// getVoteChainParams fetches and returns the voteChainParams for a ticket
// vote.
func getVoteChainParams(backend backend.Backend, duration, ticketMaturity uint32) (*voteChainParams, error) {
	// Get the best block height
	bb, err := bestBlock(backend)
	if err != nil {
		return nil, err
	}

	// Find the snapshot height. Subtract the ticket maturity
	// from the block height to get into unforkable territory.
	snapshotHeight := bb - ticketMaturity

	// Fetch the block details for the snapshot height. The
	// block hash is needed to fetch the ticket pool snapshot.
	bd := dcrdata.BlockDetails{
		Height: snapshotHeight,
	}
	payload, err := json.Marshal(bd)
	if err != nil {
		return nil, err
	}
	reply, err := backend.PluginRead(nil, dcrdata.PluginID,
		dcrdata.CmdBlockDetails, string(payload))
	if err != nil {
		return nil, errors.Errorf("PluginRead %v %v: %v",
			dcrdata.PluginID, dcrdata.CmdBlockDetails, err)
	}
	var bdr dcrdata.BlockDetailsReply
	err = json.Unmarshal([]byte(reply), &bdr)
	if err != nil {
		return nil, err
	}
	if bdr.Block.Hash == "" {
		return nil, errors.Errorf("invalid block hash for height %v",
			snapshotHeight)
	}
	snapshotHash := bdr.Block.Hash

	// Fetch the ticket pool snapshot
	tp := dcrdata.TicketPool{
		BlockHash: snapshotHash,
	}
	payload, err = json.Marshal(tp)
	if err != nil {
		return nil, err
	}
	reply, err = backend.PluginRead(nil, dcrdata.PluginID,
		dcrdata.CmdTicketPool, string(payload))
	if err != nil {
		return nil, errors.Errorf("PluginRead %v %v: %v",
			dcrdata.PluginID, dcrdata.CmdTicketPool, err)
	}
	var tpr dcrdata.TicketPoolReply
	err = json.Unmarshal([]byte(reply), &tpr)
	if err != nil {
		return nil, err
	}
	if len(tpr.Tickets) == 0 {
		return nil, errors.Errorf("no tickets found for block %v %v",
			snapshotHeight, snapshotHash)
	}

	// The start block height has the ticket maturity subtracted
	// from it to prevent forking issues. This means we the vote
	// starts in the past. The ticket maturity needs to be added
	// to the end block height to correct for this.
	endBlockHeight := snapshotHeight + duration + ticketMaturity

	return &voteChainParams{
		StartBlockHeight: snapshotHeight,
		StartBlockHash:   snapshotHash,
		EndBlockHeight:   endBlockHeight,
		EligibleTickets:  tpr.Tickets,
	}, nil
}

// verifyVoteParams verifies that the params of a ticket vote are within
// acceptable values.
func verifyVoteParams(vote v1.VoteParams, voteDurationMin, voteDurationMax uint32) error {
	// Verify vote type
	switch vote.Type {
	case v1.VoteTypeStandard:
		// This is allowed
	case v1.VoteTypeRunoff:
		// This is allowed
	default:
		return backend.PluginError{
			PluginID:  v1.PluginID,
			ErrorCode: uint32(v1.ErrorCodeVoteTypeInvalid),
		}
	}

	// Verify vote params
	switch {
	case vote.Duration > voteDurationMax:
		return backend.PluginError{
			PluginID:  v1.PluginID,
			ErrorCode: uint32(v1.ErrorCodeVoteDurationInvalid),
			ErrorContext: fmt.Sprintf("duration %v exceeds max "+
				"duration %v", vote.Duration, voteDurationMax),
		}
	case vote.Duration < voteDurationMin:
		return backend.PluginError{
			PluginID:  v1.PluginID,
			ErrorCode: uint32(v1.ErrorCodeVoteDurationInvalid),
			ErrorContext: fmt.Sprintf("duration %v under min "+
				"duration %v", vote.Duration, voteDurationMin),
		}
	case vote.QuorumPercentage > 100:
		return backend.PluginError{
			PluginID:  v1.PluginID,
			ErrorCode: uint32(v1.ErrorCodeVoteQuorumInvalid),
			ErrorContext: fmt.Sprintf("quorum percent %v exceeds "+
				"100 percent", vote.QuorumPercentage),
		}
	case vote.PassPercentage > 100:
		return backend.PluginError{
			PluginID:  v1.PluginID,
			ErrorCode: uint32(v1.ErrorCodeVotePassRateInvalid),
			ErrorContext: fmt.Sprintf("pass percent %v exceeds "+
				"100 percent", vote.PassPercentage),
		}
	}

	// Verify the vote options. Different vote types have
	// different requirements.
	if len(vote.Options) == 0 {
		return backend.PluginError{
			PluginID:     v1.PluginID,
			ErrorCode:    uint32(v1.ErrorCodeVoteOptionsInvalid),
			ErrorContext: "no vote options found",
		}
	}
	switch vote.Type {
	case v1.VoteTypeStandard, v1.VoteTypeRunoff:
		// These vote types only allow for approve/reject votes.
		// Verify that the only options present are approve/reject
		// and that they use the vote option IDs specified by the
		// v1 API.
		if len(vote.Options) != 2 {
			return backend.PluginError{
				PluginID:  v1.PluginID,
				ErrorCode: uint32(v1.ErrorCodeVoteOptionsInvalid),
				ErrorContext: fmt.Sprintf("got %v options, want 2",
					len(vote.Options)),
			}
		}
		// map[optionID]found
		options := map[string]bool{
			v1.VoteOptionIDApprove: false,
			v1.VoteOptionIDReject:  false,
		}
		for _, v := range vote.Options {
			switch v.ID {
			case v1.VoteOptionIDApprove:
				options[v.ID] = true
			case v1.VoteOptionIDReject:
				options[v.ID] = true
			}
		}
		missing := make([]string, 0, 2)
		for k, v := range options {
			if !v {
				// Option ID was not found
				missing = append(missing, k)
			}
		}
		if len(missing) > 0 {
			return backend.PluginError{
				PluginID:  v1.PluginID,
				ErrorCode: uint32(v1.ErrorCodeVoteOptionsInvalid),
				ErrorContext: fmt.Sprintf("vote option IDs not found: %v",
					strings.Join(missing, ",")),
			}
		}
	}

	// Verify vote bits are somewhat sane
	for _, v := range vote.Options {
		_ = v
		/* TODO put back in
		err := verifyVoteBit(vote.Options, vote.Mask, v.Bit)
		if err != nil {
			return backend.PluginError{
				PluginID:     v1.PluginID,
				ErrorCode:    uint32(v1.ErrorCodeVoteBitsInvalid),
				ErrorContext: err.Error(),
			}
		}
		*/
	}

	// Verify parent token
	switch {
	case vote.Type == v1.VoteTypeStandard && vote.Parent != "":
		return backend.PluginError{
			PluginID:  v1.PluginID,
			ErrorCode: uint32(v1.ErrorCodeVoteParentInvalid),
			ErrorContext: "parent token should not be provided " +
				"for a standard vote",
		}
	case vote.Type == v1.VoteTypeRunoff:
		_, err := decodeToken(vote.Parent)
		if err != nil {
			return backend.PluginError{
				PluginID:     v1.PluginID,
				ErrorCode:    uint32(v1.ErrorCodeVoteParentInvalid),
				ErrorContext: fmt.Sprintf("invalid parent %v", vote.Parent),
			}
		}
	}

	return nil
}

// verifyVoteBit verifies that the vote bit corresponds to a valid vote option.
func verifyVoteBit(options []voteOption, mask, bit uint64) error {
	if len(options) == 0 {
		return errors.Errorf("no vote options found")
	}
	if bit == 0 {
		return errors.Errorf("invalid bit 0x%x", bit)
	}

	// Verify bit is included in mask
	if mask&bit != bit {
		return errors.Errorf("invalid mask 0x%x bit 0x%x", mask, bit)
	}

	// Verify bit is included in vote options
	for _, v := range options {
		if v.Bit == bit {
			// Bit matches one of the options. We're done.
			return nil
		}
	}

	return errors.Errorf("bit 0x%x not found in vote options", bit)
}

// voteHasEnded returns whether the vote has ended.
func voteHasEnded(bestBlock, endHeight uint32) bool {
	return bestBlock >= endHeight
}
