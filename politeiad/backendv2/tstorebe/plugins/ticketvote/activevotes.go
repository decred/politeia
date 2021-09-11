// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

/*
// activeVotes provides a cache for data that is required to validate
// vote ballots in a time efficient manner. An active vote is added to the
// cache when a vote is started and is removed from the cache lazily when a
// vote summary is created for the finished vote.
//
// This cache is required in order to increase the performance of the cast
// vote validation.
//
// Record locking is handled by the backend, not by individual plugins. This
// makes the plugin implementations simpler and easier to reason about, but it
// can also lead to performance bottlenecks for expensive plugin write
// commands. The cast ballot command is one such command due to the combination
// of requiring external dcrdata calls to verify the largest commitment
// addresses for each ticket and the fact that its possible for hundreds of
// ballots to be cast concurrently. We cache the active vote data in order to
// alleviate this bottleneck.
type activeVotes struct {
	sync.RWMutex
	activeVotes map[string]activeVote // [token]activeVote
}

// activeVote caches the data required to validate vote ballots for a record
// with an active voting period.
//
// A active vote with 41k tickets will cache a maximum of 10.5 MB of data.
// This includes a 3 MB vote details, 4.5 MB commitment addresses map, and a
// potential 3 MB cast votes map if all 41k votes are cast.
type activeVote struct {
	Details   *ticketvote.VoteDetails
	CastVotes map[string]string // [ticket]voteBit

	// Addrs contains the largest commitment address for each eligble
	// ticket. The vote must be signed with the key from this address.
	//
	// This map is populated by an async job that is kicked off when a
	// a vote is started. It takes ~1.5 minutes to fully populate this
	// cache when the ticket pool is 41k tickets and when using an off
	// premise dcrdata instance with minimal latency. Any functions
	// that rely of this cache should fallback to fetching the
	// commitment addresses manually in the event the cache has not
	// been fully populated yet or has experienced unforeseen errors
	// during creation (ex. network errors). If the initial job fails
	// to complete it will not be retried.
	Addrs map[string]string // [ticket]address
}

// VoteDetails returns the vote details from the active votes cache for the
// provided token. If the token does not correspond to an active vote then nil
// is returned.
func (a *activeVotes) VoteDetails(token []byte) *ticketvote.VoteDetails {
	t := hex.EncodeToString(token)

	a.RLock()
	defer a.RUnlock()

	av, ok := a.activeVotes[t]
	if !ok {
		return nil
	}

	// Return a copy of the vote details
	eligible := make([]string, len(av.Details.EligibleTickets))
	for i, v := range av.Details.EligibleTickets {
		eligible[i] = v
	}
	options := make([]ticketvote.VoteOption, len(av.Details.Params.Options))
	for i, v := range av.Details.Params.Options {
		options[i] = v
	}
	return &ticketvote.VoteDetails{
		Params: ticketvote.VoteParams{
			Token:            av.Details.Params.Token,
			Version:          av.Details.Params.Version,
			Type:             av.Details.Params.Type,
			Mask:             av.Details.Params.Mask,
			Duration:         av.Details.Params.Duration,
			QuorumPercentage: av.Details.Params.QuorumPercentage,
			PassPercentage:   av.Details.Params.PassPercentage,
			Options:          options,
			Parent:           av.Details.Params.Parent,
		},
		PublicKey:        av.Details.PublicKey,
		Signature:        av.Details.Signature,
		StartBlockHeight: av.Details.StartBlockHeight,
		StartBlockHash:   av.Details.StartBlockHash,
		EndBlockHeight:   av.Details.EndBlockHeight,
		EligibleTickets:  eligible,
	}
}

// EligibleTickets returns the eligible tickets from the active votes cache for
// the provided token. If the token does not correspond to an active vote then
// nil is returned.
func (a *activeVotes) EligibleTickets(token []byte) map[string]struct{} {
	t := hex.EncodeToString(token)

	a.RLock()
	defer a.RUnlock()

	av, ok := a.activeVotes[t]
	if !ok {
		return nil
	}

	// Return a map of the eligible tickets
	eligible := make(map[string]struct{}, len(av.Details.EligibleTickets))
	for _, v := range av.Details.EligibleTickets {
		eligible[v] = struct{}{}
	}

	return eligible
}

// VoteIsDuplicate returns whether the vote has already been cast. The first
// bool returned represents whether the record vote exists in the active votes
// cache. The second bool returned represetns whether the ticket is a duplicate
// vote.
func (a *activeVotes) VoteIsDuplicate(token, ticket string) (bool, bool) {
	a.RLock()
	defer a.RUnlock()

	av, ok := a.activeVotes[token]
	if !ok {
		// Vote does not exist. Its possible that the vote
		// ended while a ballot was being validated.
		return false, false
	}

	_, isDup := av.CastVotes[ticket]
	return true, isDup
}

// CommitmentAddrs returns the largest comittment address for each of the
// provided tickets. The returned map is a map[ticket]commitmentAddr. Nil is
// returned if the provided token does not correspond to a record in the active
// votes cache.
func (a *activeVotes) CommitmentAddrs(token []byte, tickets []string) map[string]commitmentAddr {
	if len(tickets) == 0 {
		return map[string]commitmentAddr{}
	}

	t := hex.EncodeToString(token)
	ca := make(map[string]commitmentAddr, len(tickets))

	a.RLock()
	defer a.RUnlock()

	av, ok := a.activeVotes[t]
	if !ok {
		return nil
	}

	for _, v := range tickets {
		addr, ok := av.Addrs[v]
		if ok {
			ca[v] = commitmentAddr{
				addr: addr,
			}
		}
	}

	return ca
}

// Tally returns the tally of the cast votes for each vote option in an active
// vote. The returned map is a map[votebit]tally. An empty map is returned if
// the requested token is not in the active votes cache.
func (a *activeVotes) Tally(token string) map[string]uint32 {
	tally := make(map[string]uint32, 16)

	a.RLock()
	defer a.RUnlock()

	av, ok := a.activeVotes[token]
	if !ok {
		return tally
	}
	for _, votebit := range av.CastVotes {
		tally[votebit]++
	}
	return tally
}

// AddCastVote adds a cast ticket vote to the active votes cache.
func (a *activeVotes) AddCastVote(token, ticket, votebit string) {
	a.Lock()
	defer a.Unlock()

	av, ok := a.activeVotes[token]
	if !ok {
		// Vote does not exist. Its possible that the vote ended after
		// the cast votes passed validation but before this cache was
		// able to be populated. Log a warning and exit gracefully.
		log.Warnf("AddCastVote: vote not found %v", token)
		return
	}

	av.CastVotes[ticket] = votebit
}

// AddCommitmentAddrs adds commitment addresses to the cache for a record.
func (a *activeVotes) AddCommitmentAddrs(token string, addrs map[string]commitmentAddr) {
	a.Lock()
	defer a.Unlock()

	av, ok := a.activeVotes[token]
	if !ok {
		// Vote does not exist. Its possible for the vote to end while
		// in the middle of populating the commitment addresses cache.
		// This is ok. Exit gracefully.
		return
	}

	for ticket, v := range addrs {
		if v.err != nil {
			log.Errorf("Commitment address error %v %v %v",
				token, ticket, v.err)
			continue
		}
		av.Addrs[ticket] = v.addr
	}
}

// Del deletes an active vote from the active votes cache.
func (a *activeVotes) Del(token string) {
	a.Lock()
	delete(a.activeVotes, token)
	a.Unlock()

	log.Debugf("Active votes del %v", token)
}

// Add adds a active vote to the active votes cache.
//
// This function should NOT be called directly. The ticketvote method
// activeVotesAdd(), which also kicks of an async job to fetch the commitment
// addresses for this active votes entry, should be used instead.
func (a *activeVotes) Add(vd ticketvote.VoteDetails) {
	token := vd.Params.Token

	a.Lock()
	a.activeVotes[token] = activeVote{
		Details:   &vd,
		CastVotes: make(map[string]string, 40960), // Ticket pool size
		Addrs:     make(map[string]string, 40960), // Ticket pool size
	}
	a.Unlock()

	log.Debugf("Active votes add %v", token)
}

// newActiveVotes returns a new activeVotes.
func newActiveVotes() *activeVotes {
	return &activeVotes{
		activeVotes: make(map[string]activeVote, 256),
	}
}

// activeVotePopulateAddrs fetches the largest commitment address for each
// ticket in a vote from dcrdata and caches the results.
func (p *plugin) activeVotePopulateAddrs(vd ticketvote.VoteDetails) {
	// Get largest commitment address for each eligible ticket. A
	// TrimmedTxs response for 500 tickets is ~1MB. It takes ~1.5
	// minutes to get the largest commitment address for 41k eligible
	// tickets from an off premise dcrdata instance with minimal
	// latency.
	var (
		token    = vd.Params.Token
		pageSize = 500
		startIdx int
		done     bool
	)
	for !done {
		endIdx := startIdx + pageSize
		if endIdx > len(vd.EligibleTickets) {
			endIdx = len(vd.EligibleTickets)
			done = true
		}

		log.Debugf("Get %v commitment addrs %v/%v",
			token, endIdx, len(vd.EligibleTickets))

		tickets := vd.EligibleTickets[startIdx:endIdx]
		addrs, err := p.largestCommitmentAddrs(tickets)
		if err != nil {
			log.Errorf("Populate commitment addresses for %v at %v: %v",
				token, startIdx, err)
			continue
		}

		// Update cached active vote
		p.activeVotes.AddCommitmentAddrs(token, addrs)

		startIdx += pageSize
	}
}

// activeVotesAdd creates a active votes cache entry for the provided vote
// details and kicks off an async job that fetches and caches the largest
// commitment address for each eligible ticket.
func (p *plugin) activeVotesAdd(vd ticketvote.VoteDetails) {
	// Add the vote to the active votes cache
	p.activeVotes.Add(vd)

	// Fetch the commitment addresses asynchronously
	go p.activeVotePopulateAddrs(vd)
}
*/

/*
type activeVotes struct {
	sync.Mutex
	votes map[string]*activeVote // [token]activeVote
}

// get returns the activeVote for the provided token. If an activeVote doesn't
// exist yet, a new one is created and returned.
func (a *activeVotes) get(token []byte) *activeVote {
	a.Lock()
	defer a.Unlock()

	t := encodeToken(token)
	av, ok := a.votes[t]
	if ok {
		// Active vote already exists
		return av
	}

	// Active vote doesn't exist yet.
	// Create and save a new one.
	av = &activeVote{}
	a.votes[t] = av

	log.Debugf("Active vote cached for %x", token)

	return av
}

// del deletes the activeVote from the cache for the provided token.
func (a *activeVotes) del(token []byte) {
	a.Lock()
	defer a.Unlock()

	delete(a.votes, encodeToken(token))

	log.Debugf("Active vote deleted for %x", token)
}




type activeVote struct {
	sync.Mutex
	token    []byte
	details  *ticketvote.VoteDetails
	eligible map[string]struct{} // [ticket]struct{}
}

func (a *activeVote) voteDetails(tstore plugins.PluginClient) (*voteDetails, error) {
	if a.details != nil {
		// Vote details has already been cached
		return a.details, nil
	}

	// Get the vote details
	vd, err := getVoteDetails(tstore, token)
	if err != nil {
		return nil, err
	}
	if vd == nil {
		return nil, nil
	}

	// Cache the results
	a.Lock()
	defer a.Unlock()

	a.details = vd

	return vd, nil
}

func (a *activeVote) eligibleTickets(tstore plugins.PluginClient) (map[string]struct{}, error) {
	if len(eligible) > 0 {
		// Eligible tickets have already
		// been lazy loaded. Return them.
		return a.eligible
	}

	// Get the vote details
	vd, err := a.voteDetails(tstore)
	if err != nil {
		return nil, err
	}

	// Convert tickets slice to a map
	eligible := make(map[string]struct{}, len(vd.EligibleTickets))
	for _, v := range v.EligibleTickets {
		eligible[v] = struct{}{}
	}

	// Cache the results
	a.Lock()
	defer a.Unlock()

	a.eligible = eligible

	return eligible, nil
}
*/
