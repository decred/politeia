// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import (
	"sync"

	"github.com/decred/politeia/politeiad/plugins/ticketvote"
)

// ballotResults is used to aggregate data for votes in a ballot that are cast
// concurrently.
type ballotResults struct {
	sync.RWMutex
	addrs   map[string]string                   // [ticket]commitmentAddr
	replies map[string]ticketvote.CastVoteReply // [ticket]CastVoteReply
}

// newBallotResults returns a new ballotResults.
func newBallotResults() *ballotResults {
	return &ballotResults{
		addrs:   make(map[string]string, 40960),
		replies: make(map[string]ticketvote.CastVoteReply, 40960),
	}
}

// setAddr sets the largest commitment addresss for a ticket.
func (r *ballotResults) setAddr(ticket, commitmentAddr string) {
	r.Lock()
	defer r.Unlock()

	r.addrs[ticket] = commitmentAddr
}

// addr returns the largest commitment address for a ticket.
func (r *ballotResults) addr(ticket string) (string, bool) {
	r.RLock()
	defer r.RUnlock()

	a, ok := r.addrs[ticket]
	return a, ok
}

// setReply sets the CastVoteReply for a ticket.
func (r *ballotResults) setReply(cvr ticketvote.CastVoteReply) {
	r.Lock()
	defer r.Unlock()

	r.replies[cvr.Ticket] = cvr
}

// reply returns the CastVoteReply for a ticket.
func (r *ballotResults) reply(ticket string) (ticketvote.CastVoteReply, bool) {
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
