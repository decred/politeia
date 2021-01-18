// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import (
	"encoding/hex"
)

func (p *ticketVotePlugin) cachedVotes(token []byte) map[string]string {
	p.Lock()
	defer p.Unlock()

	// Return a copy of the map
	cv, ok := p.votes[hex.EncodeToString(token)]
	if !ok {
		return map[string]string{}
	}
	c := make(map[string]string, len(cv))
	for k, v := range cv {
		c[k] = v
	}

	return c
}

func (p *ticketVotePlugin) cachedVotesSet(token, ticket, voteBit string) {
	p.Lock()
	defer p.Unlock()

	_, ok := p.votes[token]
	if !ok {
		p.votes[token] = make(map[string]string, 40960) // Ticket pool size
	}

	p.votes[token][ticket] = voteBit

	log.Debugf("Added vote to cache: %v %v %v",
		token, ticket, voteBit)
}

func (p *ticketVotePlugin) cachedVotesDel(token string) {
	p.Lock()
	defer p.Unlock()

	delete(p.votes, token)

	log.Debugf("Deleted votes cache: %v", token)
}
