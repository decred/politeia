// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import (
	"fmt"

	"github.com/decred/politeia/politeiad/plugins/ticketvote"
)

// inventory contains the record inventory categorized by vote status. The
// authorized and started lists are updated in real-time since ticket vote
// plugin commands initiate those actions. The unauthorized and finished lists
// are lazy loaded since those lists depends on external state.
type inventory struct {
	unauthorized []string          // Unauthorized tokens
	authorized   []string          // Authorized tokens
	started      map[string]uint32 // [token]endHeight
	finished     []string          // Finished tokens
	bestBlock    uint32            // Height of last inventory update
}

func (p *ticketVotePlugin) invCacheSetToAuthorized(token string) {
	p.Lock()
	defer p.Unlock()

	// Remove the token from the unauthorized list. The unauthorize
	// list is lazy loaded so it may or may not exist.
	var i int
	var found bool
	for k, v := range p.inv.unauthorized {
		if v == token {
			i = k
			found = true
			break
		}
	}
	if found {
		// Remove the token from unauthorized
		u := p.inv.unauthorized
		u = append(u[:i], u[i+1:]...)
		p.inv.unauthorized = u

		log.Debugf("Removed from unauthorized inv: %v", token)
	}

	// Prepend the token to the authorized list
	a := p.inv.authorized
	a = append([]string{token}, a...)
	p.inv.authorized = a

	log.Debugf("Added to authorized inv: %v", token)
}

func (p *ticketVotePlugin) invCacheSetToUnauthorized(token string) {
	p.Lock()
	defer p.Unlock()

	// Remove the token from the authorized list if it exists. Going
	// from authorized to unauthorized can happen when a vote
	// authorization is revoked.
	var i int
	var found bool
	for k, v := range p.inv.authorized {
		if v == token {
			i = k
			found = true
			break
		}
	}
	if found {
		// Remove the token from authorized
		a := p.inv.authorized
		a = append(a[:i], a[i+1:]...)
		p.inv.authorized = a

		log.Debugf("Removed from authorized inv: %v", token)
	}

	// Prepend the token to the unauthorized list
	u := p.inv.unauthorized
	u = append([]string{token}, u...)
	p.inv.unauthorized = u

	log.Debugf("Added to unauthorized inv: %v", token)
}

func (p *ticketVotePlugin) invCacheSetToStarted(token string, t ticketvote.VoteT, endHeight uint32) {
	p.Lock()
	defer p.Unlock()

	switch t {
	case ticketvote.VoteTypeStandard:
		// Remove the token from the authorized list. The token should
		// always be in the authorized list prior to the vote being
		// started for standard votes so panicing when this is not the
		// case is ok.
		var i int
		var found bool
		for k, v := range p.inv.authorized {
			if v == token {
				i = k
				found = true
				break
			}
		}
		if !found {
			e := fmt.Sprintf("token not found in authorized list: %v", token)
			panic(e)
		}

		a := p.inv.authorized
		a = append(a[:i], a[i+1:]...)
		p.inv.authorized = a

		log.Debugf("Removed from authorized inv: %v", token)

	case ticketvote.VoteTypeRunoff:
		// A runoff vote does not require the submission votes be
		// authorized prior to the vote starting. The token might be in
		// the unauthorized list, but its also possible that its not
		// since the unauthorized list is lazy loaded and it might not
		// have been added yet. Remove it only if it is found.
		var i int
		var found bool
		for k, v := range p.inv.unauthorized {
			if v == token {
				i = k
				found = true
				break
			}
		}
		if found {
			// Remove the token from unauthorized
			u := p.inv.unauthorized
			u = append(u[:i], u[i+1:]...)
			p.inv.unauthorized = u

			log.Debugf("Removed from unauthorized inv: %v", token)
		}

	default:
		e := fmt.Sprintf("invalid vote type %v", t)
		panic(e)
	}

	// Add the token to the started list
	p.inv.started[token] = endHeight

	log.Debugf("Added to started inv: %v", token)
}

func (p *ticketVotePlugin) invCache(bestBlock uint32) (*inventory, error) {
	p.Lock()
	defer p.Unlock()

	// Check backend inventory for new records
	invBackend, err := p.backend.InventoryByStatus()
	if err != nil {
		return nil, fmt.Errorf("InventoryByStatus: %v", err)
	}

	// Find number of records in the vetted inventory
	var vettedInvCount int
	for _, tokens := range invBackend.Vetted {
		vettedInvCount += len(tokens)
	}

	// Find number of records in the vote inventory
	voteInvCount := len(p.inv.unauthorized) + len(p.inv.authorized) +
		len(p.inv.started) + len(p.inv.finished)

	// The vetted inventory count and the vote inventory count should
	// be the same. If they're not then it means we there are records
	// missing from vote inventory.
	if vettedInvCount != voteInvCount {
		// Records are missing from the vote inventory. Put all ticket
		// vote inventory records into a map so we can easily find what
		// backend records are missing.
		all := make(map[string]struct{}, voteInvCount)
		for _, v := range p.inv.unauthorized {
			all[v] = struct{}{}
		}
		for _, v := range p.inv.authorized {
			all[v] = struct{}{}
		}
		for k := range p.inv.started {
			all[k] = struct{}{}
		}
		for _, v := range p.inv.finished {
			all[v] = struct{}{}
		}

		// Add missing records to the vote inventory
		for _, tokens := range invBackend.Vetted {
			for _, v := range tokens {
				if _, ok := all[v]; ok {
					// Record is already in the vote inventory
					continue
				}
				// We can assume that the record vote status is unauthorized
				// since it would have already been added to the vote
				// inventory during the authorization request if one had
				// occurred.
				p.inv.unauthorized = append(p.inv.unauthorized, v)

				log.Debugf("Added to unauthorized inv: %v", v)
			}
		}
	}

	// The records are moved to their correct vote status category in
	// the inventory on authorization, revoking the authorization, and
	// on starting the vote. We can assume these lists are already
	// up-to-date. The last thing we must check for is whether any
	// votes have finished since the last inventory update.

	// Check if the inventory has been updated for this block height.
	if p.inv.bestBlock == bestBlock {
		// Inventory already updated. Nothing else to do.
		goto reply
	}

	// Inventory has not been updated for this block height. Check if
	// any proposal votes have finished.
	for token, endHeight := range p.inv.started {
		if bestBlock >= endHeight {
			// Vote has finished. Remove it from the started list.
			delete(p.inv.started, token)

			log.Debugf("Removed from started inv: %v", token)

			// Add it to the finished list
			p.inv.finished = append(p.inv.finished, token)

			log.Debugf("Added to finished inv: %v", token)
		}
	}

	// Update best block
	p.inv.bestBlock = bestBlock

	log.Debugf("Inv updated for best block %v", bestBlock)

reply:
	// Return a copy of the inventory
	var (
		unauthorized = make([]string, len(p.inv.unauthorized))
		authorized   = make([]string, len(p.inv.authorized))
		started      = make(map[string]uint32, len(p.inv.started))
		finished     = make([]string, len(p.inv.finished))
	)
	copy(unauthorized, p.inv.unauthorized)
	copy(authorized, p.inv.authorized)
	copy(finished, p.inv.finished)
	for k, v := range p.inv.started {
		started[k] = v
	}

	return &inventory{
		unauthorized: unauthorized,
		authorized:   authorized,
		started:      started,
		finished:     finished,
		bestBlock:    p.inv.bestBlock,
	}, nil
}
