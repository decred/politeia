// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"

	"github.com/decred/politeia/politeiad/plugins/ticketvote"
)

const (
	// filenameInventory is the file name of the ticketvote inventory
	// that is cached to the plugin data dir.
	filenameInventory = "inventory.json"
)

// inventory contains the record inventory categorized by vote status. The
// unauthorized, authorized, and started lists are updated in real-time since
// ticket vote plugin commands or hooks initiate those actions. The finished,
// approved, and rejected statuses are lazy loaded since those lists depends on
// external state (DCR block height).
type inventory struct {
	Tokens    map[string][]string `json:"tokens"`    // [status][]token
	Active    []activeVote        `json:"active"`    // Active votes
	BestBlock uint32              `json:"bestblock"` // Last updated
}

// activeVote is used to track active votes. The end height is stored so that
// we can check what votes have finished when a new best blocks come in.
type activeVote struct {
	Token     string `json:"token"`
	EndHeight uint32 `json:"endheight"`
}

// invPath returns the full path for the cached ticket vote inventory.
func (p *ticketVotePlugin) invPath() string {
	return filepath.Join(p.dataDir, filenameInventory)
}

// invGetLocked retrieves the inventory from disk. A new inventory is returned
// if one does not exist yet.
//
// This function must be called WITH the lock held.
func (p *ticketVotePlugin) invGetLocked() (*inventory, error) {
	b, err := ioutil.ReadFile(p.invPath())
	if err != nil {
		var e *os.PathError
		if errors.As(err, &e) && !os.IsExist(err) {
			// File does't exist. Return a new inventory.
			return &inventory{
				Tokens:    make(map[string][]string, 256),
				Active:    make([]activeVote, 0, 256),
				BestBlock: 0,
			}, nil
		}
		return nil, err
	}

	var inv inventory
	err = json.Unmarshal(b, &inv)
	if err != nil {
		return nil, err
	}

	return &inv, nil
}

// invSetLocked writes the inventory to disk.
//
// This function must be called WITH the lock held.
func (p *ticketVotePlugin) invSetLocked(inv inventory) error {
	b, err := json.Marshal(inv)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(p.invPath(), b, 0664)
	if err != nil {
		return err
	}
	return nil
}

// invAddToUnauthorized adds the token to the unauthorized vote status list.
// This is done when a unvetted record is made vetted or when a previous vote
// authorization is revoked.
func (p *ticketVotePlugin) invAddToUnauthorized(token string) {
	p.mtxInv.Lock()
	defer p.mtxInv.Unlock()

	inv, err := p.invGetLocked()
	if err != nil {
		panic(err)
	}

	var (
		// Human readable vote statuses
		unauth = ticketvote.VoteStatuses[ticketvote.VoteStatusUnauthorized]
		auth   = ticketvote.VoteStatuses[ticketvote.VoteStatusAuthorized]
	)

	// Remove token from the authorized list. It will only exit in the
	// authorized list if the user is revoking a previous authorization.
	ok := invDel(inv.Tokens, auth, token)
	if ok {
		log.Debugf("Vote inv del %v from authorized", token)
	}

	// Add the token to unauthorized
	invAdd(inv.Tokens, unauth, token)

	log.Debugf("Vote inv add %v to unauthorized", token)

	// Save inventory
	err = p.invSetLocked(*inv)
	if err != nil {
		panic(err)
	}
}

// invAddToAuthorized moves a record from the unauthorized to the authorized
// list. This is done by the ticketvote authorize command.
func (p *ticketVotePlugin) invAddToAuthorized(token string) {
	p.mtxInv.Lock()
	defer p.mtxInv.Unlock()

	inv, err := p.invGetLocked()
	if err != nil {
		panic(err)
	}

	var (
		// Human readable vote statuses
		unauth = ticketvote.VoteStatuses[ticketvote.VoteStatusUnauthorized]
		auth   = ticketvote.VoteStatuses[ticketvote.VoteStatusAuthorized]
	)

	// Remove the token from unauthorized list. The token should always
	// be in the unauthorized list.
	ok := invDel(inv.Tokens, unauth, token)
	if !ok {
		e := fmt.Sprintf("token not found in unauthorized list %v", token)
		panic(e)
	}

	log.Debugf("Vote inv del %v from unauthorized", token)

	// Prepend the token to the authorized list
	invAdd(inv.Tokens, auth, token)

	log.Debugf("Vote inv add %v to authorized", token)

	// Save inventory
	err = p.invSetLocked(*inv)
	if err != nil {
		panic(err)
	}
}

// invAddToStarted moves a record into the started vote status list. This is
// done by the ticketvote start command.
func (p *ticketVotePlugin) invAddToStarted(token string, t ticketvote.VoteT, endHeight uint32) {
	p.mtxInv.Lock()
	defer p.mtxInv.Unlock()

	inv, err := p.invGetLocked()
	if err != nil {
		panic(err)
	}

	var (
		// Human readable vote statuses
		unauth  = ticketvote.VoteStatuses[ticketvote.VoteStatusUnauthorized]
		auth    = ticketvote.VoteStatuses[ticketvote.VoteStatusAuthorized]
		started = ticketvote.VoteStatuses[ticketvote.VoteStatusStarted]
	)

	switch t {
	case ticketvote.VoteTypeStandard:
		// Remove the token from the authorized list. The token should
		// always be in the authorized list prior to the vote being
		// started for standard votes.
		ok := invDel(inv.Tokens, auth, token)
		if !ok {
			e := fmt.Sprintf("token not found in authorized list %v", token)
			panic(e)
		}

		log.Debugf("Vote inv del %v from authorized", token)

	case ticketvote.VoteTypeRunoff:
		// A runoff vote does not require the submissions be authorized
		// prior to the vote starting. The token should always be in the
		// unauthorized list.
		ok := invDel(inv.Tokens, unauth, token)
		if !ok {
			e := fmt.Sprintf("token not found in unauthorized list %v", token)
			panic(e)
		}

		log.Debugf("Vote inv del %v from unauthorized", token)

	default:
		e := fmt.Sprintf("invalid vote type %v", t)
		panic(e)
	}

	// Add token to started list
	invAdd(inv.Tokens, started, token)

	// Add token to active votes list
	vt := activeVote{
		Token:     token,
		EndHeight: endHeight,
	}
	inv.Active = append([]activeVote{vt}, inv.Active...)

	// Sort active votes
	sortActiveVotes(inv.Active)

	log.Debugf("Vote inv add %v to started with end height %v",
		token, endHeight)

	// Save inventory
	err = p.invSetLocked(*inv)
	if err != nil {
		panic(err)
	}
}

func (p *ticketVotePlugin) invGet(bestBlock uint32) (*inventory, error) {
	p.mtxInv.Lock()
	defer p.mtxInv.Unlock()

	inv, err := p.invGetLocked()
	if err != nil {
		panic(err)
	}

	// Check if the inventory has been updated for this block height.
	if inv.BestBlock == bestBlock {
		// Inventory already updated. Nothing else to do.
		return inv, nil
	}

	// The active votes should already be sorted, but sort them again
	// just to be sure.
	sortActiveVotes(inv.Active)

	// The inventory has not been updated for this block height. Check
	// if any votes have finished.
	active := make([]activeVote, 0, len(inv.Active))
	for _, v := range inv.Active {
		if v.EndHeight >= bestBlock {
			// Vote has not finished yet. Keep it in the active votes list.
			active = append(active, v)
		}

		// Vote has finished. Get vote summary.
		t, err := tokenDecode(v.Token)
		if err != nil {
			return nil, err
		}
		sr, err := p.summaryByToken(t)
		if err != nil {
			return nil, err
		}

		// Remove token from started list
		started := ticketvote.VoteStatuses[ticketvote.VoteStatusStarted]
		ok := invDel(inv.Tokens, started, v.Token)
		if !ok {
			return nil, fmt.Errorf("token not found in started %v", v.Token)
		}

		log.Debugf("Vote inv del %v from started", v.Token)

		// Add token to the appropriate list
		switch sr.Status {
		case ticketvote.VoteStatusFinished, ticketvote.VoteStatusApproved,
			ticketvote.VoteStatusRejected:
			// These statuses are allowed
			status := ticketvote.VoteStatuses[sr.Status]
			invAdd(inv.Tokens, status, v.Token)
		default:
			// Something went wrong
			return nil, fmt.Errorf("unexpected vote status %v %v",
				v.Token, sr.Status)
		}

		log.Debugf("Vote inv add %v to %v",
			v.Token, ticketvote.VoteStatuses[sr.Status])
	}

	// Update active votes list
	inv.Active = active

	// Update best block
	inv.BestBlock = bestBlock

	log.Debugf("Vote inv updated for block %v", bestBlock)

	// Save inventory
	err = p.invSetLocked(*inv)
	if err != nil {
		panic(err)
	}

	return inv, nil
}

func sortActiveVotes(v []activeVote) {
	// Sort by end height from smallest to largest
	sort.SliceStable(v, func(i, j int) bool {
		return v[i].EndHeight < v[j].EndHeight
	})
}

func invDel(inv map[string][]string, status, token string) bool {
	list, ok := inv[status]
	if !ok {
		inv[status] = make([]string, 0, 1056)
		return false
	}

	// Find token (linear time)
	var i int
	var found bool
	for k, v := range list {
		if v == token {
			i = k
			found = true
			break
		}
	}
	if !found {
		return found
	}

	// Remove token (linear time)
	copy(list[i:], list[i+1:]) // Shift list[i+1:] left one index
	list[len(list)-1] = ""     // Erase last element (write zero token)
	list = list[:len(list)-1]  // Truncate slice

	// Update inv
	inv[status] = list

	return found
}

func invAdd(inv map[string][]string, status, token string) {
	list, ok := inv[status]
	if !ok {
		list = make([]string, 0, 1056)
	}

	// Prepend token
	list = append([]string{token}, list...)

	// Update inv
	inv[status] = list
}
