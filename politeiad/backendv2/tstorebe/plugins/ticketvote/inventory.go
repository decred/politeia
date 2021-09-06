// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	"github.com/pkg/errors"
)

const (
	// inventoryKey is the kv store key for the ticketvote inventory cache.
	inventoryKey = pluginID + "-inventory"
)

// entry is an inventory entry.
type entry struct {
	Token     string                 `json:"token"`
	Status    ticketvote.VoteStatusT `json:"status"`
	EndHeight uint32                 `json:"endheight,omitempty"`
}

// inventory contains the ticketvote inventory. The unauthorized, authorized,
// and started lists are updated in real-time since ticket vote plugin commands
// or hooks initiate those actions. The finished, approved, and rejected
// statuses are lazy loaded since those lists depends on external state (DCR
// block height).
type inventory struct {
	Entries   []entry `json:"entries"`
	BestBlock uint32  `json:"bestblock"`
}

// invPath returns the full path for the cached ticket vote inventory.
func (p *ticketVotePlugin) invPath() string {
	return filepath.Join(p.dataDir, filenameInventory)
}

// invGetLocked retrieves the inventory from disk. A new inventory is returned
// if one does not exist yet.
//
// This function must be called WITH the mtxInv read lock held.
func (p *ticketVotePlugin) invGetLocked() (*inventory, error) {
	b, err := ioutil.ReadFile(p.invPath())
	if err != nil {
		var e *os.PathError
		if errors.As(err, &e) && !os.IsExist(err) {
			// File does't exist. Return a new inventory.
			return &inventory{
				Entries:   make([]entry, 0, 256),
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

// invGetLocked retrieves the inventory from disk. A new inventory is returned
// if one does not exist yet.
//
// This function must be called WITHOUT the mtxInv write lock held.
func (p *ticketVotePlugin) invGet() (*inventory, error) {
	p.mtxInv.RLock()
	defer p.mtxInv.RUnlock()

	return p.invGetLocked()
}

// invSaveLocked writes the inventory to disk.
//
// This function must be called WITH the mtxInv write lock held.
func (p *ticketVotePlugin) invSaveLocked(inv inventory) error {
	b, err := json.Marshal(inv)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(p.invPath(), b, 0664)
}

/* TODO add inventory back in
// invAdd adds a token to the ticketvote inventory.
//
// This function must be called WITHOUT the mtxInv write lock held.
func (p *ticketVotePlugin) invAdd(token string, s ticketvote.VoteStatusT) error {
	p.mtxInv.Lock()
	defer p.mtxInv.Unlock()

	// Get inventory
	inv, err := p.invGetLocked()
	if err != nil {
		return err
	}

	// Prepend token
	e := entry{
		Token:  token,
		Status: s,
	}
	inv.Entries = append([]entry{e}, inv.Entries...)

	// Save inventory
	err = p.invSaveLocked(*inv)
	if err != nil {
		return err
	}

	log.Debugf("Vote inv add %v %v", token, ticketvote.VoteStatuses[s])

	return nil
}

// inventoryAdd is a wrapper around the invAdd method that allows us to decide
// how disk read/write errors should be handled. For now we just panic.
func (p *ticketVotePlugin) inventoryAdd(token string, s ticketvote.VoteStatusT) {
	err := p.invAdd(token, s)
	if err != nil {
		panic(fmt.Sprintf("invAdd %v %v: %v", token, s, err))
	}
}

// invUpdateLocked updates a pre existing token in the inventory to a new
// vote status.
//
// This function must be called WITH the mtxInv write lock held.
func (p *ticketVotePlugin) invUpdateLocked(token string, s ticketvote.VoteStatusT, endHeight uint32) error {
	// Get inventory
	inv, err := p.invGetLocked()
	if err != nil {
		return err
	}

	// Del entry
	entries, err := entryDel(inv.Entries, token)
	if err != nil {
		// This should not happen. Panic if it does.
		panic(fmt.Sprintf("entry del: %v", err))
	}

	// Prepend new entry to inventory
	e := entry{
		Token:     token,
		Status:    s,
		EndHeight: endHeight,
	}
	inv.Entries = append([]entry{e}, entries...)

	// Save inventory
	err = p.invSaveLocked(*inv)
	if err != nil {
		return err
	}

	log.Debugf("Vote inv update %v to %v", token, ticketvote.VoteStatuses[s])

	return nil
}

// invUpdate updates a pre existing token in the inventory to a new vote
// status.
//
// This function must be called WITHOUT the mtxInv write lock held.
func (p *ticketVotePlugin) invUpdate(token string, s ticketvote.VoteStatusT, endHeight uint32) error {
	p.mtxInv.Lock()
	defer p.mtxInv.Unlock()

	return p.invUpdateLocked(token, s, endHeight)
}

// inventoryUpdate is a wrapper around the invUpdate method that allows us to
// decide how disk read/write errors should be handled. For now we just panic.
func (p *ticketVotePlugin) inventoryUpdate(token string, s ticketvote.VoteStatusT) {
	err := p.invUpdate(token, s, 0)
	if err != nil {
		panic(fmt.Sprintf("invUpdate %v %v: %v", token, s, err))
	}
}

// invUpdateForBlock updates the inventory for a new best block value. This
// means checking if ongoing ticket votes have finished and updating their
// status if they have.
//
// This function must be called WITHOUT the mtxInv write lock held.
func (p *ticketVotePlugin) invUpdateForBlock(bestBlock uint32) (*inventory, error) {
	p.mtxInv.Lock()
	defer p.mtxInv.Unlock()

	inv, err := p.invGetLocked()
	if err != nil {
		return nil, err
	}
	if inv.BestBlock == bestBlock {
		return inv, nil
	}

	// Compile the votes that have ended
	ended := make([]entry, 0, 256)
	for _, v := range inv.Entries {
		if v.EndHeight == 0 {
			continue
		}
		if voteHasEnded(bestBlock, v.EndHeight) {
			ended = append(ended, v)
		}
	}

	// Sort by end height from smallest to largest so that they're
	// added to the inventory in the correct order.
	sort.SliceStable(ended, func(i, j int) bool {
		return ended[i].EndHeight < ended[j].EndHeight
	})

	// Update the inventory for the ended entries
	for _, v := range ended {
		// Get the vote summary
		token, err := tokenDecode(v.Token)
		if err != nil {
			return nil, err
		}
		sr, err := p.summaryByToken(token)
		if err != nil {
			return nil, err
		}

		// Update inventory
		switch sr.Status {
		case ticketvote.VoteStatusFinished, ticketvote.VoteStatusApproved,
			ticketvote.VoteStatusRejected:
			// These statuses are allowed
			err := p.invUpdateLocked(v.Token, sr.Status, 0)
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unexpected vote status %v %v",
				v.Token, sr.Status)
		}
	}

	// Update best block
	inv, err = p.invGetLocked()
	if err != nil {
		return nil, err
	}
	inv.BestBlock = bestBlock

	// Save inventory
	err = p.invSaveLocked(*inv)
	if err != nil {
		return nil, err
	}

	log.Debugf("Vote inv updated for block %v", bestBlock)

	return inv, nil
}

// inventoryUpdateToStarted is a wrapper around the invUpdate method that
// allows us to decide how disk read/write errors should be handled. For now we
// just panic.
func (p *ticketVotePlugin) inventoryUpdateToStarted(token string, s ticketvote.VoteStatusT, endHeight uint32) {
	err := p.invUpdate(token, s, endHeight)
	if err != nil {
		panic(fmt.Sprintf("invUpdate %v %v: %v", token, s, err))
	}
}

// inventory returns the full ticketvote inventory.
func (p *ticketVotePlugin) Inventory(bestBlock uint32) (*inventory, error) {
	// Get inventory
	inv, err := p.invGet()
	if err != nil {
		return nil, err
	}

	// Check if the inventory has been updated for this block height.
	if bestBlock > inv.BestBlock {
		// Inventory has not been update for this block. Update it.
		return p.invUpdateForBlock(bestBlock)
	}

	return inv, nil
}

// invByStatus contains the inventory categorized by vote status. Each list
// contains a page of tokens that are sorted by the timestamp of the status
// change from newest to oldest.
type invByStatus struct {
	Tokens    map[ticketvote.VoteStatusT][]string
	BestBlock uint32
}

// invByStatusAll returns a page of token for all vote statuses.
func (p *ticketVotePlugin) invByStatusAll(bestBlock, pageSize uint32) (*invByStatus, error) {
	// Get inventory
	i, err := p.Inventory(bestBlock)
	if err != nil {
		return nil, err
	}

	// Prepare reply
	var (
		unauth = tokensParse(i.Entries, ticketvote.VoteStatusUnauthorized,
			pageSize, 1)
		auth = tokensParse(i.Entries, ticketvote.VoteStatusAuthorized,
			pageSize, 1)
		started = tokensParse(i.Entries, ticketvote.VoteStatusStarted,
			pageSize, 1)
		finished = tokensParse(i.Entries, ticketvote.VoteStatusFinished,
			pageSize, 1)
		approved = tokensParse(i.Entries, ticketvote.VoteStatusApproved,
			pageSize, 1)
		rejected = tokensParse(i.Entries, ticketvote.VoteStatusRejected,
			pageSize, 1)
		ineligible = tokensParse(i.Entries, ticketvote.VoteStatusIneligible,
			pageSize, 1)

		tokens = make(map[ticketvote.VoteStatusT][]string, 16)
	)
	if len(unauth) != 0 {
		tokens[ticketvote.VoteStatusUnauthorized] = unauth
	}
	if len(auth) != 0 {
		tokens[ticketvote.VoteStatusAuthorized] = auth
	}
	if len(started) != 0 {
		tokens[ticketvote.VoteStatusStarted] = started
	}
	if len(finished) != 0 {
		tokens[ticketvote.VoteStatusFinished] = finished
	}
	if len(approved) != 0 {
		tokens[ticketvote.VoteStatusApproved] = approved
	}
	if len(rejected) != 0 {
		tokens[ticketvote.VoteStatusRejected] = rejected
	}
	if len(ineligible) != 0 {
		tokens[ticketvote.VoteStatusIneligible] = ineligible
	}

	return &invByStatus{
		Tokens:    tokens,
		BestBlock: i.BestBlock,
	}, nil
}

// inventoryByStatus returns a page of tokens for the provided status. If no
// status is provided then a page for each status will be returned.
func (p *ticketVotePlugin) inventoryByStatus(bestBlock uint32, s ticketvote.VoteStatusT, page uint32) (*invByStatus, error) {
	pageSize := ticketvote.InventoryPageSize

	// If no status is provided a page of tokens for each status should
	// be returned.
	if s == ticketvote.VoteStatusInvalid {
		return p.invByStatusAll(bestBlock, pageSize)
	}

	// A status was provided. Return a page of tokens for the status.
	inv, err := p.Inventory(bestBlock)
	if err != nil {
		return nil, err
	}
	tokens := tokensParse(inv.Entries, s, pageSize, page)

	return &invByStatus{
		Tokens: map[ticketvote.VoteStatusT][]string{
			s: tokens,
		},
		BestBlock: inv.BestBlock,
	}, nil
}

// entryDel removes the entry for the token and returns the updated slice.
func entryDel(entries []entry, token string) ([]entry, error) {
	// Find token in entries
	var i int
	var found bool
	for k, v := range entries {
		if v.Token == token {
			i = k
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("token not found %v", token)
	}

	// Del token from entries (linear time)
	copy(entries[i:], entries[i+1:])   // Shift entries[i+1:] left one index
	entries[len(entries)-1] = entry{}  // Del last element (write zero value)
	entries = entries[:len(entries)-1] // Truncate slice

	return entries, nil
}

// tokensParse parses a page of tokens from the provided entries.
func tokensParse(entries []entry, s ticketvote.VoteStatusT, countPerPage, page uint32) []string {
	tokens := make([]string, 0, countPerPage)
	if countPerPage == 0 || page == 0 {
		return tokens
	}

	startAt := (page - 1) * countPerPage
	var foundCount uint32
	for _, v := range entries {
		if v.Status != s {
			// Status does not match
			continue
		}

		// Matching status found
		if foundCount >= startAt {
			tokens = append(tokens, v.Token)
			if len(tokens) == int(countPerPage) {
				// We got a full page. We're done.
				return tokens
			}
		}

		foundCount++
	}

	return tokens
}
*/
