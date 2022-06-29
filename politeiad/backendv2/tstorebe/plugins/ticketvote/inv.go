// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import (
	"encoding/json"
	"fmt"
	"sort"
	"sync"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	"github.com/pkg/errors"
)

// inv represents the ticketvote inventory.
//
// The unauthorized, authorized, and started lists are updated in real-time
// since ticketvote plugin commands and hooks initiate those actions.
//
// The finished, approved, and rejected statuses are lazy loaded since those
// lists depend on external state (the DCR block height).
//
// The invCtx structure provides an API for interacting with the ticketvote
// inventory.
type inv struct {
	// Entries contains the inventory entries categorized by vote
	// status and sorted from oldest to newest.
	//
	// Entries that are pre vote are sorted by the timestamp of the
	// vote status change. Entries that have begun voting or are post
	// vote are sorted by the vote's end block height.
	Entries map[ticketvote.VoteStatusT][]invEntry `json:"entries"`

	// BlockHeight is the block height that the inventory has been
	// updated with.
	BlockHeight uint32 `json:"block_height"`
}

// newInv returns a new inv.
func newInv() *inv {
	return &inv{
		Entries:     make(map[ticketvote.VoteStatusT][]invEntry),
		BlockHeight: 0,
	}
}

// Add adds an entry to the inventory. The entry is prepended onto the list
// that contains the other entries with the same vote status. The entries
//
func (i *inv) Add(e invEntry) {
	entries, ok := i.Entries[e.Status]
	if !ok {
		entries = make([]invEntry, 0, 64)
	}
	i.Entries[e.Status] = append([]invEntry{e}, entries...)
}

// Del deletes an entry from the inventory.
//
// Status is the current status of the inventory entry.
func (i *inv) Del(token string, status ticketvote.VoteStatusT) error {
	// Find the existing entry
	entries := i.Entries[status]
	var (
		idx   int // Index of target entry
		found bool
	)
	for k, v := range entries {
		if v.Token == token {
			idx = k
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("entry not found %v %v", token, status)
	}

	// Delete the entry from the list (linear time)
	copy(entries[idx:], entries[idx+1:]) // Shift entries[i+1:] left one index
	entries[len(entries)-1] = invEntry{} // Del last element (write zero value)
	entries = entries[:len(entries)-1]   // Truncate slice

	// Save the updated list
	i.Entries[status] = entries

	return nil
}

// invEntry is an entry in the ticketvote inventory.
type invEntry struct {
	Token  string                 `json:"token"`
	Status ticketvote.VoteStatusT `json:"status"`

	// Timestamp is the timestamp of the last vote status change. This
	// is used to order the inventory entries for records that have not
	// yet started voting. Once the vote has begun for a record, this
	// field will be set to 0 and the EndHeight field will be used for
	// ordering.
	Timestamp int64 `json:"timestamp,omitempty"`

	// EndBlockHeight is the end block height of the vote. This is used
	// to order the inventory entries of records that are being voted
	// on or have already been voted on. This field will be set to 0 if
	// the vote has not begun yet.
	EndBlockHeight uint32 `json:"endblockheight,omitempty"`
}

// newInvEntry returns a new invEntry.
func newInvEntry(token string, status ticketvote.VoteStatusT, timestamp int64, endBlockHeight uint32) *invEntry {
	return &invEntry{
		Token:          token,
		Status:         status,
		Timestamp:      timestamp,
		EndBlockHeight: endBlockHeight,
	}
}

// invCtx provides an API for interacting with the cached ticketvote inventory.
// The inventory is saved to the TstoreClient provided plugin cache.
//
// A mutex is required because tstore does not execute writes using a sql
// transaction. This means concurrent access to the plugin cache must be
// control locally using this mutex.
type invCtx struct {
	sync.Mutex
	tstore  plugins.TstoreClient
	backend backend.Backend
}

// newInvCtx returns a new invCtx.
func newInvCtx(tstore plugins.TstoreClient, backend backend.Backend) *invCtx {
	return &invCtx{
		tstore:  tstore,
		backend: backend,
	}
}

// AddEntry adds a new entry to the inventory.
//
// New entries will always correspond to a vote status that has not been voted
// on yet. This is why a timestamp is required and not the end height. The
// timestamp of the timestamp of the vote status change.
//
// Plugin writes are not currently executed using a sql transaction, which
// means that there is no way to unwind previous writes if this cache update
// fails. For this reason, we panic instead of returning an error so that the
// sysadmin is alerted that the cache is incoherent and needs to be rebuilt.
//
// This function is concurrency safe.
func (c *invCtx) AddEntry(token string, status ticketvote.VoteStatusT, timestamp int64) {
	c.Lock()
	defer c.Unlock()

	err := c.addEntry(token, status, timestamp)
	if err != nil {
		e := fmt.Sprintf("%v %v %v: %v", token, status, timestamp, err)
		panic(e)
	}
}

// This function is concurrency safe.
func (c *invCtx) UpdateEntryPreVote(token string, status ticketvote.VoteStatusT, timestamp int64) {
	c.Lock()
	defer c.Unlock()
}

// This function is concurrency safe.
func (c *invCtx) UpdateEntryPostVote(token string, status ticketvote.VoteStatusT, endBlockHeight uint32) {
	c.Lock()
	defer c.Unlock()
}

// Page returns a page of inventory results for all vote statuses.
//
// The best block is required to ensure that the returned results are
// up-to-date. Certain inventory statuses, such as VoteStatusFinished, are
// updated based on the vote's ending block height and the best block.
//
// This function is concurrency safe.
func (c *invCtx) GetPage(bestBlock uint32) (*inv, error) {
	c.Lock()
	defer c.Unlock()

	return nil, nil
}

// PageForStatus returns a page of inventory results for the provided vote
// status.
//
// The best block is required to ensure that the returned results are
// up-to-date. Certain inventory statuses, such as VoteStatusFinished, are
// updated based on the vote's ending block height and the best block.
//
// The page is the page number that is being requested. Page 1 corresponds to
// the most recent page of inventory entries.
//
// This function is concurrency safe.
func (c *invCtx) GetPageForStatus(bestBlock uint32, status ticketvote.VoteStatusT, page uint32) ([]invEntry, error) {
	c.Lock()
	defer c.Unlock()

	return nil, nil
}

// Rebuild rebuilds the inventory from scratch and saves it to the tstore
// provided cache.
func (c invCtx) Rebuild() error {
	return nil
}

// addEntry adds a new entry to the inventory.
//
// New entries will always correspond to a vote status that has not been voted
// on yet. This is why a timestamp is required and not the end height. The
// timestamp of the timestamp of the vote status change.
//
// This function is not concurrency safe and must be called with the mutex
// locked.
func (c *invCtx) addEntry(token string, status ticketvote.VoteStatusT, timestamp int64) error {
	inv, err := c.getInv()
	if err != nil {
		return err
	}

	e := newInvEntry(token, status, timestamp, 0)
	inv.Add(*e)

	err = c.saveInv(*inv)
	if err != nil {
		return err
	}

	s := ticketvote.VoteStatuses[status]
	log.Debugf("Vote inv entry added %v %v", token, s)

	return nil
}

// updateBlockHeight updates the inventory with a new block height. Any votes
// that have ended based on the new block height are updated in the inventory
// based on the vote's outcome (passed, failed, etc).
//
// This function is not concurrency safe and must be called with the mutex
// locked.
func (c *invCtx) updateBlockHeight(blockHeight uint32) (*inv, error) {
	inv, err := c.getInv()
	if err != nil {
		return nil, err
	}
	if inv.BlockHeight == blockHeight {
		// Inventory is up-to-date
		return inv, nil
	}

	// Compile the votes that have ended since the previous
	// update.
	ended := make([]invEntry, 0, 256)
	started := inv.Entries[ticketvote.VoteStatusStarted]
	for _, v := range started {
		if voteHasEnded(blockHeight, v.EndBlockHeight) {
			ended = append(ended, v)
		}
	}

	// Sort by end height from smallest to largest so that
	// they're added to the inventory in the correct order.
	sort.SliceStable(ended, func(i, j int) bool {
		return ended[i].EndBlockHeight < ended[j].EndBlockHeight
	})

	// Update the inventory entries whose vote has ended.
	// We need to get the vote summary for each entry to
	// determine if the vote passed or failed.
	for _, v := range ended {
		s, err := c.summary(v.Token)
		if err != nil {
			return nil, err
		}
		switch s.Status {
		case ticketvote.VoteStatusFinished,
			ticketvote.VoteStatusApproved,
			ticketvote.VoteStatusRejected:
			// These statuses are expected. Update the entry in
			// the inventory.
			err = inv.Del(v.Token, ticketvote.VoteStatusStarted)
			if err != nil {
				return nil, err
			}
			e := newInvEntry(v.Token, s.Status, 0, s.EndBlockHeight)
			inv.Add(*e)

		default:
			// Something went wrong
			return nil, errors.Errorf("unexpected vote status %v %v",
				v.Token, s.Status)
		}
	}

	// Save the updated inventory
	err = c.saveInv(*inv)
	if err != nil {
		return nil, err
	}

	log.Debugf("Inv updated for block %v", blockHeight)

	return inv, nil
}

var (
	// invKey is the key-value store key for the cached inventory.
	invKey = "inv"
)

// saveInv saves the inventory to the tstore cache.
func (c *invCtx) saveInv(inv inv) error {
	b, err := json.Marshal(inv)
	if err != nil {
		return err
	}
	return c.tstore.CachePut(map[string][]byte{invKey: b}, false)
}

// getInv returns the inventory from the tstore cache. A new inv is returned
// if one does not exist in the cache.
func (c *invCtx) getInv() (*inv, error) {
	blobs, err := c.tstore.CacheGet([]string{invKey})
	if err != nil {
		return nil, err
	}
	b, ok := blobs[invKey]
	if !ok {
		// The inventory doesn't exist. Return a new one.
		return newInv(), nil
	}
	var i inv
	err = json.Unmarshal(b, &i)
	if err != nil {
		return nil, err
	}
	return &i, nil
}

// summary returns the vote summary for a record.
func (c *invCtx) summary(token string) (*ticketvote.SummaryReply, error) {
	tokenB, err := tokenDecode(token)
	if err != nil {
		return nil, err
	}
	reply, err := c.backend.PluginRead(tokenB,
		ticketvote.PluginID, ticketvote.CmdSummary, "")
	if err != nil {
		return nil, err
	}
	var sr ticketvote.SummaryReply
	err = json.Unmarshal([]byte(reply), &sr)
	if err != nil {
		return nil, err
	}
	return &sr, nil
}

// entryTokens filters and returns the tokens from the inventory entries.
func entryTokens(entries []invEntry) []string {
	tokens := make([]string, 0, 2048)
	for _, v := range entries {
		tokens = append(tokens, v.Token)
	}
	return tokens
}
