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
// that contains the other entries with the same vote status.
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

// Sort sorts the inventory entries.
//
// The inventory entries are categorized by vote status and sorted from newest
// to oldest. The vote statuses that occur prior to the start of the voting
// period are sorted by the timestamp of the vote status change. The vote
// statuses that occur after a vote has been started or has finished are sorted
// by the vote's end block height.
func (i *inv) Sort() {
	for status, entries := range i.Entries {
		switch status {
		case ticketvote.VoteStatusUnauthorized,
			ticketvote.VoteStatusAuthorized,
			ticketvote.VoteStatusIneligible:

			// Sort by the timestamps from newest to oldest
			sort.SliceStable(entries, func(i, j int) bool {
				return entries[i].Timestamp > entries[j].Timestamp
			})

		case ticketvote.VoteStatusStarted,
			ticketvote.VoteStatusFinished,
			ticketvote.VoteStatusApproved,
			ticketvote.VoteStatusRejected:

			// Sort by the end block heights from newest to oldest
			sort.SliceStable(entries, func(i, j int) bool {
				return entries[i].EndBlockHeight > entries[j].EndBlockHeight
			})

		default:
			// Should not happen
			e := fmt.Sprintf("unknown vote status %v", status)
			panic(e)
		}

		i.Entries[status] = entries
	}
}

// GetPage returns a page of inventory entries.
func (i *inv) GetPage(status ticketvote.VoteStatusT, pageNumber, pageSize uint32) []invEntry {
	entries, ok := i.Entries[status]
	if !ok {
		return []invEntry{}
	}
	if pageSize == 0 || pageNumber == 0 {
		return []invEntry{}
	}
	var (
		startIdx = int((pageNumber - 1) * pageSize) // Inclusive
		endIdx   = startIdx + int(pageSize)         // Exclusive
	)
	if startIdx >= len(entries) {
		return []invEntry{}
	}
	if endIdx >= len(entries) {
		// The inventory does not contain a full
		// page of entries at the requested page
		// number. Return a partial page.
		return entries[startIdx:]
	}
	// Return a full page of entries
	return entries[startIdx:endIdx]
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
//
// This implementation will have performance limitations once the inventory
// gets large enough. Probably once the number of records gets into the
// thousands. This will not be an issue for Decred for quite a while and by the
// time it does become an issue, the plugins should have much more
// sophisticated caching API available to them, such as the ability to create
// their own db tables that they can run sql queries against.
type invCtx struct {
	sync.Mutex
	tstore   plugins.TstoreClient
	backend  backend.Backend
	pageSize uint32
}

// newInvCtx returns a new invCtx.
func newInvCtx(tstore plugins.TstoreClient, backend backend.Backend, pageSize uint32) *invCtx {
	return &invCtx{
		tstore:   tstore,
		backend:  backend,
		pageSize: pageSize,
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

// UpdateEntryPreVote updates an entry in the inventory whose voting period has
// not yet begun. The timestamp is the timestamp of the vote status change.
// The inventory entries whose voting period has not yet begun are ordered
// using this timestamp.
//
// Plugin writes are not currently executed using a sql transaction, which
// means that there is no way to unwind previous writes if this cache update
// fails. For this reason, we panic instead of returning an error so that the
// sysadmin is alerted that the cache is incoherent and needs to be rebuilt.
//
// This function is concurrency safe.
func (c *invCtx) UpdateEntryPreVote(token string, status ticketvote.VoteStatusT, timestamp int64) {
	c.Lock()
	defer c.Unlock()

	err := c.updateEntry(token, status, timestamp, 0)
	if err != nil {
		e := fmt.Sprintf("%v %v %v: %v", token, status, timestamp, err)
		panic(e)
	}
}

// UpdateEntryPostVote updates an entry in the inventory whose voting period
// has been started or has already finished. The inventory entries that fall
// into this category are ordered by the endBlockHeight of the voting period.
//
// Plugin writes are not currently executed using a sql transaction, which
// means that there is no way to unwind previous writes if this cache update
// fails. For this reason, we panic instead of returning an error so that the
// sysadmin is alerted that the cache is incoherent and needs to be rebuilt.
//
// This function is concurrency safe.
func (c *invCtx) UpdateEntryPostVote(token string, status ticketvote.VoteStatusT, endBlockHeight uint32) {
	c.Lock()
	defer c.Unlock()

	err := c.updateEntry(token, status, 0, endBlockHeight)
	if err != nil {
		e := fmt.Sprintf("%v %v %v: %v", token, status, endBlockHeight, err)
		panic(e)
	}
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

	fullInv, err := c.updateBlockHeight(bestBlock)
	if err != nil {
		return nil, err
	}
	invPage := newInv()
	for status := range fullInv.Entries {
		invPage.Entries[status] = fullInv.GetPage(status, 1, c.pageSize)
	}

	return invPage, nil
}

// PageForStatus returns a page of inventory results for the provided vote
// status.
//
// Page 1 corresponds to the most recent page of inventory entries.
//
// This function is concurrency safe.
func (c *invCtx) GetPageForStatus(bestBlock uint32, status ticketvote.VoteStatusT, pageNumber uint32) ([]invEntry, error) {
	c.Lock()
	defer c.Unlock()

	fullInv, err := c.updateBlockHeight(bestBlock)
	if err != nil {
		return nil, err
	}

	return fullInv.GetPage(status, pageNumber, c.pageSize), nil
}

// Rebuild rebuilds the inventory using the provided inventory entries and
// saves it to the tstore plugin cache.
//
// This function is concurrency safe.
func (c *invCtx) Rebuild(entries []invEntry) error {
	c.Lock()
	defer c.Unlock()

	inv := newInv()
	for _, v := range entries {
		inv.Add(v)
	}
	inv.Sort()

	return c.saveInv(*inv)
}

// addEntry adds a new entry to the inventory.
//
// New entries will always correspond to a vote status that has not been voted
// on yet. This is why a timestamp is required and not the end height. The
// timestamp of the timestamp of the vote status change.
//
// This function is not concurrency safe. It must be called with the mutex
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

// updateEntry updates an existing inventory entry. The existing entry is
// deleted from the inventory and a new entry is added using the provided
// arguments. The updated inventory is saved to the tstore plugin cache.
//
// This function is not concurrency safe. It must be called with the mutex
// locked.
func (c *invCtx) updateEntry(token string, status ticketvote.VoteStatusT, timestamp int64, endBlockHeight uint32) error {
	// Get the existing inventory
	inv, err := c.getInv()
	if err != nil {
		return err
	}

	// We must first delete the existing entry from the inventory
	// before we can add the updated entry. To do this, we need
	// to know the vote status of the existing entry. We ascertain
	// this info using the vote status of the updated entry. For
	// example, an entry that is being updated to the status of
	// VoteStatusStarted must currently exist in the inventory
	// under the status of VoteStatusAuthorized.
	var (
		// statusesToScan is populated with the vote statuses that
		// will be scanned in order to find the existing entry.
		statusesToScan []ticketvote.VoteStatusT

		// prevStatus is the status of the record's existing
		// inventory entry. We need to know this in order to
		// delete the existing entry.
		prevStatus ticketvote.VoteStatusT
	)
	switch status {
	case ticketvote.VoteStatusUnauthorized:
		statusesToScan = []ticketvote.VoteStatusT{
			ticketvote.VoteStatusAuthorized,
		}

	case ticketvote.VoteStatusAuthorized:
		statusesToScan = []ticketvote.VoteStatusT{
			ticketvote.VoteStatusUnauthorized,
		}

	case ticketvote.VoteStatusStarted:
		statusesToScan = []ticketvote.VoteStatusT{
			ticketvote.VoteStatusAuthorized,
		}

	case ticketvote.VoteStatusFinished,
		ticketvote.VoteStatusApproved,
		ticketvote.VoteStatusRejected:
		statusesToScan = []ticketvote.VoteStatusT{
			ticketvote.VoteStatusStarted,
		}

	case ticketvote.VoteStatusIneligible:
		statusesToScan = []ticketvote.VoteStatusT{
			ticketvote.VoteStatusAuthorized,
			ticketvote.VoteStatusUnauthorized,
		}

	default:
		// This should not happen. If this path is getting hit then
		// there is likely a bug somewhere. Log an error instead of
		// returning one so that the caller does not panic. Search
		// the full inventory. An error will be returned below if
		// the token is not found in the inventory.
		log.Errorf("Update vote inv entry unknown status %v %v", token, status)
		for s, entries := range inv.Entries {
			if entriesIncludeToken(entries, token) {
				prevStatus = s
				break
			}
		}
	}

	// Find the existing inventory entry for the record
	for _, s := range statusesToScan {
		entries, ok := inv.Entries[s]
		if !ok {
			continue
		}
		if entriesIncludeToken(entries, token) {
			prevStatus = s
			break
		}
	}

	// Delete the existing entry then add the updated entry to
	// the inventory.
	err = inv.Del(token, prevStatus)
	if err != nil {
		return err
	}
	e := newInvEntry(token, status, timestamp, endBlockHeight)
	inv.Add(*e)

	// Save the updated inventory
	err = c.saveInv(*inv)
	if err != nil {
		return err
	}

	var (
		prevStatusStr = ticketvote.VoteStatuses[prevStatus]
		statusStr     = ticketvote.VoteStatuses[status]
	)
	log.Debugf("Vote inv update %v from %v to %v",
		token, prevStatusStr, statusStr)

	return nil
}

// updateBlockHeight updates the inventory with a new block height. Any votes
// that have ended based on the new block height are updated in the inventory
// based on the vote's outcome (passed, failed, etc).
//
// This function is not concurrency safe. It must be called with the mutex
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

	// Sort by end height from oldest to newest so that
	// they're added to the inventory in the correct order.
	// They are prepended onto the inventory list so we
	// want the newest to be added last.
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

	// Update the inventory block height
	inv.BlockHeight = blockHeight

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
func (c *invCtx) saveInv(i inv) error {
	b, err := json.Marshal(i)
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

// entriesIncludeToken returns whether the inventory entries include an entry
// that matches the provided token.
func entriesIncludeToken(entries []invEntry, token string) bool {
	var found bool
	for _, v := range entries {
		if v.Token == token {
			found = true
			break
		}
	}
	return found
}

// entryTokens filters and returns the tokens from the inventory entries.
func entryTokens(entries []invEntry) []string {
	tokens := make([]string, 0, 2048)
	for _, v := range entries {
		tokens = append(tokens, v.Token)
	}
	return tokens
}
