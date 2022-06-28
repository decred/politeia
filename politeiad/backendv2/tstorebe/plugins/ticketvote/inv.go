// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import (
	"encoding/json"
	"sync"

	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	"github.com/pkg/errors"
)

// inv contains the ticketvote inventory. The inventory is saved to the plugin
// cache that is provided by the tstore backend.
//
// The unauthorized, authorized, and started lists are updated in real-time
// since ticket vote plugin commands or hooks initiate those actions.
//
// The finished, approved, and rejected statuses are lazy loaded since those
// lists depends on external state (DCR block height).
type inv struct {
	Entries map[ticketvote.VoteStatusT][]invEntry `json:"entries"`

	// BestBlock is the block height that the inventory has been updated with.
	BestBlock uint32 `json:"bestblock"`
}

// invEntry is an inventory entry.
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

// invCtx provides an API for interacting with the cached ticketvote inventory.
// The inventory is saved to the Tstore provided plugin cache.
//
// A mutex is required because tstore does not execute writes using a sql
// transaction. This means concurrent access to the plugin cache must be
// control locally using this mutex.
type invCtx struct {
	sync.Mutex
	tstore plugins.TstoreClient
}

// newInvCtx returns a new invCtx.
func newInvCtx(tstore plugins.TstoreClient) *invCtx {
	return &invCtx{
		tstore: tstore,
	}
}

// AddEntry adds a new entry to the inventory.
//
// New entries will always correspond to a vote status that has not been voted
// on yet. This is why a timestamp is required and not the end height.
//
// The plugin writes are not currently executed using a sql transaction, which
// means that there is no way to unwind previous writes if this cache update
// fails. For this reason, we panic instead of returning an error so that the
// sysadmin is alerted that the cache is incoherent and needs to be rebuilt.
func (c *invCtx) AddEntry(token string, status ticketvote.VoteStatusT, timestamp int64) {
	c.Lock()
	defer c.Unlock()
}

func (c *invCtx) UpdateEntryPreVote(token string, status ticketvote.VoteStatusT, timestamp int64) {
	c.Lock()
	defer c.Unlock()
}

func (c *invCtx) UpdateEntryPostVote(token string, status ticketvote.VoteStatusT, endBlockHeight uint32) {
	c.Lock()
	defer c.Unlock()
}

// Page returns a page of inventory results for all vote statuses.
//
// The best block is required to ensure that the returned results are
// up-to-date. Certain inventory statuses, such as VoteStatusFinished, are
// updated based on the vote's ending block height and the best block.
func (c *invCtx) GetPage(bestBlock uint32) (*inv, error) {
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
func (c *invCtx) GetPageForStatus(bestBlock uint32, status ticketvote.VoteStatusT, page uint32) ([]invEntry, error) {
	return nil, nil
}

// Rebuild rebuilds the inventory from scratch and saves it to the tstore
// provided cache.
func (c invCtx) Rebuild() error {
	return nil
}

var (
	// invKey is the key-value store key for the cached inventory.
	invKey = "inv"
)

// setInv saves the inventory to the tstore cache.
func (c *invCtx) setInv(inv inv) error {
	b, err := json.Marshal(inv)
	if err != nil {
		return err
	}
	return c.tstore.CachePut(map[string][]byte{invKey: b}, false)
}

// getInv returns the inventory from the tstore cache.
func (c *invCtx) getInv() (*inv, error) {
	blobs, err := c.tstore.CacheGet([]string{invKey})
	if err != nil {
		return nil, err
	}
	b, ok := blobs[invKey]
	if !ok {
		return nil, errors.Errorf("inv not found")
	}
	var i inv
	err = json.Unmarshal(b, &i)
	if err != nil {
		return nil, err
	}
	return &i, nil
}

// entryTokens filters and returns the tokens from the inventory entries.
func entryTokens(entries []invEntry) []string {
	tokens := make([]string, 0, 2048)
	for _, v := range entries {
		tokens = append(tokens, v.Token)
	}
	return tokens
}
