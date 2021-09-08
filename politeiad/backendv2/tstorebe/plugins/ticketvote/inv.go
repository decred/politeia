// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import (
	"encoding/json"
	"errors"

	"github.com/decred/politeia/politeiad/backendv2/tstorebe/inv"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
)

const (
	// Key-value store keys for the cached ticketvote inventory.
	invKey          = pluginID + "-inventory-v1"
	invExtraDataKey = pluginID + "-inventory-extradata-v1"
)

// invBits represents bit flags that are used to encode the vote status into an
// inventory entry. The inventory can be queried using these bit flags.
type invBits uint64

const (
	// Vote status bits. These map directly to the ticketvote vote
	// statuses and are used to request tokens from the inventory by
	// vote status.
	bitsInvalid            invBits = 0
	bitsStatusUnauthorized invBits = 1 << 0
	bitsStatusAuthorized   invBits = 1 << 1
	bitsStatusStarted      invBits = 1 << 2
	bitsStatusFinished     invBits = 1 << 3
	bitsStatusApproved     invBits = 1 << 4
	bitsStatusRejected     invBits = 1 << 5
	bitsStatusIneligible   invBits = 1 << 6
)

// updateInv updates the vote status of a record in the inventory. If the token
// does not exist in the inventory yet, an entry is created and added.
//
// An entryExtraData argument is optional and will only be provided for certain
// vote statuses.
func updateInv(tstore plugins.TstoreClient, token string, s ticketvote.VoteStatusT, timestamp int64, eed *entryExtraData) error {
	// Encode extra data
	var extraData string
	var err error
	if eed != nil {
		extraData, err = eed.encode()
		if err != nil {
			return err
		}
	}

	// Save invetory entry
	c := tstore.InvClient(invKey, false)
	e := inv.Entry{
		Token:     token,
		Bits:      uint64(convertVoteStatusToBits(s)),
		ExtraData: extraData,
	}
	err = c.Update(e)
	if errors.Is(err, inv.ErrEntryNotFound) {
		// Entry doesn't exist yet. Add it.
		err = c.Add(e)
	}
	if err != nil {
		return err
	}

	log.Debugf("Inv updated %v to %v", token, ticketvote.VoteStatuses[s])

	return nil
}

// invExtraData contains inventory metadata that is saved to the cache using
// the invExtraDataKey.
type invExtraData struct {
	BestBlock uint32 `json:"bestblock"` // Last update block height
}

// entryExtraData is the structure that is encoded and stuffed into the
// inventory entry ExtraData field. This will only be present on records with
// that are currently being voted on.
type entryExtraData struct {
	EndHeight uint32 `json:"endheight,omitempty"` // Vote end block height
}

// encode encodes the entryExtraData into a JSON encoded string.
func (e *entryExtraData) encode() (string, error) {
	b, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// decodeEntryExtraData decode a JSON encoded string into a entryExtraData.
func decodeEntryExtraData(s string) (*entryExtraData, error) {
	var eed entryExtraData
	err := json.Unmarshal([]byte(s), &eed)
	if err != nil {
		return nil, err
	}
	return &eed, nil
}

// convertVoteStatusToBits converts a vote status the appropriate inventory
// bit.
func convertVoteStatusToBits(s ticketvote.VoteStatusT) invBits {
	var b invBits
	switch s {
	case ticketvote.VoteStatusUnauthorized:
		b = bitsStatusUnauthorized
	case ticketvote.VoteStatusAuthorized:
		b = bitsStatusAuthorized
	case ticketvote.VoteStatusStarted:
		b = bitsStatusStarted
	case ticketvote.VoteStatusFinished:
		b = bitsStatusFinished
	case ticketvote.VoteStatusApproved:
		b = bitsStatusApproved
	case ticketvote.VoteStatusRejected:
		b = bitsStatusRejected
	case ticketvote.VoteStatusIneligible:
		b = bitsStatusIneligible
	}
	return b
}

/*
// inventory contains the full record inventory where each entry is encoded
// with ticketvote data that allows us to sort the record inventory by vote
// status.
//
// The unauthorized, authorized, and started statuses are updated in real-time
// since these statuses are initiated by ticketvote plugin commands or record
// hooks. The finished, approved, and rejected statuses are lazy loaded since
// they depend on external state (DCR block height).
type inventory struct {
	Version   uint32  `json:"version"` // Struct version
	Entries   []entry `json:"entries"`
	BestBlock uint32  `json:"bestblock"` // Last updated block height
}

// newInventory returns a new inventory.
func newInventory() *inventory {
	return &inventory{
		Entries:   make([]entry, 0, 256),
		BestBlock: 0,
	}
}

// getInventory retrieves the cached ticketvote inventory. A new inventory is
// returned if one does not exist yet.
func getInventory(g store.Getter) (*inventory, error) {
	// Setup the inventory client
	c, err := inv.Client(inventoryKey, false)
	if err != nil {
		return nil, err
	}

	// Get the inventory entries

	b, err := g.Get(inventoryKey)
	if err != nil {
		if err == store.NotFound {
			// Cached inventory doesn't exist
			// yet. Return a new one.
			return newInventory(), nil
		}
		return err
	}

	var inv inventory
	err = json.Unmarshal(b, &inv)
	if err != nil {
		return nil, err
	}

	return &inv, nil
}

// invSaveLocked writes the inventory to disk.
func (p *ticketVotePlugin) invSaveLocked(inv inventory) error {
	b, err := json.Marshal(inv)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(p.invPath(), b, 0664)
}

// invAdd adds a token to the ticketvote inventory.
func (p *ticketVotePlugin) invAdd(token string, s ticketvote.VoteStatusT) error {
	// Get inventory
	inv, err := p.getInventory()
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

// invUpdateLocked updates a pre existing token in the inventory to a new
// vote status.
func (p *ticketVotePlugin) invUpdateLocked(token string, s ticketvote.VoteStatusT, endHeight uint32) error {
	// Get inventory
	inv, err := p.getInventory()
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

// invUpdateForBlock updates the inventory for a new best block value. This
// means checking if ongoing ticket votes have finished and updating their
// status if they have.
func (p *ticketVotePlugin) invUpdateForBlock(bestBlock uint32) (*inventory, error) {
	inv, err := p.getInventory()
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
	inv, err = p.getInventory()
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
*/
