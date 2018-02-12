package main

import (
	"fmt"

	pd "github.com/decred/politeia/politeiad/api/v1"
)

var (
	errRecordNotFound = fmt.Errorf("record not found")
)

type inventoryRecord struct {
	record        pd.Record        // actual record
	metadataCache [int]interface{} // cache for metadata streams
}

// initializeInventory initializes the inventory map and loads it with a
// InventoryReply.
//
// This function must be called WITH the mutex held.
func (b *backend) initializeInventory(inv *pd.InventoryReply) error {
	b._inventory = make(map[string]pd.Record)

	for _, v := range append(inv.Vetted, inv.Branches...) {
		if _, ok := b._inventory[v.CensorshipRecord.Token]; ok {
			return fmt.Errorf("duplicate token: %v",
				v.CensorshipRecord.Token)
		}
		b._inventory[v.CensorshipRecord.Token] = v
	}

	return nil
}

// _getInventoryRecord reads an inventory record from the inventory cache.
//
// This function must be called WITH the mutex held.
func (b *backend) _getInventoryRecord(token string) (*pd.Record, error) {
	r, ok := b._inventory[token]
	if !ok {
		return nil, errRecordNotFound
	}
	return &r, nil
}

// getInventoryRecord returns an inventory record from the inventory cache.
//
// This function must be called WITHOUT the mutex held.
func (b *backend) getInventoryRecord(token string) (*pd.Record, error) {
	b.RLock()
	defer b.RUnlock()
	return b._getInventoryRecord(token)
}

// getInventoryRecordMD returns a metadata record from the inventory record
// cache.
//
// This function must be called WITHOUT the mutex held.
func (b *backend) getInventoryRecordMD(token string, md int) (interface{}, error) {
	b.RLock()
	defer b.RUnlock()
	return b._getInventoryRecordMD(token, md)
}
