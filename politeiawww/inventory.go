package main

import (
	"fmt"

	pd "github.com/decred/politeia/politeiad/api/v1"
)

var (
	errRecordNotFound = fmt.Errorf("record not found")
)

type inventoryRecord struct {
	record   pd.Record                 // actual record
	metadata map[uint64]interface{}    // [md type] cache for metadata streams
	comments map[uint64]BackendComment // [token][parent]comment
}

// initializeInventory initializes the inventory map and loads it with a
// InventoryReply.
//
// This function must be called WITH the mutex held.
func (b *backend) initializeInventory(inv *pd.InventoryReply) error {
	b._inventory = make(map[string]inventoryRecord)

	for _, v := range append(inv.Vetted, inv.Branches...) {
		if _, ok := b._inventory[v.CensorshipRecord.Token]; ok {
			return fmt.Errorf("duplicate token: %v",
				v.CensorshipRecord.Token)
		}

		b._inventory[v.CensorshipRecord.Token] = inventoryRecord{
			record:   v,
			metadata: make(map[uint64]interface{}),
			comments: make(map[uint64]BackendComment),
		}

		// Fish metadata out as well
		var (
			record interface{}
			err    error
		)
		for _, m := range v.Metadata {
			p := []byte(m.Payload)
			switch m.ID {
			case mdStreamGeneral:
				record, err = decodeBackendProposalMetadata(p)
			case mdStreamComments:
				err = b.loadComments(v.CensorshipRecord.Token,
					m.Payload)
			case mdStreamChanges:
				log.Errorf("initializeInventory: "+
					"skipping changes, fixme: %v",
					v.CensorshipRecord.Token)
			case mdStreamVoting:
				log.Errorf("initializeInventory: "+
					"skipping voting, fixme: %v",
					v.CensorshipRecord.Token)
			default:
				// log error but proceed
				log.Errorf("initializeInventory: invalid "+
					"metadata stream ID %v token %v", m.ID,
					v.CensorshipRecord.Token)
			}
			if err != nil {
				log.Errorf("initializeInventory %v: %v",
					v.CensorshipRecord.Token, err)
			}
			//ir.metadataCache[m.ID] = record
			_ = record
		}
	}

	return nil
}

// _getInventoryRecord reads an inventory record from the inventory cache.
//
// This function must be called WITH the mutex held.
func (b *backend) _getInventoryRecord(token string) (inventoryRecord, error) {
	r, ok := b._inventory[token]
	if !ok {
		return inventoryRecord{}, errRecordNotFound
	}
	return r, nil
}

// getInventoryRecord returns an inventory record from the inventory cache.
//
// This function must be called WITHOUT the mutex held.
func (b *backend) getInventoryRecord(token string) (inventoryRecord, error) {
	b.RLock()
	defer b.RUnlock()
	return b._getInventoryRecord(token)
}
