package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	pd "github.com/decred/politeia/politeiad/api/v1"
)

var (
	errRecordNotFound = fmt.Errorf("record not found")
)

type inventoryRecord struct {
	record     pd.Record                 // actual record
	proposalMD BackendProposalMetadata   // proposal metadata
	comments   map[uint64]BackendComment // [token][parent]comment
	changes    []MDStreamChanges         // changes metadata
	voting     []MDStreamVoting          // voting metadata
}

// initializeInventory initializes the inventory map and loads it with a
// InventoryReply.
//
// This function must be called WITH the mutex held.
func (b *backend) initializeInventory(inv *pd.InventoryReply) error {
	b._inventory = make(map[string]*inventoryRecord)

	for _, v := range append(inv.Vetted, inv.Branches...) {
		t := v.CensorshipRecord.Token
		if _, ok := b._inventory[t]; ok {
			return fmt.Errorf("duplicate token: %v",
				v.CensorshipRecord.Token)
		}

		b._inventory[t] = &inventoryRecord{
			record:   v,
			comments: make(map[uint64]BackendComment),
		}

		// Fish metadata out as well
		var err error
		for _, m := range v.Metadata {
			switch m.ID {
			case mdStreamGeneral:
				err = b.loadPropMD(t, m.Payload)
				if err != nil {
					log.Errorf("initializeInventory "+
						"could not load metadata: %v",
						err)
					continue
				}
			case mdStreamComments:
				err = b.loadComments(t, m.Payload)
				if err != nil {
					log.Errorf("initializeInventory "+
						"could not load comments: %v",
						err)
					continue
				}
			case mdStreamChanges:
				err = b.loadChanges(t, m.Payload)
				if err != nil {
					log.Errorf("initializeInventory "+
						"could not load changes: %v",
						err)
					continue
				}
			case mdStreamVoting:
				err = b.loadVoting(t, m.Payload)
				if err != nil {
					log.Errorf("initializeInventory "+
						"could not load vote: %v",
						err)
					continue
				}
			default:
				// log error but proceed
				log.Errorf("initializeInventory: invalid "+
					"metadata stream ID %v token %v",
					m.ID, t)
			}
		}
	}

	return nil
}

// loadPropMD decodes backend proposal metadata and stores it inventory object.
func (b *backend) loadPropMD(token, payload string) error {
	f := strings.NewReader(payload)
	d := json.NewDecoder(f)
	var md BackendProposalMetadata
	if err := d.Decode(&md); err == io.EOF {
		b._inventory[token].proposalMD = md
	} else if err != nil {
		return err
	}
	return nil
}

// loadChanges decodes chnages metadata and stores it inventory object.
func (b *backend) loadChanges(token, payload string) error {
	f := strings.NewReader(payload)
	d := json.NewDecoder(f)
	for {
		var md MDStreamChanges
		if err := d.Decode(&md); err == io.EOF {
			return nil
		} else if err != nil {
			return err
		}
		p := b._inventory[token]
		p.changes = append(p.changes, md)
	}
	return nil
}

// loadVoting decodes voting metadata and stores it inventory object.
func (b *backend) loadVoting(token, payload string) error {
	f := strings.NewReader(payload)
	d := json.NewDecoder(f)
	for {
		var md MDStreamVoting
		if err := d.Decode(&md); err == io.EOF {
			return nil
		} else if err != nil {
			return err
		}
		p := b._inventory[token]
		p.voting = append(p.voting, md)
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
	return *r, nil
}

// getInventoryRecord returns an inventory record from the inventory cache.
//
// This function must be called WITHOUT the mutex held.
func (b *backend) getInventoryRecord(token string) (inventoryRecord, error) {
	b.RLock()
	defer b.RUnlock()
	return b._getInventoryRecord(token)
}
