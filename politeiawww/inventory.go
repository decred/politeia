package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/decred/politeia/decredplugin"
	pd "github.com/decred/politeia/politeiad/api/v1"
	www "github.com/decred/politeia/politeiawww/api/v1"
)

type inventoryRecord struct {
	//	commentsLikes     map[string][]www.LikeComment // [id]comment likes
	voteAuthorization www.AuthorizeVoteReply // vote authorization metadata
	votebits          www.StartVote          // vote bits and options
	voting            www.StartVoteReply     // voting metadata
}

// _newInventoryRecord adds a record to the inventory.
//
// This function must be called WITH the mutex held.
func (b *backend) _newInventoryRecord(token string) error {
	_, ok := b.inventory[token]
	if ok {
		return fmt.Errorf("newInventoryRecord: duplicate token: %v", token)
	}

	b.inventory[token] = &inventoryRecord{}

	return nil
}

// newInventoryRecord adds a record to the inventory.
//
// This function must be called WITHOUT the mutex held.
func (b *backend) newInventoryRecord(token string) error {
	b.Lock()
	defer b.Unlock()
	return b._newInventoryRecord(token)
}

// loadVoteAuthorization decodes vote authorization metadata and stores it
// in the proposal's inventory record.
//
// This function must be called WITH the mutex held.
func (b *backend) loadVoteAuthorization(token, payload string) error {
	f := strings.NewReader(payload)
	d := json.NewDecoder(f)
	var avr decredplugin.AuthorizeVoteReply
	if err := d.Decode(&avr); err == io.EOF {
		return nil
	} else if err != nil {
		return err
	}
	avrWWW := convertAuthorizeVoteReplyFromDecredplugin(avr)
	b.inventory[token].voteAuthorization = avrWWW
	return nil
}

// loadVoting decodes voting metadata and stores it inventory object.
//
// This function must be called WITH the mutex held.
func (b *backend) loadVoting(token, payload string) error {
	f := strings.NewReader(payload)
	d := json.NewDecoder(f)
	var md decredplugin.StartVoteReply
	if err := d.Decode(&md); err == io.EOF {
		return nil
	} else if err != nil {
		return err
	}
	p := b.inventory[token]
	p.voting = convertStartVoteReplyFromDecredplugin(md)
	return nil
}

// loadVoteBits decodes voting metadata and stores it inventory object.
//
// This function must be called WITH the mutex held.
func (b *backend) loadVoteBits(token, payload string) error {
	f := strings.NewReader(payload)
	d := json.NewDecoder(f)
	var md decredplugin.StartVote
	if err := d.Decode(&md); err == io.EOF {
		return nil
	} else if err != nil {
		return err
	}
	log.Tracef("loadVoteBits: %v %v", token, payload)
	p := b.inventory[token]
	p.votebits = convertStartVoteFromDecredplugin(md)
	return nil
}

// loadRecordMetadata load an entire record metadata into inventory.
//
// This function must be called WITH the mutex held.
func (b *backend) loadRecordMetadata(v pd.Record) {
	t := v.CensorshipRecord.Token

	// Fish metadata out as well
	var err error
	for _, m := range v.Metadata {
		switch m.ID {
		case mdStreamGeneral:
			continue
		case mdStreamChanges:
			continue
		case decredplugin.MDStreamAuthorizeVote:
			err = b.loadVoteAuthorization(t, m.Payload)
			if err != nil {
				log.Errorf("initializeInventory "+
					"could not load vote authorization: %v", err)
				continue
			}
		case decredplugin.MDStreamVoteBits:
			err = b.loadVoteBits(t, m.Payload)
			if err != nil {
				log.Errorf("initializeInventory "+
					"could not load vote bits: %v", err)
				continue
			}
		case decredplugin.MDStreamVoteSnapshot:
			err = b.loadVoting(t, m.Payload)
			if err != nil {
				log.Errorf("initializeInventory "+
					"could not load vote snapshot: %v", err)
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

// initializeInventory initializes the inventory map and loads it with a
// InventoryReply.
//
// This function must be called WITH the mutex held.
func (b *backend) initializeInventory(inv *pd.InventoryReply) error {
	b.inventory = make(map[string]*inventoryRecord)

	for _, v := range append(inv.Vetted, inv.Branches...) {
		err := b._newInventoryRecord(v.CensorshipRecord.Token)
		if err != nil {
			return err
		}
	}

	return nil
}

// _getInventoryRecord reads an inventory record from the inventory cache.
//
// This function must be called WITH the mutex held.
func (b *backend) _getInventoryRecord(token string) (inventoryRecord, error) {
	r, ok := b.inventory[token]
	if !ok {
		return inventoryRecord{}, fmt.Errorf("inventory record not found %v", token)
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

// setRecordVoting sets the voting of a proposal
// this can be used for adding or updating a proposal voting
//
// This function must be called WITH the mutex held
func (b *backend) _setRecordVoting(token string, sv www.StartVote, svr www.StartVoteReply) error {
	// Sanity check
	ir, ok := b.inventory[token]
	if !ok {
		return fmt.Errorf("inventory record not found: %v", token)
	}

	// update record
	ir.voting = svr
	ir.votebits = sv
	b.inventory[token] = ir

	return nil
}

// setRecordVoteAuthorization sets the vote authorization metadata for the
// specified inventory record.
//
// This function must be called WITH the mutex held.
func (b *backend) _setRecordVoteAuthorization(token string, avr www.AuthorizeVoteReply) error {
	// Sanity check
	_, ok := b.inventory[token]
	if !ok {
		return fmt.Errorf("inventory record not found %v", token)
	}

	// Set vote authorization
	b.inventory[token].voteAuthorization = avr

	return nil
}

// setRecordVoteAuthorization sets the vote authorization metadata for the
// specified inventory record.
//
// This function must be called WITHOUT the mutex held.
func (b *backend) setRecordVoteAuthorization(token string, avr www.AuthorizeVoteReply) error {
	b.Lock()
	defer b.Unlock()
	return b._setRecordVoteAuthorization(token, avr)
}
