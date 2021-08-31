// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tstore

import (
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/inv"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
	"github.com/pkg/errors"
)

// invClient provides a concurrency safe API that plugins can use to manage a
// cached inventory of tokens.
//
// Operations will be atomic if the client is initialized by a plugin write
// command. Operations WILL NOT be atomic if the client is initialized by a
// plugin read command.
//
// Data save to the inventory WILL NOT be timestamped onto the Decred
// blockchain.
//
// Bit flags are used to encode relevant data into inventory entries. An extra
// data field is also provided for the caller to use freely. The inventory can
// be queried by bit flags, by entry timestamp, or by providing a callback
// function that is invoked on each entry.
//
// invClient satisfies the plugins InvClient interface.
type invClient struct {
	id  string // Caller ID used for logging
	inv *inv.Inv

	// writer is used for all write operations. Write operations are
	// atomic.
	//
	// This will be nil when the client is initialized by a plugin
	// read command.
	writer store.Tx

	// reader is used for all read operations.
	//
	// reader will be a store Tx when the client is initialized by
	// a plugin write command. Operations will be atomic.
	//
	// reader will be a store BlobKV when the client is initialized
	// by a plugin read command. Operations WILL NOT be atomic.
	reader store.Getter
}

// newInvClient returns a new invClient.
func newInvClient(id, key string, encrypt bool, tx store.Tx, r store.Getter) *invClient {
	return &invClient{
		id:     id,
		inv:    inv.New(key, encrypt),
		writer: tx,
		reader: r,
	}
}

// Add adds a new entry to the inventory.
//
// This function satisfies the plugins InvClient interface.
func (c *invClient) Add(e inv.Entry) error {
	log.Tracef("%v Inv Add: %v", c.id, e.Token)

	// Verify that this call is part of a write command.
	if c.writer == nil {
		return errors.Errorf("attempting to execute a write " +
			"when the client has been initialized for a read")
	}

	return c.inv.Add(c.writer, e)
}

// Update updates an inventory entry.
//
// This function satisfies the plugins InvClient interface.
func (c *invClient) Update(e inv.Entry) error {
	log.Tracef("%v Inv Update: %v", c.id, e.Token)

	// Verify that this call is part of a write command.
	if c.writer == nil {
		return errors.Errorf("attempting to execute a write " +
			"when the client has been initialized for a read")
	}

	return c.inv.Update(c.writer, e)
}

// Del deletes an entry from the inventory.
//
// This function satisfies the plugins InvClient interface.
func (c *invClient) Del(token string) error {
	log.Tracef("%v Inv Del: %v", c.id, token)

	// Verify that this call is part of a write command.
	if c.writer == nil {
		return errors.Errorf("attempting to execute a write " +
			"when the client has been initialized for a read")
	}

	return c.inv.Del(c.writer, token)
}

// Get returns a page of tokens that match the provided filtering criteria.
//
// This function satisfies the plugins InvClient interface.
func (c *invClient) Get(bits uint64, pageSize, pageNum uint32) ([]string, error) {
	log.Tracef("%v Inv Get: %v %v %v", bits, pageSize, pageNum)

	return c.inv.Get(c.reader, bits, pageSize, pageNum)
}

// GetMulti returns a page of tokens for each of the provided bits.  The bits
// are used as filtering criteria.
//
// The returned map is a map[bits][]token.
//
// This function satisfies the plugins InvClient interface.
func (c *invClient) GetMulti(bits []uint64, pageSize, pageNum uint32) (map[uint64][]string, error) {
	log.Tracef("%v Inv GetMulti: %v %v %v", bits, pageSize, pageNum)

	return c.inv.GetMulti(c.reader, bits, pageSize, pageNum)
}

// GetOrdered orders the entries from newest to oldest and returns the
// specified page.
//
// This function satisfies the plugins InvClient interface.
func (c *invClient) GetOrdered(pageSize, pageNum uint32) ([]string, error) {
	log.Tracef("%v Inv GetOrdered: %v %v", pageSize, pageNum)

	return c.inv.GetOrdered(c.reader, pageSize, pageNum)
}

// GetAll returns all tokens in the inventory.
//
// This function satisfies the plugins InvClient interface.
func (c *invClient) GetAll() ([]string, error) {
	log.Tracef("%v Inv GetAll")

	return c.inv.GetAll(c.reader)
}

// Iter iterates through the inventory and invokes the provided callback on
// each inventory entry.
//
// This function satisfies the plugins InvClient interface.
func (c *invClient) Iter(callback func(e inv.Entry) error) error {
	log.Tracef("%v Inv Iter")

	return c.inv.Iter(c.reader, callback)
}
