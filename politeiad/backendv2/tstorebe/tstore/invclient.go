// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tstore

import (
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/inv"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
	"github.com/pkg/errors"
)

// InvClient provides a concurrency safe API that plugins can use to manage an
// inventory of tokens.
//
// Operations will be atomic if the InvClient is initialized by a plugin write
// command. Operations WILL NOT be atomic if the InvClient is initialized by a
// plugin read command.
//
// Bit flags are used to encode relevant data into inventory entries. An extra
// data field is also provided for the caller to use freely. The inventory can
// be queried by bit flags, by entry timestamp, or by providing a callback
// function that is invoked on each entry.
type InvClient struct {
	id  string // Caller ID used for logging
	inv *inv.Inv

	// writer is used for all write operations. Write operations are
	// atomic.
	//
	// This will be nil when the InvClient is initialized by a plugin
	// read command.
	writer store.Tx

	// reader is used for all read operations.
	//
	// reader will be a store Tx when the InvClient is initialized by
	// a plugin write command. Operations will be atomic.
	//
	// reader will be the store BlobKV when the InvClient is
	// initialized by a plugin read commad. Operations will not be
	// atomic.
	reader store.Getter
}

// newInvClient returns a new InvClient.
func newInvClient(id, key string, encrypt bool, tx store.Tx, r store.Getter) *InvClient {
	return &InvClient{
		id:     id,
		inv:    inv.New(key, encrypt),
		writer: tx,
		reader: r,
	}
}

// Add adds a new entry to the inventory.
func (c *InvClient) Add(e inv.Entry) error {
	log.Tracef("%v InvClient Add: %v", c.id, e.Token)

	// Verify that this call is part of a write command.
	if c.writer == nil {
		return errors.Errorf("attempting to execute a write " +
			"when the client has been initialized for a read")
	}

	return c.inv.Add(c.writer, e)
}

// Update updates an inventory entry.
func (c *InvClient) Update(e inv.Entry) error {
	log.Tracef("%v InvClient Update: %v", c.id, e.Token)

	// Verify that this call is part of a write command.
	if c.writer == nil {
		return errors.Errorf("attempting to execute a write " +
			"when the client has been initialized for a read")
	}

	return c.inv.Update(c.writer, e)
}

// Del deletes an entry from the inventory.
func (c *InvClient) Del(token string) error {
	log.Tracef("%v InvClient Del: %v", c.id, token)

	// Verify that this call is part of a write command.
	if c.writer == nil {
		return errors.Errorf("attempting to execute a write " +
			"when the client has been initialized for a read")
	}

	return c.inv.Del(c.writer, token)
}

// Get returns a page of tokens that match the provided filtering criteria.
func (c *InvClient) Get(bits uint64, pageSize, pageNum uint32) ([]string, error) {
	log.Tracef("%v InvClient Get: %v %v %v", bits, pageSize, pageNum)

	return c.inv.Get(c.reader, bits, pageSize, pageNum)
}

// GetMulti returns a page of tokens for each of the provided bits.  The bits
// are used as filtering criteria.
//
// The returned map is a map[bits][]token.
func (c *InvClient) GetMulti(bits []uint64, pageSize, pageNum uint32) (map[uint64][]string, error) {
	log.Tracef("%v InvClient GetMulti: %v %v %v", bits, pageSize, pageNum)

	return c.inv.GetMulti(c.reader, bits, pageSize, pageNum)
}

// GetOrdered orders the entries from newest to oldest and returns the
// specified page.
func (c *InvClient) GetOrdered(pageSize, pageNum uint32) ([]string, error) {
	log.Tracef("%v InvClient GetOrdered: %v %v", pageSize, pageNum)

	return c.inv.GetOrdered(c.reader, pageSize, pageNum)
}

// GetAll returns all tokens in the inventory.
func (c *InvClient) GetAll() ([]string, error) {
	log.Tracef("%v InvClient GetAll")

	return c.inv.GetAll(c.reader)
}

// Iter iterates through the inventory and invokes the provided callback on
// each inventory entry.
func (c *InvClient) Iter(callback func(e inv.Entry) error) error {
	log.Tracef("%v InvClient Iter")

	return c.inv.Iter(c.reader, callback)
}
