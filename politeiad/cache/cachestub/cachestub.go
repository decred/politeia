// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cachestub

import "github.com/thi4go/politeia/politeiad/cache"

// cachestub implements the cache interface.
type cachestub struct{}

// NewRecord is a stub to satisfy the cache interface.
func (c *cachestub) NewRecord(r cache.Record) error {
	return nil
}

// Record is a stub to satisfy the cache interface.
func (c *cachestub) Record(token string) (*cache.Record, error) {
	return &cache.Record{}, nil
}

// Records is a stub to satisfy the cache interface.
func (c *cachestub) Records(token []string, fetchFiles bool) (map[string]cache.Record, error) {
	records := make(map[string]cache.Record)
	return records, nil
}

// RecordVersion is a stub to satisfy the cache interface.
func (c *cachestub) RecordVersion(token, version string) (*cache.Record, error) {
	return &cache.Record{}, nil
}

// UpdateRecord is a stub to satisfy the cache interface.
func (c *cachestub) UpdateRecord(r cache.Record) error {
	return nil
}

// UpdateRecordStatus is a stub to satisfy the cache interface.
func (c *cachestub) UpdateRecordStatus(token, version string, status cache.RecordStatusT, timestamp int64, metadata []cache.MetadataStream) error {
	return nil
}

func (c *cachestub) UpdateRecordMetadata(token string, ms []cache.MetadataStream) error {
	return nil
}

// Inventory is a stub to satisfy the cache interface.
func (c *cachestub) Inventory() ([]cache.Record, error) {
	return make([]cache.Record, 0), nil
}

// InventoryStats is a stub to satisfy the cache interface.
func (c *cachestub) InventoryStats() (*cache.InventoryStats, error) {
	return &cache.InventoryStats{}, nil
}

// Setup is a stub to satisfy the cache interface.
func (c *cachestub) Setup() error {
	return nil
}

// Build is a stub to satisfy the cache interface.
func (c *cachestub) Build(records []cache.Record) error {
	return nil
}

func (c *cachestub) RegisterPlugin(p cache.Plugin) error {
	return nil
}

// PluginSetup is a stub to satisfy the cache interface.
func (c *cachestub) PluginSetup(id string) error {
	return nil
}

// PluginBuild is a stub to satisfy the cache interface.
func (c *cachestub) PluginBuild(id, payload string) error {
	return nil
}

// PluginExec is a stub to satisfy the cache interface.
func (c *cachestub) PluginExec(pc cache.PluginCommand) (*cache.PluginCommandReply, error) {
	return &cache.PluginCommandReply{}, nil
}

// Close is a stub to satisfy the cache interface.
func (c *cachestub) Close() {}

// NewStub returns a new cachestub context.
func New() *cachestub {
	return &cachestub{}
}
