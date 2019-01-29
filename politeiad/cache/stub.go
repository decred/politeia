// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cache

// cachestub implements the cache interface.
type cachestub struct{}

// NewRecord is a stub to satisfy the cache interface.
func (c *cachestub) NewRecord(r Record) error {
	return nil
}

// Record is a stub to satisfy the cache interface.
func (c *cachestub) Record(token string) (*Record, error) {
	return &Record{}, nil
}

// RecordVersion is a stub to satisfy the cache interface.
func (c *cachestub) RecordVersion(token, version string) (*Record, error) {
	return &Record{}, nil
}

// UpdateRecord is a stub to satisfy the cache interface.
func (c *cachestub) UpdateRecord(r Record) error {
	return nil
}

// UpdateRecordStatus is a stub to satisfy the cache interface.
func (c *cachestub) UpdateRecordStatus(token, version string, status RecordStatusT, timestamp int64, metadata []MetadataStream) error {
	return nil
}

// Inventory is a stub to satisfy the cache interface.
func (c *cachestub) Inventory() ([]Record, error) {
	return make([]Record, 0), nil
}

// InventoryStats is a stub to satisfy the cache interface.
func (c *cachestub) InventoryStats() (*InventoryStats, error) {
	return &InventoryStats{}, nil
}

func (c *cachestub) RegisterPlugin(p Plugin) error {
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
func (c *cachestub) PluginExec(pc PluginCommand) (*PluginCommandReply, error) {
	return &PluginCommandReply{}, nil
}

// Build is a stub to satisfy the cache interface.
func (c *cachestub) Build(records []Record) error {
	return nil
}

// Close is a stub to satisfy the cache interface.
func (c *cachestub) Close() {}

// NewStub returns a new cachestub context.
func NewStub() *cachestub {
	return &cachestub{}
}
