// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tstore

import (
	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
)

var (
	_ plugins.TstoreClient = (*tstoreClient)(nil)
)

// tstoreClient satisfies the plugin TstoreClient interface.
type tstoreClient struct {
	pluginID string
	tstore   *Tstore
}

// Record is a wrapper of the tstore Record func.
func (t *tstoreClient) Record(token []byte, version uint32) (*backend.Record, error) {
	return t.tstore.Record(token, version)
}

// RecordLatest is a wrapper of the tstore RecordLatest func.
func (t *tstoreClient) RecordLatest(token []byte) (*backend.Record, error) {
	return t.tstore.RecordLatest(token)
}

// RecordPartial is a wrapper of the tstore RecordPartial func.
func (t *tstoreClient) RecordPartial(token []byte, version uint32, filenames []string, omitAllFiles bool) (*backend.Record, error) {
	return t.tstore.RecordPartial(token, version, filenames, omitAllFiles)
}

// RecordState is a wraper of the tstore RecordState func.
func (t *tstoreClient) RecordState(token []byte) (backend.StateT, error) {
	return t.tstore.RecordState(token)
}
