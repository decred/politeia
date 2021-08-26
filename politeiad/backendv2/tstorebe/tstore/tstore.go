// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tstore

import (
	"fmt"
	"net/url"

	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
	"github.com/robfig/cron"
)

// Tstore is a data store that automatically timestamps all data saved to it
// onto the decred blockchain, making it possible to cryptographically prove
// that a piece of data existed at a specific block height. It combines a
// trillian log (tlog) and a key-value store. When data is saved to a tstore
// instance it is first saved to the key-value store then a digest of the data
// is appended onto the tlog tree. Tlog trees are episodically timestamped onto
// the decred blockchain. An inlcusion proof, i.e. the cryptographic proof that
// the data was included in the decred timestamp, can be retrieved for any
// individual piece of data saved to the tstore.
//
// Saving only the digest of the data to tlog means that we separate the
// timestamp from the data itself. This allows us to remove content that is
// deemed undesirable from the key-value store without impacting the ability to
// retrieve inclusion proofs for any other pieces of data saved to tstore.
//
// The tlog tree is append only and is treated as the source of truth. If any
// blobs make it into the key-value store but do not make it into the tlog tree
// they are considered to be orphaned and are simply ignored. We do not unwind
// failed calls.
type Tstore struct {
	net     chaincfg.Params
	tlog    tlogClient
	store   store.BlobKV
	dcrtime *dcrtimeClient
	cron    *cron.Cron
	plugins map[string]plugin // [pluginID]plugin
}

// Setup performs all required work to setup the tstore instance.
func (t *Tstore) Setup() error {
	log.Tracef("Setup")

	err := t.startAnchorProcess()
	if err != nil {
		return err
	}

	// TODO have option to build short tokens cache. If a tree does
	// not have any leaves then it does not need a short token cache
	// entry.

	return nil
}

// Tx returns a key-value store transaction. This method does not lock a record
// and should not be used for record updates. See the RecordTx() method for
// more details.
func (t *Tstore) Tx() (store.Tx, func(), error) {
	log.Tracef("Tx")

	return t.store.Tx()
}

// TODO implement all fsck's
// Fsck performs a filesystem check on the tstore.
func (t *Tstore) Fsck() {
	log.Tracef("Fsck")

	// Verify that a short token cache entry exists for all trees that
	// have leaves. If a tree is empty then it doesn't need a short token
	// cache entry.

	// Set tree status to frozen for any trees that are frozen and have
	// been anchored one last time.
	// Verify all file blobs have been deleted for censored records.
}

// Close performs cleanup of the tstore.
func (t *Tstore) Close() {
	log.Tracef("Close")

	// Stop all cron jobs
	t.cron.Stop()

	// Close connections
	t.tlog.Close()
	t.store.Close()
}

// New returns a new tstore instance.
func New(net chaincfg.Params, kvstore store.BlobKV, tlogHost, tlogPass, dcrtimeHost, dcrtimeCert string) (*Tstore, error) {
	// Setup trillian client
	log.Infof("Tlog host: %v", tlogHost)
	tlogKey, err := deriveTlogKey(kvstore, tlogPass)
	if err != nil {
		return nil, err
	}
	tlogClient, err := newTClient(tlogHost, tlogKey)
	if err != nil {
		return nil, err
	}

	// Verify dcrtime host
	_, err = url.Parse(dcrtimeHost)
	if err != nil {
		return nil, fmt.Errorf("parse dcrtime host '%v': %v", dcrtimeHost, err)
	}
	log.Infof("Anchor host: %v", dcrtimeHost)

	// Setup dcrtime client
	dcrtimeClient, err := newDcrtimeClient(dcrtimeHost, dcrtimeCert)
	if err != nil {
		return nil, err
	}

	// Start cron
	c := cron.New()
	c.Start()

	return &Tstore{
		net:     net,
		tlog:    tlogClient,
		store:   kvstore,
		dcrtime: dcrtimeClient,
		cron:    c,
		plugins: make(map[string]plugin),
	}, nil
}
