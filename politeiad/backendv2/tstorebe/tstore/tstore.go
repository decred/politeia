// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tstore

import (
	"encoding/binary"
	"fmt"
	"net/url"
	"sync"

	"github.com/decred/dcrd/chaincfg/v3"
	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
	"github.com/decred/politeia/util"
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
	// TODO get rid of mutex
	sync.RWMutex
	net     chaincfg.Params
	tlog    tlogClient
	store   store.BlobKV
	dcrtime *dcrtimeClient
	cron    *cron.Cron
	plugins map[string]plugin // [pluginID]plugin

	// TODO remove
	// tokens contains the short token to full token mappings. The
	// short token is the first n characters of the hex encoded record
	// token, where n is defined by the short token length politeiad
	// setting. Record lookups using short tokens are allowed. This
	// cache is used to prevent collisions when creating new tokens
	// and to facilitate lookups using only the short token. This cache
	// is built on startup.
	tokens map[string][]byte // [shortToken]fullToken
}

// tokenFromTreeID returns the record token for a tlog tree.
func tokenFromTreeID(treeID int64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(treeID))
	return b
}

// treeIDFromToken returns the tlog tree ID for the given record token.
func treeIDFromToken(token []byte) int64 {
	return int64(binary.LittleEndian.Uint64(token))
}

// tokenIsFullLength returns whether the token is a full length token.
func tokenIsFullLength(token []byte) bool {
	return util.TokenIsFullLength(util.TokenTypeTstore, token)
}

// tokenCollision returns whether the short version of the provided token
// already exists. This can be used to prevent collisions when creating new
// tokens.
func (t *Tstore) tokenCollision(fullToken []byte) bool {
	shortToken, err := util.ShortTokenEncode(fullToken)
	if err != nil {
		return false
	}

	t.RLock()
	defer t.RUnlock()

	_, ok := t.tokens[shortToken]
	return ok
}

// tokenAdd adds a entry to the tokens cache.
func (t *Tstore) tokenAdd(fullToken []byte) error {
	if !tokenIsFullLength(fullToken) {
		return fmt.Errorf("token is not full length")
	}

	shortToken, err := util.ShortTokenEncode(fullToken)
	if err != nil {
		return err
	}

	t.Lock()
	t.tokens[shortToken] = fullToken
	t.Unlock()

	log.Tracef("Token cache add: %v", shortToken)

	return nil
}

// fullLengthToken returns the full length token given the short token. A
// ErrRecordNotFound error is returned if a record does not exist for the
// provided token.
func (t *Tstore) fullLengthToken(token []byte) ([]byte, error) {
	if tokenIsFullLength(token) {
		// Token is already full length. Nothing else to do.
		return token, nil
	}

	shortToken, err := util.ShortTokenEncode(token)
	if err != nil {
		// Token was not large enough to be a short token. This cannot
		// be used to lookup a record.
		return nil, backend.ErrRecordNotFound
	}

	t.RLock()
	defer t.RUnlock()

	fullToken, ok := t.tokens[shortToken]
	if !ok {
		// Short token does not correspond to a record token
		return nil, backend.ErrRecordNotFound
	}

	return fullToken, nil
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

// Setup performs any required work to setup the tstore instance.
func (t *Tstore) Setup() error {
	log.Tracef("Setup")

	err := t.startAnchorProcess()
	if err != nil {
		return err
	}

	// Setup token prefix cache
	log.Infof("Building backend token prefix cache")

	tokens, err := t.Inventory()
	if err != nil {
		return err
	}

	log.Infof("%v records in the tstore", len(tokens))

	for _, v := range tokens {
		t.tokenAdd(v)
	}

	return nil
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
		tokens:  make(map[string][]byte),
	}, nil
}
