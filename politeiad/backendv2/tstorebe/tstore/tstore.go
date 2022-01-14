// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tstore

import (
	"encoding/binary"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"

	"github.com/decred/dcrd/chaincfg/v3"
	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store/localdb"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store/mysql"
	"github.com/decred/politeia/util"
	"github.com/pkg/errors"
	"github.com/robfig/cron"
)

const (
	// DBTypeLevelDB is a config option that sets the backing key-value
	// store to a leveldb instance.
	DBTypeLevelDB = "leveldb"

	// DBTypeMySQL is a config option that sets the backing key-value
	// store to a MySQL instance.
	DBTypeMySQL = "mysql"

	// LevelDB settings
	storeDirname = "store"

	// MySQL settings
	dbUser = "politeiad"
)

var (
	_ plugins.TstoreClient = (*tstoreClient)(nil)
)

// tstoreClient satisfies the plugin TstoreClient interface.
type tstoreClient struct {
	pluginID string
	tstore   *Tstore
}

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
	sync.RWMutex
	dataDir         string
	activeNetParams *chaincfg.Params
	tlog            tlogClient
	store           store.BlobKV
	dcrtime         *dcrtimeClient
	cron            *cron.Cron
	plugins         map[string]plugin // [pluginID]plugin

	// droppingAnchor indicates whether tstore is in the process of
	// dropping an anchor, i.e. timestamping unanchored tlog trees
	// using dcrtime. An anchor is dropped periodically using cron.
	droppingAnchor bool

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

// FullLengthToken returns the full length token given the short token. A
// ErrRecordNotFound error is returned if a record does not exist for the
// provided token.
func (t *Tstore) FullLengthToken(token []byte) ([]byte, error) {
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

// Fsck performs a filesystem check on the tstore.
func (t *Tstore) Fsck(allTokens [][]byte) error {
	// Set tree status to frozen for any trees that are frozen and have
	// been anchored one last time.
	// Verify all file blobs have been deleted for censored records.

	// Run plugin fscks's
	for _, pluginID := range t.pluginIDs() {
		p, _ := t.plugin(pluginID)

		log.Infof("Performing fsck for the %v plugin", pluginID)

		err := p.client.Fsck(allTokens)
		if err != nil {
			return errors.Errorf("plugin %v fsck: %v",
				pluginID, err)
		}
	}

	return nil
}

// Close performs cleanup of the tstore.
func (t *Tstore) Close() {
	log.Tracef("Close")

	// Close connections
	t.tlog.Close()
	t.store.Close()
}

// Setup performs any required work to setup the tstore instance.
func (t *Tstore) Setup() error {
	log.Infof("Building backend token prefix cache")

	tokens, err := t.Inventory()
	if err != nil {
		return fmt.Errorf("Inventory: %v", err)
	}

	log.Infof("%v records in the tstore", len(tokens))

	for _, v := range tokens {
		t.tokenAdd(v)
	}

	return nil
}

// New returns a new tstore instance.
func New(appDir, dataDir string, anp *chaincfg.Params, tlogHost, tlogPass, dbType, dbHost, dbPass, dcrtimeHost, dcrtimeCert string) (*Tstore, error) {
	// Setup datadir for this tstore instance
	dataDir = filepath.Join(dataDir)
	err := os.MkdirAll(dataDir, 0700)
	if err != nil {
		return nil, err
	}

	// Setup key-value store
	log.Infof("Database type: %v", dbType)
	var kvstore store.BlobKV
	switch dbType {
	case DBTypeLevelDB:
		fp := filepath.Join(dataDir, storeDirname)
		err = os.MkdirAll(fp, 0700)
		if err != nil {
			return nil, err
		}
		kvstore, err = localdb.New(appDir, fp)
		if err != nil {
			return nil, err
		}
	case DBTypeMySQL:
		// Example db name: testnet3_unvetted_kv
		dbName := fmt.Sprintf("%v_kv", anp.Name)
		kvstore, err = mysql.New(dbHost, dbUser, dbPass, dbName)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("invalid db type: %v", dbType)
	}

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

	// Setup tstore
	t := Tstore{
		dataDir:         dataDir,
		activeNetParams: anp,
		tlog:            tlogClient,
		store:           kvstore,
		dcrtime:         dcrtimeClient,
		cron:            cron.New(),
		plugins:         make(map[string]plugin),
		tokens:          make(map[string][]byte),
	}

	// Launch cron
	log.Infof("Launch cron anchor job")
	err = t.cron.AddFunc(anchorSchedule, func() {
		err := t.anchorTrees()
		if err != nil {
			log.Errorf("anchorTrees: %v", err)
		}
	})
	if err != nil {
		return nil, err
	}
	t.cron.Start()

	return &t, nil
}
