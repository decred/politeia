// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/dcrutil/v3"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/tstore"
	"github.com/decred/politeia/politeiawww/config"
	"github.com/decred/politeia/util"
)

const (
	// Default command settings
	defaultTlogHost = "localhost:8090"
	defaultDBType   = "mysql"
	defaultDBHost   = "localhost:3306"
	defaultDBPass   = "politeiadpass"
)

var (
	// CLI flags for the import command
	importFlags = flag.NewFlagSet(importCmdName, flag.ContinueOnError)
	tlogHost    = importFlags.String("tloghost", defaultTlogHost, "")
	dbHost      = importFlags.String("dbhost", defaultDBHost, "")
	dbPass      = importFlags.String("dbpass", defaultDBPass, "")
	testnet     = importFlags.Bool("testnet", false, "")

	// tstore settings
	politeiadHomeDir = dcrutil.AppDataDir("politeiad", false)
	politeiadDataDir = filepath.Join(politeiadHomeDir, "data")
	dbType           = tstore.DBTypeMySQL
	dcrtimeHost      = "" // Not needed for import
	dcrtimeCert      = "" // Not needed for import
)

// importCmd is the context that manages the shared memory caches that are
// used throughout the import command. The execution speed is limited by the
// trillian log signer interval (currently 200ms). Data is submitted
// concurrently in order to work around this bottleneck.
type importCmd struct {
	sync.Mutex
	tstoreClient *tstore.Client
	tstoreTokens map[string]string // [gitToken][tstoreToken]

	// startRunoffRecords holds the startRunoffRecord blob of each RFP parent to
	// be saved at a later stage of the parsing, when all the submissions are
	// imported in tstore and got their new tstore tokens.
	startRunoffRecords map[string]*startRunoffRecord
}

// setTstoreToken sets a tstore token mapping in the memory cache.
func (c *importCmd) setTstoreToken(gitToken, tstoreToken string) {
	c.Lock()
	defer c.Unlock()

	c.tstoreTokens[gitToken] = tstoreToken
}

// getTstoreToken gets a RFP tstore token from the memory cache.
func (c *importCmd) getTstoreToken(gitToken string) string {
	c.Lock()
	defer c.Unlock()

	tstoreToken := c.tstoreTokens[gitToken]
	return tstoreToken
}

// setStartRunoffRecord sets a startRunoffRecord blob mapping in the memory
// cache.
func (c *importCmd) setStartRunoffRecord(gitToken string, srr *startRunoffRecord) {
	c.Lock()
	defer c.Unlock()

	c.startRunoffRecords[gitToken] = srr
}

// getStartRunoffRecord gets a startRunoffRecord blob from the memory cache,
// returns nil if no entry was found.
func (c *importCmd) getStartRunoffRecord(gitToken string) *startRunoffRecord {
	c.Lock()
	defer c.Unlock()

	return c.startRunoffRecords[gitToken]
}

// execImportCmd executes the import command.
func execImportCmd(args []string) error {
	// Verify the legacy directory exists
	if len(args) == 0 {
		return fmt.Errorf("missing legacy directory argument")
	}
	legacyDir := util.CleanAndExpandPath(args[0])
	if _, err := os.Stat(legacyDir); err != nil {
		return fmt.Errorf("legacy directory not found: %v", legacyDir)
	}

	// Parse the CLI flags
	err := importFlags.Parse(args[1:])
	if err != nil {
		return err
	}

	// Network params
	var p *chaincfg.Params
	switch {
	case *testnet:
		p = config.TestNet3Params.Params
	default:
		p = config.MainNetParams.Params
	}

	// Setup tstore connection
	ts, err := tstore.New(politeiadHomeDir, politeiadDataDir, p, *tlogHost,
		dbType, *dbHost, *dbPass, dcrtimeHost, dcrtimeCert)
	if err != nil {
		return err
	}

	// Setup the import cmd context
	cmd := &importCmd{
		tstoreClient: &tstore.Client{
			PluginID: importCmdName,
			Tstore:   ts,
		},
		tstoreTokens:       make(map[string]string, 115),
		startRunoffRecords: make(map[string]*startRunoffRecord, 1),
	}

	// Import the legacy proposals
	return importProposals(legacyDir, cmd)
}

func fsckProposal() {}
