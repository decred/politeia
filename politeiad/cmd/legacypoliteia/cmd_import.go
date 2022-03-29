// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/decred/dcrd/dcrutil/v3"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/tstore"
	"github.com/decred/politeia/politeiawww/config"
	"github.com/decred/politeia/util"
)

/*
TODO

Check if signature is broken
- usermd UserMetadata signature

Signatures that are broken:
- usermd StatusChangeMetadata signature (wrong message)
- ticketvote AuthDetails receipt (wrong server pubkey)
- ticketvote VoteDetails signature (wrong message)
- ticketvote VoteDetails receipt (wrong message, wrong server pubkey)

Fields that need to be updated:
- ProposalMetadata
  - Version and iteration may need to be hardcoded to 1
*/

const (
	// Default command settings
	defaultTlogHost = "localhost:8090"
	defaultTlogPass = "tlogpass"
	defaultDBType   = "mysql"
	defaultDBHost   = "localhost:3306"
	defaultDBPass   = "politeiadpass"
)

var (
	// Import command CLI flags
	importFlags = flag.NewFlagSet(importCmdName, flag.ContinueOnError)
	tlogHost    = importFlags.String("tloghost", defaultTlogHost, "")
	dbHost      = importFlags.String("dbhost", defaultDBHost, "")
	dbPass      = importFlags.String("dbpass", defaultDBPass, "")

	// tstore settings
	politeiadHomeDir = dcrutil.AppDataDir("politeiad", false)
	politeiadDataDir = filepath.Join(politeiadHomeDir, "data")
	dbType           = tstore.DBTypeMySQL
	dcrtimeHost      = "" // Not needed for import
	dcrtimeCert      = "" // Not needed for import
)

// execImportCmd executes the import command.
func execImportCmd(args []string) error {
	// Verify the legacy directory exists
	if len(args) == 0 {
		return fmt.Errorf("legacy dir argument not provided")
	}
	legacyDir := util.CleanAndExpandPath(args[0])
	if _, err := os.Stat(legacyDir); err != nil {
		return fmt.Errorf("legacy directory not found: %v", legacyDir)
	}

	// Parse the CLI flags
	err := importFlags.Parse(args)
	if err != nil {
		return err
	}

	// Setup tstore connection
	ts, err := tstore.New(politeiadHomeDir, politeiadDataDir,
		config.MainNetParams.Params, *tlogHost,
		dbType, *dbHost, *dbPass, "", "")
	if err != nil {
		return err
	}

	// Setup the import cmd context
	c := &importCmd{
		legacyDir: legacyDir,
		tstore:    ts,
		rfpTokens: make(map[string]string, 64),
	}

	// Import the legacy proposals
	return c.importLegacyProposals()
}

// importCmd implements the legacypoliteia import command. The execution speed
// is limited by the trillian log signer interval (currently 200ms). Data is
// submitted concurrently in order to work around this bottleneck.
type importCmd struct {
	sync.Mutex
	legacyDir string
	tstore    *tstore.Tstore
	rfpTokens map[string]string // [gitToken][tstoreToken]
}

// importProposals walks the import directory and imports the legacy proposals
// into tstore. It accomplishes this using the following steps:
//
// 1. Inventory all of the legacy proposals being imported.
//
// 2. Retrieve the tstore token inventory.
//
// 3. Iterate through each record in the existing tstore inventory and check
//    if the record corresponds to one of the legacy proposals.
//
// 4. An fsck is performed on all proposals that have been found to already
//    exist in tstore to verify that the full legacy proposal has been
//    imported.  Any missing legacy proposal content is added to tstore. This
//    can happen if the import command was previously being run and was stopped
//    prior to fully importing the proposal or if the command encountered an
//    unexpected error.
//
// 5. Add all remaining legacy RFP proposals to tstore. This must be done first
//    so that the RFP submissions can link to the tstore RFP proposal token.
//
// 6. Add all remaining proposals to tstore.
func (c *importCmd) importLegacyProposals() error {

	return nil
}

// importProposal imports the specified legacy proposal into tstore.
//
// This function assumes that the proposal does not yet exist in tstore.
// Handling proposals that have been partially added is done by the
// fsckPropsal() function.
//
// This function replaces the git backend token with the tstore backend token
// in the following structures:
// - Fill
// - In
// - This
// - List
//
// The git token to tstore token mapping is added to the memory cache for all
// RFP parent proposals.
//
// The parent token of all RFP submissions are updated with the tstore RFP
// parent token.
func importProposal(legacyDir, gitToken string, cmd *importCmd) {}

func fsckProposal() {}

func updateProposalWithTstoreToken(p *proposal, tstoreToken string) {}

func updateRFPSubmissionWithRFPTstoreToken(submission *proposal, tstoreRFPToken string) {}

// setRFPToken sets a RPF token mapping in the memory cache.
func (c *importCmd) setRFPToken(gitToken, tstoreToken string) {
	c.Lock()
	defer c.Unlock()

	c.rfpTokens[gitToken] = tstoreToken
}

// getRFPToken gets a RFP tstore token from the memory cache.
func (c *importCmd) getRFPToken(gitToken string) (string, bool) {
	c.Lock()
	defer c.Unlock()

	tstoreToken, ok := c.rfpTokens[gitToken]
	return tstoreToken, ok
}
