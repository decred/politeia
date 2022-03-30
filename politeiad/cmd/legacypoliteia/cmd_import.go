// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/decred/dcrd/dcrutil/v3"
	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/tstore"
	"github.com/decred/politeia/politeiad/plugins/pi"
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
	// CLI flags for the import command. We print a custom usage message,
	// see usage.go, so the individual flag usage messages are left blank.
	importFlags = flag.NewFlagSet(importCmdName, flag.ExitOnError)
	testnet     = importFlags.Bool("testnet", false, "")
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
	// Parse the CLI flags
	err := importFlags.Parse(args)
	if err != nil {
		return err
	}

	// Verify the legacy directory exists
	if len(args) == 0 {
		return fmt.Errorf("legacy dir argument not provided")
	}
	legacyDir := util.CleanAndExpandPath(args[len(args)-1])
	if _, err := os.Stat(legacyDir); err != nil {
		return fmt.Errorf("legacy directory not found: %v", legacyDir)
	}

	// Testnet or mainnet
	params := config.MainNetParams.Params
	if *testnet {
		params = config.TestNet3Params.Params
	}

	fmt.Printf("\n")
	fmt.Printf("Network  : %v\n", params.Name)
	fmt.Printf("Tlog host: %v\n", *tlogHost)
	fmt.Printf("DB host  : %v\n", *dbHost)
	fmt.Printf("\n")

	// Setup tstore connection
	ts, err := tstore.New(politeiadHomeDir, politeiadDataDir,
		params, *tlogHost, dbType, *dbHost, *dbPass, "", "")
	if err != nil {
		return err
	}

	// Setup the import cmd
	c := &importCmd{
		legacyDir: legacyDir,
		tstore:    ts,
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
}

// importProposals walks the legacy directory and imports the legacy proposals
// into tstore. It accomplishes this using the following steps:
//
// 1. Inventory all legacy proposals being imported.
//
// 2. Retrieve the tstore token inventory.
//
// 3. Iterate through each record in the existing tstore inventory and check
//    if the record corresponds to one of the legacy proposals.
//
// 4. Perform an fsck on all legacy proposals that have been found to already
//    exist in tstore to verify that the full legacy proposal has been
//    imported. Any missing legacy proposal content is added to tstore. A
//    partial import can happen if the import command was previously being run
//    and was stopped prior completion or if the command encountered an
//    unexpected error.
//
// 5. Add all remaining legacy RFP proposals to tstore. This must be done first
//    so that the RFP submissions can link to the tstore RFP proposal token.
//
// 6. Add all remaining proposals to tstore.
func (c *importCmd) importLegacyProposals() error {
	// 1. Inventory all legacy proposals being imported
	legacyInv, err := parseLegacyTokens(c.legacyDir)
	if err != nil {
		return err
	}
	legacyInvM := make(map[string]struct{}, len(legacyInv))
	for _, token := range legacyInv {
		legacyInvM[token] = struct{}{}
	}

	fmt.Printf("%v legacy proposals found\n", len(legacyInv))

	// 2. Retrieve the tstore token inventory
	inv, err := c.tstore.Inventory()
	if err != nil {
		return err
	}

	fmt.Printf("%v existing proposals found in tstore\n", len(inv))

	// imported contains the legacy tokens of all legacy proposals
	// that have already been imported into tstore. This list does
	// not differentiate between partially imported or fully
	// imported proposals. The fsck function checks for and handles
	// partially imported proposals.
	imported := make(map[string]struct{}, len(legacyInv))

	// 3. Iterate through each record in the existing tstore
	// inventory and check if the record corresponds to one
	// of the legacy proposals.
	for _, tokenB := range inv {
		// Get the record metadata from tstore
		filenames := []string{pi.FileNameProposalMetadata}
		r, err := c.tstore.RecordPartial(tokenB, 0, filenames, false)
		if err != nil {
			return err
		}
		switch r.RecordMetadata.Status {
		case backend.StatusPublic, backend.StatusArchived:
			// These statuses are expected
		default:
			// This is not a record that we're interested in.
			// The legacy proposals are all going to be either
			// public or archived.
			continue
		}

		// Check if this is a legacy proposal
		pm, err := decodeProposalMetadata(r.Files)
		if err != nil {
			return err
		}
		if pm.LegacyToken == "" {
			// This is not a legacy proposal
			continue
		}

		// This is a legacy proposal. Add it to the imported list.
		imported[pm.LegacyToken] = struct{}{}
	}

	fmt.Printf("%v legacy proposals were found in tstore\n", len(imported))

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

// parseLegacyTokens parses and returns all the unique tokens that are found in
// the file path of the provided directory or any contents of the directory.
// The tokens are returned in alphabetical order.
func parseLegacyTokens(dir string) ([]string, error) {
	tokens := make(map[string]struct{}, 1024)
	err := filepath.WalkDir(dir,
		func(path string, d fs.DirEntry, err error) error {
			token, ok := parseProposalToken(path)
			if !ok {
				return nil
			}
			tokens[token] = struct{}{}
			return nil
		})
	if err != nil {
		return nil, err
	}

	// Convert map to a slice and sort alphabetically
	legacyTokens := make([]string, 0, len(tokens))
	for token := range tokens {
		legacyTokens = append(legacyTokens, token)
	}
	sort.SliceStable(legacyTokens, func(i, j int) bool {
		return legacyTokens[i] < legacyTokens[j]
	})

	return legacyTokens, nil
}

// decodeLegacyTokenFromFiles decodes and returns the ProposalMetadata from the
// provided files.
func decodeProposalMetadata(files []backend.File) (*pi.ProposalMetadata, error) {
	var f *backend.File
	for _, v := range files {
		if v.Name == pi.FileNameProposalMetadata {
			f = &v
			break
		}
	}
	if f == nil {
		// This should not happen
		return nil, fmt.Errorf("proposal metadata not found")
	}
	b, err := base64.StdEncoding.DecodeString(f.Payload)
	if err != nil {
		return nil, err
	}
	var pm pi.ProposalMetadata
	err = json.Unmarshal(b, &pm)
	if err != nil {
		return nil, err
	}
	return &pm, nil
}
