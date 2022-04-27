// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/decred/dcrd/dcrutil/v3"
	"github.com/decred/politeia/politeiad/api/v1/mime"
	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/tstore"
	"github.com/decred/politeia/politeiad/plugins/pi"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	"github.com/decred/politeia/politeiad/plugins/usermd"
	"github.com/decred/politeia/politeiawww/config"
	"github.com/decred/politeia/util"
)

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
	importToken = importFlags.String("token", "", "")

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
	err := importFlags.Parse(args[1:])
	if err != nil {
		return err
	}

	// Testnet or mainnet
	params := config.MainNetParams.Params
	if *testnet {
		params = config.TestNet3Params.Params
	}

	fmt.Printf("\n")
	fmt.Printf("Command parameters\n")
	fmt.Printf("Network  : %v\n", params.Name)
	fmt.Printf("Tlog host: %v\n", *tlogHost)
	fmt.Printf("DB host  : %v\n", *dbHost)
	fmt.Printf("\n")

	fmt.Printf("Connecting to tstore...\n")

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
		token:     *importToken,
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
	token     string // Optional
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
// 4. Perform an fsck on all legacy proposals that already exist in tstore to
//    verify that the full legacy proposal has been imported. Any missing
//    legacy proposal content is added to tstore during this step. A partial
//    import can happen if the import command was being run and was stopped
//    prior to completion or if it encountered an unexpected error.
//
// 5. Add the legacy RFP proposals to tstore. This must be done first so that
//    the RFP submissions can link to the tstore RFP proposal token.
//
// 6. Add the remaining legacy proposals to tstore.
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
	//
	// map[legacyToken]tstoreToken
	imported := make(map[string][]byte, len(legacyInv))

	// 3. Iterate through each record in the existing tstore
	// inventory and check if the record corresponds to one
	// of the legacy proposals.
	for _, tstoreToken := range inv {
		// Get the record metadata from tstore
		filenames := []string{pi.FileNameProposalMetadata}
		r, err := c.tstore.RecordPartial(tstoreToken, 0, filenames, false)
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
		imported[pm.LegacyToken] = tstoreToken
	}

	fmt.Printf("%v legacy proposals were found in tstore\n", len(imported))

	// 4. Perform an fsck on all legacy proposals that already exist
	//    in tstore to verify that the full legacy proposal has been
	//    imported. Any missing legacy proposal content is added to
	//    tstore during this step. A partial import can happen if
	//    the import command was being run and was stopped prior to
	//    completion or if it encountered an unexpected error.
	for legacyToken, tstoreToken := range imported {
		err := c.fsckProposal(legacyToken, tstoreToken)
		if err != nil {
			return err
		}
	}

	// 5. Add the legacy RFP proposals to tstore. This must be done
	//    first so that the RFP submissions can link to the tstore
	//    RFP proposal token.
	for _, legacyToken := range legacyInv {
		if c.token != "" && c.token != legacyToken {
			// The caller wants to import a specific
			// proposal and this is not it.
			continue
		}
		if _, ok := imported[legacyToken]; ok {
			// This proposal has already been imported
			continue
		}
		p, err := readProposal(c.legacyDir, legacyToken)
		if err != nil {
			return err
		}
		if !p.isRFP() {
			// This is not an RFP. Skip it for now.
			continue
		}
		tstoreToken, err := c.importProposal(p, nil)
		if err != nil {
			return err
		}

		imported[legacyToken] = tstoreToken
	}

	// 6. Add the remaining legacy proposals to tstore
	for _, legacyToken := range legacyInv {
		if c.token != "" && c.token != legacyToken {
			// The caller wants to import a specific
			// proposal and this is not it.
			continue
		}
		if _, ok := imported[legacyToken]; ok {
			// This proposal has already been imported
			continue
		}

		// Read the proposal from disk
		p, err := readProposal(c.legacyDir, legacyToken)
		if err != nil {
			return err
		}

		// Lookup th RFP parent tstore token if this is an RFP submission.
		// The RFP submissions must reference the parent RFP tstore token,
		// not the parent RFP legacy token.
		var rfpTstoreToken []byte
		if p.isRFPSubmission() {
			rfpTstoreToken = imported[p.VoteMetadata.LinkTo]
			if rfpTstoreToken == nil {
				// Should not happen
				return fmt.Errorf("rpf parent tstore token not found")
			}
		}

		// Import the proposal
		tstoreToken, err := c.importProposal(p, rfpTstoreToken)
		if err != nil {
			return err
		}

		imported[legacyToken] = tstoreToken
	}

	return nil
}

// fsckProposal verifies that a legacy proposal has been fully imported into
// tstore. If a partial import is found, this function will pick up where the
// previous invocation left off and finish the import.
func (c *importCmd) fsckProposal(legacyToken string, tstoreToken []byte) error {
	fmt.Printf("Fsck proposal %x %v\n", tstoreToken, legacyToken)

	return nil
}

// importProposal imports the specified legacy proposal into tstore and returns
// the tstore token that is created during import.
//
// rfpTstoreToken is an optional argument that will be populated for RFP
// submissions. The rfpTstoreToken is the parent RFP tstore token that the
// RFP submissions will need to reference. This argument will be nil for all
// proposals that are not RFP submissions.
//
// This function assumes that the proposal does not yet exist in tstore.
// Handling proposals that have been partially added is done by the
// fsckPropsal() function.
func (c *importCmd) importProposal(p *proposal, rfpTstoreToken []byte) ([]byte, error) {
	fmt.Printf("Importing proposal %v\n", p.RecordMetadata.Token)

	// Create a new tstore record entry
	tstoreToken, err := c.tstore.RecordNew()
	if err != nil {
		return nil, err
	}

	fmt.Printf("  Tstore token: %x\n", tstoreToken)

	// Save the proposal to tstore
	fmt.Printf("  Saving proposal to tstore...\n")

	err = c.saveProposal(p, tstoreToken, rfpTstoreToken)
	if err != nil {
		return nil, err
	}

	// Save the comment plugin data to tstore. This is done in a
	// separate go routine to get around the trillian log signer
	// bottleneck.
	fmt.Printf("  Saving comment plugin data to tstore...\n")

	// Save the ticketvote plugin data to tstore. This is done is
	// a separate go routine to get around the trillian log signer
	// bottleneck.
	fmt.Printf("  Saving ticketvote plugin data to tstore...\n")

	return nil, nil
}

// saveProposal saves a proposal to tstore using the same steps that would
// occur under if the proposal was saved under normal conditions and not being
// imported by this tool. This is required because there are certain steps that
// the tstore backend must complete, ex. re-saving encrypted blobs as plain
// text when a proposal is made public, in order for the proposal to be
// imported correctly.
//
// rfpTstoreToken is an optional argument that will be populated for RFP
// submissions. The rfpTstoreToken is the parent RFP tstore token that the
// RFP submissions will need to reference. This argument will be nil for all
// proposals that are not RFP submissions.
func (c *importCmd) saveProposal(p *proposal, tstoreToken, rfpTstoreToken []byte) error {
	// Perform proposal data changes
	err := overwriteProposalFields(p, tstoreToken, rfpTstoreToken)
	if err != nil {
		return err
	}

	// Convert user generated metadata into backend files.
	//
	// User generated metadata includes:
	// - pi plugin ProposalMetadata
	// - ticketvote plugin VoteMetadata (may not exist)
	f, err := convertProposalMetadataToFile(p.ProposalMetadata)
	if err != nil {
		return err
	}
	p.Files = append(p.Files, *f)

	if p.VoteMetadata != nil {
		f, err := convertVoteMetadataToFile(*p.VoteMetadata)
		if err != nil {
			return err
		}
		p.Files = append(p.Files, *f)
	}

	// Convert server generated metadata into backed metadata.
	//
	// Server generated metadata includes:
	// - user plugin StatusChangeMetadata
	// - user plugin UserMetadata
	//
	// Public proposals will only have one status change. Abandoned
	// proposals will have two status changes, the public status change
	// and the archived status change. The status changes are handled
	// individually and not automatically added to the same metadata
	// stream so that we can mimick how status change data is saved
	// under normal operation.
	userStream, err := convertUserMetadataToMetadataStream(p.UserMetadata)
	if err != nil {
		return err
	}

	var (
		publicStatus    = p.StatusChanges[0]
		abandonedStatus *usermd.StatusChangeMetadata
	)
	if len(p.StatusChanges) > 1 {
		abandonedStatus = &p.StatusChanges[1]
	}

	// Cache the record status that we will end up at. We
	// must go through the normal status iterations in order
	// to import the proposal correctly.
	//
	// Ex: unreviewed -> public -> abandoned
	status := p.RecordMetadata.Status

	// Save the proposal as unvetted
	p.RecordMetadata.State = backend.StateUnvetted
	p.RecordMetadata.Status = backend.StatusUnreviewed

	metadataStreams := []backend.MetadataStream{
		*userStream,
	}

	err = c.tstore.RecordSave(tstoreToken, p.RecordMetadata,
		metadataStreams, p.Files)
	if err != nil {
		return err
	}

	// Save the proposal as vetted. The public status change
	// is added to the status change metadata stream during
	// this step.  The timestamp is incremented by 1 second
	// so it's not the same timestamp as the unvetted version.
	p.RecordMetadata.State = backend.StateVetted
	p.RecordMetadata.Status = backend.StatusPublic
	p.RecordMetadata.Timestamp += 1

	statusChangeStream, err := convertStatusChangeToMetadataStream(publicStatus)
	if err != nil {
		return err
	}

	metadataStreams = []backend.MetadataStream{
		*userStream,
		*statusChangeStream,
	}

	err = c.tstore.RecordSave(tstoreToken, p.RecordMetadata,
		metadataStreams, p.Files)
	if err != nil {
		return err
	}

	switch status {
	case backend.StatusPublic:
		// This is a public proposal. There is nothing else
		// that needs to be done.
		return nil

	case backend.StatusArchived:
		// This is an abandoned proposal. Continue so that the
		// status is updated below.

	default:
		// This should not happen. There should only be public
		// and abandoned proposals.
		return fmt.Errorf("invalid record status %v", status)
	}

	// This is an abandoned proposal. Update the record metadata,
	// add the abandoned status to the status changes metadata
	// stream, and freeze the tstore record. This is what would
	// happen under regular operating conditions. The timestamp
	// is incremented by 1 second so that it is unique.
	p.RecordMetadata.Status = backend.StatusArchived
	p.RecordMetadata.Iteration += 1
	p.RecordMetadata.Timestamp += 1

	abandonedStream, err := convertStatusChangeToMetadataStream(*abandonedStatus)
	if err != nil {
		return err
	}

	metadataStreams = []backend.MetadataStream{
		*userStream,
		appendMetadataStream(*statusChangeStream, *abandonedStream),
	}

	return c.tstore.RecordFreeze(tstoreToken, p.RecordMetadata,
		metadataStreams, p.Files)
}

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

// appendMetadataStream appends the addition metadata streams onto the
// base metadata stream.
func appendMetadataStream(base, addition backend.MetadataStream) backend.MetadataStream {
	buf := bytes.NewBuffer([]byte(base.Payload))
	buf.WriteString(addition.Payload)
	base.Payload = buf.String()
	return base
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

// convertProposalMetadataToFile converts a pi plugin ProposalMetadata into a
// backend File.
func convertProposalMetadataToFile(pm pi.ProposalMetadata) (*backend.File, error) {
	pmb, err := json.Marshal(pm)
	if err != nil {
		return nil, err
	}
	return &backend.File{
		Name:    pi.FileNameProposalMetadata,
		MIME:    mime.DetectMimeType(pmb),
		Digest:  hex.EncodeToString(util.Digest(pmb)),
		Payload: base64.StdEncoding.EncodeToString(pmb),
	}, nil
}

// convertVoteMetadataToFile converts a ticketvote plugin VoteMetadata into a
// backend File.
func convertVoteMetadataToFile(vm ticketvote.VoteMetadata) (*backend.File, error) {
	vmb, err := json.Marshal(vm)
	if err != nil {
		return nil, err
	}
	return &backend.File{
		Name:    ticketvote.FileNameVoteMetadata,
		MIME:    mime.DetectMimeType(vmb),
		Digest:  hex.EncodeToString(util.Digest(vmb)),
		Payload: base64.StdEncoding.EncodeToString(vmb),
	}, nil
}

// convertUserMetadataToMetadataStream converts a usermd plugin UserMetadata
// into a backend MetadataStream.
func convertUserMetadataToMetadataStream(um usermd.UserMetadata) (*backend.MetadataStream, error) {
	b, err := json.Marshal(um)
	if err != nil {
		return nil, err
	}
	return &backend.MetadataStream{
		PluginID: usermd.PluginID,
		StreamID: usermd.StreamIDUserMetadata,
		Payload:  string(b),
	}, nil
}

// convertStatusChangeToMetadataStream converts a usermd plugin
// StatusChangeMetadata into a backend MetadataStream.
func convertStatusChangeToMetadataStream(scm usermd.StatusChangeMetadata) (*backend.MetadataStream, error) {
	b, err := json.Marshal(scm)
	if err != nil {
		return nil, err
	}
	return &backend.MetadataStream{
		PluginID: usermd.PluginID,
		StreamID: usermd.StreamIDStatusChanges,
		Payload:  string(b),
	}, nil
}
