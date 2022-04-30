// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/decred/dcrd/dcrutil/v3"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/api/v1/mime"
	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/tstore"
	"github.com/decred/politeia/politeiad/plugins/comments"
	"github.com/decred/politeia/politeiad/plugins/pi"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	"github.com/decred/politeia/politeiad/plugins/usermd"
	"github.com/decred/politeia/politeiawww/config"
	"github.com/decred/politeia/politeiawww/legacy/user"
	mysqldb "github.com/decred/politeia/politeiawww/legacy/user/mysql"
	"github.com/decred/politeia/util"
	"github.com/google/uuid"
)

const (
	// tstore settings
	defaultTlogHost = "localhost:8090"
	defaultTlogPass = "tlogpass"
	defaultDBType   = "mysql"
	defaultDBHost   = "localhost:3306"
	defaultDBPass   = "politeiadpass"

	// User database settings
	userDBPass = "politeiawwwpass"
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
	stubUsers   = importFlags.Bool("stubusers", false, "")

	// tstore settings
	politeiadHomeDir = dcrutil.AppDataDir("politeiad", false)
	politeiadDataDir = filepath.Join(politeiadHomeDir, "data")
	dbType           = tstore.DBTypeMySQL
	dcrtimeHost      = "" // Not needed for import
	dcrtimeCert      = "" // Not needed for import

	// User database settings
	userDBEncryptionKey = filepath.Join(config.DefaultHomeDir, "sbox.key")
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

	// Setup the tstore connection
	ts, err := tstore.New(politeiadHomeDir, politeiadDataDir,
		params, *tlogHost, dbType, *dbHost, *dbPass, "", "")
	if err != nil {
		return err
	}

	// Setup the user database connection
	var (
		userDB user.Database
		httpC  *http.Client
	)
	if *stubUsers {
		userDB, err = mysqldb.New(*dbHost, userDBPass,
			params.Name, userDBEncryptionKey)
		if err != nil {
			return err
		}
		httpC, err = util.NewHTTPClient(false, "")
		if err != nil {
			return err
		}
	}

	// Setup the import cmd
	c := &importCmd{
		legacyDir: legacyDir,
		tstore:    ts,
		token:     *importToken,
		stubUsers: *stubUsers,
		userDB:    userDB,
		http:      httpC,
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
	stubUsers bool
	tstore    *tstore.Tstore

	// The following fields will only be populated when the caller provides
	// the stub users flag.
	userDB user.Database
	http   *http.Client
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

	fmt.Printf("%v legacy proposals found for import\n", len(legacyInv))

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

		// Stub the user in the politeiawww user database
		if c.stubUsers {
			err := c.stubProposalUsers(*p)
			if err != nil {
				return err
			}
		}
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

	// Perform proposal data changes
	err = overwriteProposalFields(p, tstoreToken, rfpTstoreToken)
	if err != nil {
		return nil, err
	}

	// Import the proposal contents
	fmt.Printf("  Importing record data...\n")
	err = c.importRecord(*p, tstoreToken)
	if err != nil {
		return nil, err
	}

	fmt.Printf("  Importing comment plugin data...\n")
	err = c.importCommentPluginData(*p, tstoreToken)
	if err != nil {
		return nil, err
	}

	fmt.Printf("  Importing ticketvote plugin data...\n")
	err = c.importTicketvotePluginData(*p, tstoreToken)
	if err != nil {
		return nil, err
	}

	return nil, nil
}

// importRecord imports the backend record portion of a proposal into tstore
// using the same steps that would occur under if the proposal was saved under
// normal conditions and not being imported by this tool. This is required
// because there are certain steps that the tstore backend must complete, ex.
// re-saving encrypted blobs as plain text when a proposal is made public, in
// order for the proposal to be imported correctly.
func (c *importCmd) importRecord(p proposal, tstoreToken []byte) error {
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

	// Convert server generated metadata into backed metadata streams.
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

// importCommentPluginData imports the comment plugin data into tstore for
// the provided proposal.
func (c *importCmd) importCommentPluginData(p proposal, tstoreToken []byte) error {
	for i, v := range p.CommentAdds {
		s := fmt.Sprintf("    Comment add %v/%v", i+1, len(p.CommentAdds))
		printInPlace(s)

		err := c.saveCommentAdd(tstoreToken, v)
		if err != nil {
			return err
		}

		if i == len(p.CommentAdds)-1 {
			fmt.Printf("\n")
		}
	}
	for i, v := range p.CommentDels {
		s := fmt.Sprintf("    Comment del %v/%v", i+1, len(p.CommentDels))
		printInPlace(s)

		err := c.saveCommentDel(tstoreToken, v)
		if err != nil {
			return err
		}

		if i == len(p.CommentDels)-1 {
			fmt.Printf("\n")
		}
	}
	for i, v := range p.CommentVotes {
		s := fmt.Sprintf("    Comment vote %v/%v", i+1, len(p.CommentVotes))
		printInPlace(s)

		err := c.saveCommentVote(tstoreToken, v)
		if err != nil {
			return err
		}

		if i == len(p.CommentVotes)-1 {
			fmt.Printf("\n")
		}
	}
	return nil
}

// importTicketvotePluginData imports the ticketvote plugin data into tstore
// for the provided proposal.
//
// Some proposals we're never voted on and therefor do not have any ticketvote
// plugin data that needs to be imported.
func (c *importCmd) importTicketvotePluginData(p proposal, tstoreToken []byte) error {
	// Save the auth details
	if p.AuthDetails == nil {
		return nil
	}

	fmt.Printf("    Auth details\n")

	err := c.saveAuthDetails(tstoreToken, *p.AuthDetails)
	if err != nil {
		return err
	}

	// Save the vote details
	if p.VoteDetails == nil {
		return nil
	}

	fmt.Printf("    Vote details\n")

	err = c.saveVoteDetails(tstoreToken, *p.VoteDetails)
	if err != nil {
		return err
	}

	// Save the cast votes. These are saved concurrently in batches
	// to get around the tlog signer performance bottleneck. The tlog
	// signer will only append queued leaves onto a tlog tree every
	// xxx interval, where xxx is a config setting that is currently
	// configured to 200ms for politeia. If we did not submit the
	// votes concurrently, each vote would take at least 200ms to
	// be saved, which is unacceptably slow when you have tens of
	// thousands of votes to save.
	for i, v := range p.CastVotes {
		s := fmt.Sprintf("    Cast vote %v/%v", i+1, len(p.CastVotes))
		printInPlace(s)

		err = c.saveCastVoteDetails(tstoreToken, v)
		if err != nil {
			return err
		}
		vc := voteCollider{
			Token:  v.Token,
			Ticket: v.Ticket,
		}
		err = c.saveVoteCollider(tstoreToken, vc)
		if err != nil {
			return err
		}
	}
	fmt.Printf("\n")

	// TODO save the startRunoffRecord to the parent RFP tlog tree

	return nil
}

const (
	// The following data descriptors were pulled from the plugins. They're not
	// exported from the plugins and under normal circumstances there's no reason
	// to have them as exported variables, so we duplicate them here.

	// comments plugin data descriptors
	dataDescriptorCommentAdd  = comments.PluginID + "-add-v1"
	dataDescriptorCommentDel  = comments.PluginID + "-del-v1"
	dataDescriptorCommentVote = comments.PluginID + "-vote-v1"

	// ticketvote plugin data descriptors
	dataDescriptorAuthDetails     = ticketvote.PluginID + "-auth-v1"
	dataDescriptorVoteDetails     = ticketvote.PluginID + "-vote-v1"
	dataDescriptorCastVoteDetails = ticketvote.PluginID + "-castvote-v1"
	dataDescriptorVoteCollider    = ticketvote.PluginID + "-vcollider-v1"
	dataDescriptorStartRunoff     = ticketvote.PluginID + "-startrunoff-v1"
)

// saveCommentAdd saves a CommentAdd to tstore as a plugin data blob.
func (c *importCmd) saveCommentAdd(tstoreToken []byte, ca comments.CommentAdd) error {
	data, err := json.Marshal(ca)
	if err != nil {
		return err
	}
	hint, err := json.Marshal(
		store.DataDescriptor{
			Type:       store.DataTypeStructure,
			Descriptor: dataDescriptorCommentAdd,
		})
	if err != nil {
		return err
	}
	be := store.NewBlobEntry(hint, data)
	tstoreClient := tstore.NewTstoreClient(c.tstore, comments.PluginID)
	return tstoreClient.BlobSave(tstoreToken, be)
}

// saveCommentDel saves a CommentDel to tstore as a plugin data blob.
func (c *importCmd) saveCommentDel(tstoreToken []byte, cd comments.CommentDel) error {
	data, err := json.Marshal(cd)
	if err != nil {
		return err
	}
	hint, err := json.Marshal(
		store.DataDescriptor{
			Type:       store.DataTypeStructure,
			Descriptor: dataDescriptorCommentDel,
		})
	if err != nil {
		return err
	}
	be := store.NewBlobEntry(hint, data)
	tstoreClient := tstore.NewTstoreClient(c.tstore, comments.PluginID)
	return tstoreClient.BlobSave(tstoreToken, be)
}

// saveCommentVote saves a CommentVote to tstore as a plugin data blob.
func (c *importCmd) saveCommentVote(tstoreToken []byte, cv comments.CommentVote) error {
	data, err := json.Marshal(cv)
	if err != nil {
		return err
	}
	hint, err := json.Marshal(
		store.DataDescriptor{
			Type:       store.DataTypeStructure,
			Descriptor: dataDescriptorCommentVote,
		})
	if err != nil {
		return err
	}
	be := store.NewBlobEntry(hint, data)
	tstoreClient := tstore.NewTstoreClient(c.tstore, comments.PluginID)
	return tstoreClient.BlobSave(tstoreToken, be)
}

// saveAuthDetails saves a AuthDetails to tstore as a plugin data blob.
func (c *importCmd) saveAuthDetails(tstoreToken []byte, ad ticketvote.AuthDetails) error {
	data, err := json.Marshal(ad)
	if err != nil {
		return err
	}
	hint, err := json.Marshal(
		store.DataDescriptor{
			Type:       store.DataTypeStructure,
			Descriptor: dataDescriptorAuthDetails,
		})
	if err != nil {
		return err
	}
	be := store.NewBlobEntry(hint, data)
	tstoreClient := tstore.NewTstoreClient(c.tstore, ticketvote.PluginID)
	return tstoreClient.BlobSave(tstoreToken, be)
}

// saveVoteDetails saves a VoteDetails to tstore as a plugin data blob.
func (c *importCmd) saveVoteDetails(tstoreToken []byte, vd ticketvote.VoteDetails) error {
	data, err := json.Marshal(vd)
	if err != nil {
		return err
	}
	hint, err := json.Marshal(
		store.DataDescriptor{
			Type:       store.DataTypeStructure,
			Descriptor: dataDescriptorVoteDetails,
		})
	if err != nil {
		return err
	}
	be := store.NewBlobEntry(hint, data)
	tstoreClient := tstore.NewTstoreClient(c.tstore, ticketvote.PluginID)
	return tstoreClient.BlobSave(tstoreToken, be)
}

// saveCastVoteDetails saves a CastVoteDetails to tstore as a plugin data blob.
func (c *importCmd) saveCastVoteDetails(tstoreToken []byte, cvd ticketvote.CastVoteDetails) error {
	data, err := json.Marshal(cvd)
	if err != nil {
		return err
	}
	hint, err := json.Marshal(
		store.DataDescriptor{
			Type:       store.DataTypeStructure,
			Descriptor: dataDescriptorCastVoteDetails,
		})
	if err != nil {
		return err
	}
	be := store.NewBlobEntry(hint, data)
	tstoreClient := tstore.NewTstoreClient(c.tstore, ticketvote.PluginID)
	return tstoreClient.BlobSave(tstoreToken, be)
}

// saveVoteCollider saves a voteCollider to tstore as a plugin data blob.
func (c *importCmd) saveVoteCollider(tstoreToken []byte, vc voteCollider) error {
	data, err := json.Marshal(vc)
	if err != nil {
		return err
	}
	hint, err := json.Marshal(
		store.DataDescriptor{
			Type:       store.DataTypeStructure,
			Descriptor: dataDescriptorVoteCollider,
		})
	if err != nil {
		return err
	}
	be := store.NewBlobEntry(hint, data)
	tstoreClient := tstore.NewTstoreClient(c.tstore, ticketvote.PluginID)
	return tstoreClient.BlobSave(tstoreToken, be)
}

// stubProposalUsers creates a stub in the user database for all user IDs and
// public keys found in any of the proposal data.
func (c *importCmd) stubProposalUsers(p proposal) error {
	fmt.Printf("  Stubbing proposal users...\n")

	// Stub the proposal author
	err := c.stubUser(p.UserMetadata.UserID, p.UserMetadata.PublicKey)
	if err != nil {
		return err
	}

	// Stub the comment and comment vote authors. A user
	// ID may be associated with multiple public keys.
	pks := make(map[string]string, 256) // [publicKey]userID
	for _, v := range p.CommentAdds {
		pks[v.PublicKey] = v.UserID
	}
	for _, v := range p.CommentDels {
		pks[v.PublicKey] = v.UserID
	}
	for _, v := range p.CommentVotes {
		pks[v.PublicKey] = v.UserID
	}
	for publicKey, userID := range pks {
		err := c.stubUser(userID, publicKey)
		if err != nil {
			return err
		}
	}

	return nil
}

// stubUser creates a stub in the user database for the provided user ID.
//
// If a user stub already exists, this function verifies that the stub contains
// the provided public key. If it doesn't, the function will add the missing
// public key to the user and update the stub in the database.
func (c *importCmd) stubUser(userID, publicKey string) error {
	// Check if this user already exists in the user database
	uid, err := uuid.Parse(userID)
	if err != nil {
		return err
	}
	dbu, err := c.userDB.UserGetById(uid)
	switch {
	case err == nil:
		// User already exist. Update the user if the provided
		// public key is not part of the user stub.
		for _, id := range dbu.Identities {
			if id.String() == publicKey {
				// This user stub already contains the provided
				// public key. Nothing else to do.
				return nil
			}
		}

		fmt.Printf("    Updating stubbed user %v %v\n", uid, dbu.Username)

		updatedIDs, err := addIdentity(dbu.Identities, publicKey)
		if err != nil {
			return err
		}

		dbu.Identities = updatedIDs
		return c.userDB.UserUpdate(*dbu)

	case errors.Is(err, user.ErrUserNotFound):
		// User doesn't exist. Pull their username from the mainnet
		// Politeia API and add them to the user database.
		u, err := userByID(c.http, userID)
		if err != nil {
			return err
		}

		// Setup the identities
		ids, err := addIdentity([]user.Identity{}, publicKey)
		if err != nil {
			return err
		}

		fmt.Printf("    Stubbing user %v %v\n", uid, u.Username)

		return c.userDB.InsertUser(user.User{
			ID:             uid,
			Email:          u.Username + "@example.com",
			Username:       u.Username,
			HashedPassword: []byte("password"),
			Admin:          false,
			Identities:     ids,
		})

	default:
		// All other errors
		return err
	}
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

// addIdentity converts the provided public key string into a politeiawww user
// identity and adds it to the provided identities list.
//
// The created identities will not mimic what would happen during normal
// operation of the backend and this function should only be used for creating
// test user stubs in the database.
func addIdentity(ids []user.Identity, publicKey string) ([]user.Identity, error) {
	if ids == nil {
		return nil, fmt.Errorf("identities slice is nil")
	}

	// Add the identities to the existing identities list
	id, err := identity.PublicIdentityFromString(publicKey)
	if err != nil {
		return nil, err
	}
	ids = append(ids, user.Identity{
		Key:       id.Key,
		Activated: time.Now().Unix(),
	})

	// Make the last identity the only active identity.
	// Not sure if this actually matters, but do it anyway.
	for i, v := range ids {
		v.Deactivated = v.Activated + 1
		ids[i] = v
	}
	ids[len(ids)-1].Deactivated = 0

	return ids, nil
}
