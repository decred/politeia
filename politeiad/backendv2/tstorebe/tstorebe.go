// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tstorebe

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"time"

	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/api/v1/mime"
	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/tstore"
	"github.com/decred/politeia/util"
	"github.com/pkg/errors"
	"github.com/subosito/gozaru"
)

var (
	_ backend.Backend = (*tstoreBackend)(nil)
)

// tstoreBackend implements the backendv2 Backend interface using a tstore as
// the backing data store.
type tstoreBackend struct {
	settings backend.BackendSettings
	tstore   *tstore.Tstore

	// cache is the key-value store cache. This is used by read only
	// methods for interacting with cached data. Write methods use a
	// store Tx instead of interacting with the BlobKV directly.
	cache store.BlobKV

	// inv provides a concurrency save API for tracking the record
	// inventory. Only the record tokens and some additional filtering
	// criteria, such as record status, are saved to the inventory.
	inv *recordInv
}

// New returns a new tstoreBackend.
func New(appDir, dataDir string, tlogHost, tlogPass, dbType, dbHost, dbPass, dcrtimeHost, dcrtimeCert string, fi identity.FullIdentity, net chaincfg.Params) (*tstoreBackend, error) {
	// Setup the key-value store
	log.Infof("Database type: %v", dbType)
	opts := blobKVOpts{
		Type:     dbType,
		AppDir:   appDir,
		DataDir:  dataDir,
		Host:     dbHost,
		Password: dbPass,
		Net:      net.Name,
	}
	kv, err := newBlobKV(opts)
	if err != nil {
		return nil, err
	}

	// Setup tstore
	ts, err := tstore.New(net, kv, tlogHost, tlogPass,
		dcrtimeHost, dcrtimeCert)
	if err != nil {
		return nil, err
	}

	return &tstoreBackend{
		settings: backend.BackendSettings{
			Identity: fi,
			Net:      net,
		},
		tstore: ts,
		cache:  kv,
		inv:    newRecordInv(),
	}, nil
}

// RecordNew creates a new record.
//
// This function satisfies the backendv2 Backend interface.
func (t *tstoreBackend) RecordNew(metadata []backend.MetadataStream, files []backend.File) (*backend.Record, error) {
	log.Tracef("RecordNew: %v metadata, %v files", len(metadata), len(files))

	// Verify record content
	err := metadataStreamsVerify(metadata)
	if err != nil {
		return nil, err
	}
	err = filesVerify(files, nil)
	if err != nil {
		return nil, err
	}

	// Setup a new tstore transaction. The Tx method is used instead
	// of the RecordTx method because we have not created the record
	// yet. Creating a record creates a tree in tlog. A record should
	// not be created until the plugin validation (HookNewRecordPre)
	// has passed, but we still need a key-value store tx in order to
	// execute the plugin hooks so we use the Tx method.
	tx, cancel, err := t.tstore.Tx()
	if err != nil {
		return nil, err
	}
	defer cancel()

	// Call pre plugin hooks
	pre := plugins.RecordNew{
		Metadata: metadata,
		Files:    files,
	}
	b, err := json.Marshal(pre)
	if err != nil {
		return nil, err
	}
	err = t.tstore.PluginHook(tx, plugins.HookRecordNewPre, string(b))
	if err != nil {
		return nil, err
	}

	// Create a new token
	token, err := t.tstore.RecordNew(tx)
	if err != nil {
		return nil, err
	}

	// Create record metadata
	rm, err := recordMetadataNew(token, files, backend.StateUnvetted,
		backend.StatusUnreviewed, 1, 1)
	if err != nil {
		return nil, err
	}

	// Save the record
	err = t.tstore.RecordSave(tx, token, *rm, metadata, files)
	if err != nil {
		return nil, err
	}

	// Call post plugin hooks
	post := plugins.RecordNew{
		Metadata:       metadata,
		Files:          files,
		RecordMetadata: rm,
	}
	b, err = json.Marshal(post)
	if err != nil {
		return nil, err
	}
	err = t.tstore.PluginHook(tx, plugins.HookRecordNewPost, string(b))
	if err != nil {
		return nil, err
	}

	// Update the inventory cache
	err = t.invAdd(tx, token, rm.Timestamp)
	if err != nil {
		return nil, err
	}

	// Commit the tstore transaction
	err = tx.Commit()
	if err != nil {
		if err2 := tx.Rollback(); err2 != nil {
			// We're in trouble!
			panic(fmt.Sprintf("rollback tx failed: "+
				"commit:'%v' rollback:'%v'", err, err2))
		}
		return nil, err
	}

	// Return the full record
	return t.tstore.RecordLatest(token)
}

// RecordEdit edits an existing record. This creates a new version of the
// record.
//
// This function satisfies the backendv2 Backend interface.
func (t *tstoreBackend) RecordEdit(token []byte, mdAppend, mdOverwrite []backend.MetadataStream, filesAdd []backend.File, filesDel []string) (*backend.Record, error) {
	log.Tracef("RecordEdit: %x", token)

	// Verify record contents. Send in a single metadata array to
	// verify there are no dups.
	allMD := append(mdAppend, mdOverwrite...)
	err := metadataStreamsVerify(allMD)
	if err != nil {
		return nil, err
	}
	err = filesVerify(filesAdd, filesDel)
	if err != nil {
		return nil, err
	}

	// Setup a new tstore transaction
	tx, cancel, err := t.tstore.RecordTx(token)
	if err != nil {
		return nil, err
	}
	defer cancel()

	// Get existing record
	r, err := t.tstore.TxRecordLatest(tx, token)
	if err != nil {
		return nil, err
	}

	// Apply changes
	var (
		rm       = r.RecordMetadata
		metadata = metadataStreamsUpdate(r.Metadata, mdAppend, mdOverwrite)
		files    = filesUpdate(r.Files, filesAdd, filesDel)
	)
	recordMD, err := recordMetadataNew(token, files, rm.State, rm.Status,
		rm.Version+1, rm.Iteration+1)
	if err != nil {
		return nil, err
	}

	// Verify that file changes are being made. The merkle root is the
	// merkle root of the files. It will be the same if no file changes
	// are being made.
	if r.RecordMetadata.Merkle == recordMD.Merkle {
		// No file changes found
		return nil, backend.ErrNoRecordChanges
	}

	// Call pre plugin hooks
	re := plugins.RecordEdit{
		Record:         *r,
		RecordMetadata: *recordMD,
		Metadata:       metadata,
		Files:          files,
	}
	b, err := json.Marshal(re)
	if err != nil {
		return nil, err
	}
	err = t.tstore.PluginHook(tx, plugins.HookRecordEditPre, string(b))
	if err != nil {
		return nil, err
	}

	// Save record
	err = t.tstore.RecordSave(tx, token, *recordMD, metadata, files)
	if err != nil {
		return nil, err
	}

	// Call post plugin hooks
	err = t.tstore.PluginHook(tx, plugins.HookRecordEditPost, string(b))
	if err != nil {
		return nil, err
	}

	// Commit the tstore transaction
	err = tx.Commit()
	if err != nil {
		if err2 := tx.Rollback(); err2 != nil {
			// We're in trouble!
			panic(fmt.Sprintf("rollback tx failed: "+
				"commit:'%v' rollback:'%v'", err, err2))
		}
		return nil, err
	}

	// Return the updated record
	return t.tstore.RecordLatest(token)
}

// RecordEditMetadata edits the metadata of a record without changing any
// record files. This creates a new iteration of the record, but not a new
// version of the record.
//
// This function satisfies the backendv2 Backend interface.
func (t *tstoreBackend) RecordEditMetadata(token []byte, mdAppend, mdOverwrite []backend.MetadataStream) (*backend.Record, error) {
	log.Tracef("RecordEditMetadata: %x", token)

	// Verify metadata. Send in a single metadata array to verify there
	// are no dups.
	allMD := append(mdAppend, mdOverwrite...)
	err := metadataStreamsVerify(allMD)
	if err != nil {
		return nil, err
	}
	if len(mdAppend) == 0 && len(mdOverwrite) == 0 {
		return nil, backend.ErrNoRecordChanges
	}

	// Setup a new tstore transaction
	tx, cancel, err := t.tstore.RecordTx(token)
	if err != nil {
		return nil, err
	}
	defer cancel()

	// Get existing record
	r, err := t.tstore.TxRecordLatest(tx, token)
	if err != nil {
		if err == backend.ErrRecordNotFound {
			return nil, err
		}
		return nil, err
	}

	// Apply changes. The version is not incremented for metadata only
	// updates. The iteration is incremented.
	var (
		rm       = r.RecordMetadata
		metadata = metadataStreamsUpdate(r.Metadata, mdAppend, mdOverwrite)
	)
	recordMD, err := recordMetadataNew(token, r.Files, rm.State, rm.Status,
		rm.Version, rm.Iteration+1)
	if err != nil {
		return nil, err
	}

	// Call pre plugin hooks
	em := plugins.RecordEditMetadata{
		Record:   *r,
		Metadata: metadata,
	}
	b, err := json.Marshal(em)
	if err != nil {
		return nil, err
	}
	err = t.tstore.PluginHook(tx, plugins.HookRecordEditMetadataPre, string(b))
	if err != nil {
		return nil, err
	}

	// Update metadata
	err = t.tstore.RecordSave(tx, token, *recordMD, metadata, r.Files)
	if err != nil {
		return nil, err
	}

	// Call post plugin hooks
	err = t.tstore.PluginHook(tx, plugins.HookRecordEditMetadataPost, string(b))
	if err != nil {
		return nil, err
	}

	// Commit the tstore transaction
	err = tx.Commit()
	if err != nil {
		if err2 := tx.Rollback(); err2 != nil {
			// We're in trouble!
			panic(fmt.Sprintf("rollback tx failed: "+
				"commit:'%v' rollback:'%v'", err, err2))
		}
		return nil, err
	}

	// Return updated record
	return t.tstore.RecordLatest(token)
}

var (
	// statusChanges contains the allowed record status changes. If
	// statusChanges[currentStatus][newStatus] exists then the status
	// change is allowed.
	statusChanges = map[backend.StatusT]map[backend.StatusT]struct{}{
		// Unreviewed to...
		backend.StatusUnreviewed: {
			backend.StatusPublic:   {},
			backend.StatusCensored: {},
		},
		// Public to...
		backend.StatusPublic: {
			backend.StatusCensored: {},
			backend.StatusArchived: {},
		},
		// Statuses that do not allow any further transitions
		backend.StatusCensored: {},
		backend.StatusArchived: {},
	}
)

// statusChangeIsAllowed returns whether the provided status change is allowed.
func statusChangeIsAllowed(from, to backend.StatusT) bool {
	allowed, ok := statusChanges[from]
	if !ok {
		return false
	}
	_, ok = allowed[to]
	return ok
}

// setStatusPublic updates the status of a record to public.
func (t *tstoreBackend) setStatusPublic(tx store.Tx, token []byte, rm backend.RecordMetadata, metadata []backend.MetadataStream) error {
	return t.tstore.RecordSaveMetadata(tx, token, rm, metadata)
}

// setStatusArchived freezes the provided record. The provided record metadata
// and metadata streams are saved to tstore as part of the freezing process.
func (t *tstoreBackend) setStatusArchived(tx store.Tx, token []byte, rm backend.RecordMetadata, metadata []backend.MetadataStream) error {
	// Freeze record
	err := t.tstore.RecordFreeze(tx, token, rm, metadata)
	if err != nil {
		return err
	}

	log.Debugf("Record frozen %x", token)

	// Nothing else needs to be done for a archived record

	return nil
}

// setStatusCensored freezes the provided record and deletes all record files
// for all versions of the record. The provided record metadata and metadata
// streams are saved to tstore as part of the freezing process.
func (t *tstoreBackend) setStatusCensored(tx store.Tx, token []byte, rm backend.RecordMetadata, metadata []backend.MetadataStream) error {
	// Freeze the tree
	err := t.tstore.RecordFreeze(tx, token, rm, metadata)
	if err != nil {
		return err
	}

	log.Debugf("Record frozen %x", token)

	// Delete all record files
	err = t.tstore.RecordDel(tx, token)
	if err != nil {
		return err
	}

	log.Debugf("Record contents deleted %x", token)

	return nil
}

// RecordSetStatus sets the status of a record.
//
// This function satisfies the backendv2 Backend interface.
func (t *tstoreBackend) RecordSetStatus(token []byte, status backend.StatusT, mdAppend, mdOverwrite []backend.MetadataStream) (*backend.Record, error) {
	log.Tracef("RecordSetStatus: %x %v", token, status)

	// Setup a new tstore transaction
	tx, cancel, err := t.tstore.RecordTx(token)
	if err != nil {
		return nil, err
	}
	defer cancel()

	// Get existing record
	r, err := t.tstore.TxRecordLatest(tx, token)
	if err != nil {
		return nil, err
	}
	currStatus := r.RecordMetadata.Status

	// Validate status change
	if !statusChangeIsAllowed(currStatus, status) {
		return nil, backend.StatusTransitionError{
			From: currStatus,
			To:   status,
		}
	}

	// If the record is being made public the record state gets updated
	// to vetted and the version and iteration are reset. Otherwise,
	// the state and version remain the same while the iteration gets
	// incremented to reflect the status change.
	var (
		state   = r.RecordMetadata.State
		version = r.RecordMetadata.Version
		iter    = r.RecordMetadata.Iteration + 1 // Increment for status change
	)
	if status == backend.StatusPublic {
		state = backend.StateVetted
		version = 1
		iter = 1
	}

	// Apply changes
	recordMD, err := recordMetadataNew(token, r.Files,
		state, status, version, iter)
	if err != nil {
		return nil, err
	}
	metadata := metadataStreamsUpdate(r.Metadata, mdAppend, mdOverwrite)

	// Call pre plugin hooks
	rss := plugins.RecordSetStatus{
		Record:         *r,
		RecordMetadata: *recordMD,
		Metadata:       metadata,
	}
	b, err := json.Marshal(rss)
	if err != nil {
		return nil, err
	}
	err = t.tstore.PluginHook(tx, plugins.HookRecordSetStatusPre, string(b))
	if err != nil {
		return nil, err
	}

	// Update record status
	switch status {
	case backend.StatusPublic:
		err := t.setStatusPublic(tx, token, *recordMD, metadata)
		if err != nil {
			return nil, err
		}
	case backend.StatusArchived:
		err := t.setStatusArchived(tx, token, *recordMD, metadata)
		if err != nil {
			return nil, err
		}
	case backend.StatusCensored:
		err := t.setStatusCensored(tx, token, *recordMD, metadata)
		if err != nil {
			return nil, err
		}
	default:
		// Should not happen
		return nil, errors.Errorf("unknown status %v", status)
	}

	log.Debugf("Status updated %x from %v (%v) to %v (%v)",
		token, backend.Statuses[currStatus], currStatus,
		backend.Statuses[status], status)

	// Call post plugin hooks
	err = t.tstore.PluginHook(tx, plugins.HookRecordSetStatusPost, string(b))
	if err != nil {
		return nil, err
	}

	// Update inventory cache
	switch status {
	case backend.StatusPublic:
		// The state is updated to vetted when a record is made public
		err = t.invMoveToVetted(tx, token, r.RecordMetadata.Timestamp)
		if err != nil {
			return nil, err
		}
	default:
		err = t.invUpdate(tx, r.RecordMetadata.State, token,
			status, r.RecordMetadata.Timestamp)
		if err != nil {
			return nil, err
		}
	}

	// Commit the tstore transaction
	err = tx.Commit()
	if err != nil {
		if err2 := tx.Rollback(); err2 != nil {
			// We're in trouble!
			panic(fmt.Sprintf("rollback tx failed: "+
				"commit:'%v' rollback:'%v'", err, err2))
		}
		return nil, err
	}

	// Return updated record
	return t.tstore.RecordLatest(token)
}

// RecordExists returns whether a record exists.
//
// This method only returns whether a tree exists for the provided token. It's
// possible for a tree to exist that does not correspond to a record in the
// rare case that a tree was created but an unexpected error, such as a network
// error, was encoutered prior to the record being saved to the tree. We ignore
// this edge case because:
//
// 1. A user has no way to obtain this token unless the trillian instance has
//    been opened to the public.
//
// 2. Even if they have the token they cannot do anything with it. Any attempt
//  	to read from the tree or write to the tree will return a RecordNotFound
//    error.
//
// Pulling the leaves from the tree to see if a record has been saved to the
// tree adds a large amount of overhead to this call, which should be a very
// light weight call. Its for this reason that we rely on the tree exists call
// despite the edge case.
//
// This function satisfies the backendv2 Backend interface.
func (t *tstoreBackend) RecordExists(token []byte) bool {
	log.Tracef("RecordExists: %x", token)

	return t.tstore.RecordExists(token)
}

// RecordTimestamps returns the timestamps for a record. If no version is
// provided then timestamps for the most recent version will be returned.
//
// This function satisfies the backendv2 Backend interface.
func (t *tstoreBackend) RecordTimestamps(token []byte, version uint32) (*backend.RecordTimestamps, error) {
	log.Tracef("RecordTimestamps: %x %v", token, version)

	return t.tstore.RecordTimestamps(token, version)
}

// Records retreives a batch of records. Individual record errors are not
// returned. If the record was not found then it will not be included in the
// returned map.
//
// This function satisfies the backendv2 Backend interface.
func (t *tstoreBackend) Records(reqs []backend.RecordRequest) (map[string]backend.Record, error) {
	log.Tracef("Records: %v reqs", len(reqs))

	records := make(map[string]backend.Record, len(reqs)) // [token]Record
	for _, v := range reqs {
		// Lookup the record
		r, err := t.tstore.RecordPartial(v.Token, v.Version,
			v.Filenames, v.OmitAllFiles)
		if err != nil {
			if err == backend.ErrRecordNotFound {
				// Record doesn't exist. This is ok. It will not be included
				// in the reply.
				log.Debugf("Record not found %x", v.Token)
				continue
			}
			// An unexpected error occurred. Log it and continue.
			log.Errorf("RecordPartial %x: %v", v.Token, err)
			continue
		}

		// Update reply. Use whatever token was provided as the key so
		// that the client can validate the reply using the same token
		// that they provided, regardless of whether its a short token
		// or full length token.
		records[util.TokenEncode(v.Token)] = *r
	}

	return records, nil
}

// Inventory returns the tokens of records in the inventory categorized by
// record state and record status. The tokens are ordered by the timestamp of
// their most recent status change, sorted from newest to oldest.
//
// The state, status, and pageNum arguments can be provided to request a
// specific page of record tokens.
//
// If no status is provided then the most recent page of tokens for all
// statuses will be returned. The state and pageNum arguments are ignored when
// no status is provided.
//
// This function satisfies the backendv2 Backend interface.
func (t *tstoreBackend) Inventory(state backend.StateT, status backend.StatusT, pageSize, pageNum uint32) (*backend.Inventory, error) {
	log.Tracef("Inventory: %v %v %v %v", state, status, pageSize, pageNum)

	inv, err := t.invByStatus(t.cache, state, status, pageSize, pageNum)
	if err != nil {
		return nil, err
	}

	return &backend.Inventory{
		Unvetted: inv.Unvetted,
		Vetted:   inv.Vetted,
	}, nil
}

// InventoryOrdered returns a page of record tokens ordered by the timestamp of
// their most recent status change. The returned tokens will include all record
// statuses.
//
// This function satisfies the backendv2 Backend interface.
func (t *tstoreBackend) InventoryOrdered(state backend.StateT, pageSize, pageNumber uint32) ([]string, error) {
	log.Tracef("InventoryOrdered: %v %v %v", state, pageSize, pageNumber)

	return t.invOrdered(t.cache, state, pageSize, pageNumber)
}

// PluginRegister registers a plugin.
//
// This function satisfies the backendv2 Backend interface.
func (t *tstoreBackend) PluginRegister(p backend.Plugin) error {
	log.Tracef("PluginRegister: %v %v", p.ID, p.Settings)

	return t.tstore.PluginRegister(t, t.settings, p)
}

// PluginSetup performs any required plugin setup.
//
// This function satisfies the backendv2 Backend interface.
func (t *tstoreBackend) PluginSetup(pluginID string) error {
	log.Tracef("PluginSetup: %v", pluginID)

	return t.tstore.PluginSetup(pluginID)
}

// PluginRead executes a read-only plugin command.
//
// This function satisfies the backendv2 Backend interface.
func (t *tstoreBackend) PluginRead(token []byte, pluginID, pluginCmd, payload string) (string, error) {
	log.Tracef("PluginRead: %x %v %v %v", token, pluginID, pluginCmd, payload)

	// Verify record exists if a token was provided. The token is
	// optional on read commands so one may not exist.
	if len(token) > 0 && !t.RecordExists(token) {
		return "", backend.ErrRecordNotFound
	}

	// Execute plugin command
	return t.tstore.PluginRead(token, pluginID, pluginCmd, payload)
}

// PluginWrite executes a plugin command that writes data.
//
// This function satisfies the backendv2 Backend interface.
func (t *tstoreBackend) PluginWrite(token []byte, pluginID, pluginCmd, payload string) (string, error) {
	log.Tracef("PluginWrite: %x %v %v", token, pluginID, pluginCmd)

	// Verify record exists
	if !t.RecordExists(token) {
		return "", backend.ErrRecordNotFound
	}

	// Setup a new tstore transaction
	tx, cancel, err := t.tstore.RecordTx(token)
	if err != nil {
		return "", err
	}
	defer cancel()

	// Call pre plugin hooks
	pw := plugins.PluginWrite{
		Token:    token,
		PluginID: pluginID,
		Cmd:      pluginCmd,
		Payload:  payload,
	}
	b, err := json.Marshal(pw)
	if err != nil {
		return "", err
	}
	err = t.tstore.PluginHook(tx, plugins.HookPluginWritePre, string(b))
	if err != nil {
		return "", err
	}

	// Execute plugin command
	reply, err := t.tstore.PluginWrite(tx, token, pluginID, pluginCmd, payload)
	if err != nil {
		return "", err
	}

	// Call post plugin hooks
	pw = plugins.PluginWrite{
		PluginID: pluginID,
		Cmd:      pluginCmd,
		Payload:  payload,
		Reply:    reply,
	}
	b, err = json.Marshal(pw)
	if err != nil {
		return "", err
	}
	err = t.tstore.PluginHook(tx, plugins.HookPluginWritePost, string(b))
	if err != nil {
		return "", err
	}

	// Commit the tstore transaction
	err = tx.Commit()
	if err != nil {
		if err2 := tx.Rollback(); err2 != nil {
			// We're in trouble!
			panic(fmt.Sprintf("rollback tx failed: "+
				"commit:'%v' rollback:'%v'", err, err2))
		}
		return "", err
	}

	return reply, nil
}

// PluginInventory returns all registered plugins.
//
// This function satisfies the backendv2 Backend interface.
func (t *tstoreBackend) PluginInventory() []backend.Plugin {
	log.Tracef("PluginInventory")

	return t.tstore.Plugins()
}

// Close performs cleanup of the backend.
//
// This function satisfies the backendv2 Backend interface.
func (t *tstoreBackend) Close() {
	log.Tracef("Close")

	// Close tstore connections
	t.tstore.Close()
}

// metadataStreamsVerify verifies that all provided metadata streams are sane.
func metadataStreamsVerify(metadata []backend.MetadataStream) error {
	// Verify metadata
	md := make(map[string]map[uint32]struct{}, len(metadata))
	for i, v := range metadata {
		// Verify all fields are provided
		switch {
		case v.PluginID == "":
			e := fmt.Sprintf("plugin id missing at index %v", i)
			return backend.ContentError{
				ErrorCode:    backend.ContentErrorMetadataStreamInvalid,
				ErrorContext: e,
			}
		case v.StreamID == 0:
			e := fmt.Sprintf("stream id missing at index %v", i)
			return backend.ContentError{
				ErrorCode:    backend.ContentErrorMetadataStreamInvalid,
				ErrorContext: e,
			}
		case v.Payload == "":
			e := fmt.Sprintf("payload missing on %v %v", v.PluginID, v.StreamID)
			return backend.ContentError{
				ErrorCode:    backend.ContentErrorMetadataStreamInvalid,
				ErrorContext: e,
			}
		}

		// Verify no duplicates
		m, ok := md[v.PluginID]
		if !ok {
			m = make(map[uint32]struct{}, len(metadata))
			md[v.PluginID] = m
		}
		if _, ok := m[v.StreamID]; ok {
			e := fmt.Sprintf("%v %v", v.PluginID, v.StreamID)
			return backend.ContentError{
				ErrorCode:    backend.ContentErrorMetadataStreamDuplicate,
				ErrorContext: e,
			}
		}

		// Add to metadata list
		m[v.StreamID] = struct{}{}
		md[v.PluginID] = m
	}

	return nil
}

func metadataStreamsUpdate(curr, mdAppend, mdOverwrite []backend.MetadataStream) []backend.MetadataStream {
	// Put current metadata into a map
	md := make(map[string]backend.MetadataStream, len(curr))
	for _, v := range curr {
		k := v.PluginID + strconv.FormatUint(uint64(v.StreamID), 10)
		md[k] = v
	}

	// Apply overwrites
	for _, v := range mdOverwrite {
		k := v.PluginID + strconv.FormatUint(uint64(v.StreamID), 10)
		md[k] = v
	}

	// Apply appends. Its ok if an append is specified but there is no
	// existing metadata for that metadata stream. In this case the
	// append data will become the full metadata stream.
	for _, v := range mdAppend {
		k := v.PluginID + strconv.FormatUint(uint64(v.StreamID), 10)
		m, ok := md[k]
		if !ok {
			// No existing metadata. Use append data as full metadata
			// stream.
			md[k] = v
			continue
		}

		// Metadata exists. Append to it.
		buf := bytes.NewBuffer([]byte(m.Payload))
		buf.WriteString(v.Payload)
		m.Payload = buf.String()
		md[k] = m
	}

	// Convert metadata back to a slice
	metadata := make([]backend.MetadataStream, 0, len(md))
	for _, v := range md {
		metadata = append(metadata, v)
	}

	return metadata
}

// filesVerify verifies that all provided files are sane.
func filesVerify(files []backend.File, filesDel []string) error {
	// Verify files are being updated
	if len(files) == 0 && len(filesDel) == 0 {
		return backend.ContentError{
			ErrorCode: backend.ContentErrorFilesEmpty,
		}
	}

	// Prevent paths
	for i := range files {
		if filepath.Base(files[i].Name) != files[i].Name {
			e := fmt.Sprintf("%v contains a file path", files[i].Name)
			return backend.ContentError{
				ErrorCode:    backend.ContentErrorFileNameInvalid,
				ErrorContext: e,
			}
		}
	}
	for _, v := range filesDel {
		if filepath.Base(v) != v {
			e := fmt.Sprintf("%v contains a file path", v)
			return backend.ContentError{
				ErrorCode:    backend.ContentErrorFileNameInvalid,
				ErrorContext: e,
			}
		}
	}

	// Prevent duplicate filenames
	fn := make(map[string]struct{}, len(files)+len(filesDel))
	for i := range files {
		if _, ok := fn[files[i].Name]; ok {
			return backend.ContentError{
				ErrorCode:    backend.ContentErrorFileNameDuplicate,
				ErrorContext: files[i].Name,
			}
		}
		fn[files[i].Name] = struct{}{}
	}
	for _, v := range filesDel {
		if _, ok := fn[v]; ok {
			return backend.ContentError{
				ErrorCode:    backend.ContentErrorFileNameDuplicate,
				ErrorContext: v,
			}
		}
		fn[v] = struct{}{}
	}

	// Prevent bad filenames
	for i := range files {
		if gozaru.Sanitize(files[i].Name) != files[i].Name {
			e := fmt.Sprintf("%v is not sanitized", files[i].Name)
			return backend.ContentError{
				ErrorCode:    backend.ContentErrorFileNameInvalid,
				ErrorContext: e,
			}
		}

		// Verify digest
		d, ok := util.ConvertDigest(files[i].Digest)
		if !ok {
			return backend.ContentError{
				ErrorCode:    backend.ContentErrorFileDigestInvalid,
				ErrorContext: files[i].Name,
			}
		}

		// Verify payload is not empty
		if files[i].Payload == "" {
			e := fmt.Sprintf("%v payload empty", files[i].Name)
			return backend.ContentError{
				ErrorCode:    backend.ContentErrorFilePayloadInvalid,
				ErrorContext: e,
			}
		}

		// Decode base64 payload
		payload, err := base64.StdEncoding.DecodeString(files[i].Payload)
		if err != nil {
			e := fmt.Sprintf("%v invalid base64", files[i].Name)
			return backend.ContentError{
				ErrorCode:    backend.ContentErrorFilePayloadInvalid,
				ErrorContext: e,
			}
		}

		// Calculate payload digest
		dp := util.Digest(payload)
		if !bytes.Equal(d[:], dp) {
			e := fmt.Sprintf("%v digest got %x, want %x",
				files[i].Name, d[:], dp)
			return backend.ContentError{
				ErrorCode:    backend.ContentErrorFileDigestInvalid,
				ErrorContext: e,
			}
		}

		// Verify MIME
		detectedMIMEType := mime.DetectMimeType(payload)
		if detectedMIMEType != files[i].MIME {
			e := fmt.Sprintf("%v mime got %v, want %v",
				files[i].Name, files[i].MIME, detectedMIMEType)
			return backend.ContentError{
				ErrorCode:    backend.ContentErrorFileMIMETypeInvalid,
				ErrorContext: e,
			}
		}

		if !mime.MimeValid(files[i].MIME) {
			return backend.ContentError{
				ErrorCode:    backend.ContentErrorFileMIMETypeUnsupported,
				ErrorContext: files[i].Name,
			}
		}
	}

	return nil
}

// filesUpdate updates the current files with new file adds and deletes.
func filesUpdate(filesCurr, filesAdd []backend.File, filesDel []string) []backend.File {
	// Put current files into a map
	curr := make(map[string]backend.File, len(filesCurr)) // [filename]File
	for _, v := range filesCurr {
		curr[v.Name] = v
	}

	// Apply deletes
	for _, fn := range filesDel {
		_, ok := curr[fn]
		if ok {
			delete(curr, fn)
		}
	}

	// Apply adds
	for _, v := range filesAdd {
		curr[v.Name] = v
	}

	// Convert back to a slice
	f := make([]backend.File, 0, len(curr))
	for _, v := range curr {
		f = append(f, v)
	}

	return f
}

// recordMetadataNew returns a new record metadata.
func recordMetadataNew(token []byte, files []backend.File, state backend.StateT, status backend.StatusT, version, iteration uint32) (*backend.RecordMetadata, error) {
	digests := make([]string, 0, len(files))
	for _, v := range files {
		digests = append(digests, v.Digest)
	}
	m, err := util.MerkleRoot(digests)
	if err != nil {
		return nil, err
	}
	return &backend.RecordMetadata{
		Token:     hex.EncodeToString(token),
		Version:   version,
		Iteration: iteration,
		State:     state,
		Status:    status,
		Timestamp: time.Now().Unix(),
		Merkle:    hex.EncodeToString(m[:]),
	}, nil
}
