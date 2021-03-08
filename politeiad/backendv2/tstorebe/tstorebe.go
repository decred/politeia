// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tstorebe

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/politeia/politeiad/api/v1/mime"
	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/tstore"
	"github.com/decred/politeia/util"
	"github.com/subosito/gozaru"
)

var (
	_ backend.Backend = (*tstoreBackend)(nil)
)

// tstoreBackend implements the Backend interface.
type tstoreBackend struct {
	sync.RWMutex
	appDir   string
	dataDir  string
	shutdown bool
	tstore   *tstore.Tstore

	// prefixes contains the prefix to full token mapping for all
	// records. The prefix is the first n characters of the hex encoded
	// record token, where n is defined by the token prefix length
	// politeiad setting. Record lookups by token prefix are allowed.
	// This cache is used to prevent prefix collisions when creating
	// new tokens and to facilitate lookups by token prefix. This cache
	// is built on startup.
	prefixes map[string][]byte // [tokenPrefix]token

	// recordMtxs allows the backend to hold a lock on an individual
	// record so that it can perform multiple read/write operations
	// in a concurrent safe manner. These mutexes are lazy loaded.
	recordMtxs map[string]*sync.Mutex
}

// isShutdown returns whether the backend is shutdown.
func (t *tstoreBackend) isShutdown() bool {
	t.RLock()
	defer t.RUnlock()

	return t.shutdown
}

// recordMutex returns the mutex for a record.
func (t *tstoreBackend) recordMutex(token []byte) *sync.Mutex {
	t.Lock()
	defer t.Unlock()

	ts := hex.EncodeToString(token)
	m, ok := t.recordMtxs[ts]
	if !ok {
		// recordMtxs is lazy loaded
		m = &sync.Mutex{}
		t.recordMtxs[ts] = m
	}

	return m
}

func (t *tstoreBackend) prefixExists(fullToken []byte) bool {
	t.RLock()
	defer t.RUnlock()

	_, ok := t.prefixes[util.TokenPrefix(fullToken)]
	return ok
}

func (t *tstoreBackend) prefixAdd(fullToken []byte) {
	t.Lock()
	defer t.Unlock()

	prefix := util.TokenPrefix(fullToken)
	t.prefixes[prefix] = fullToken

	log.Debugf("Add token prefix: %v", prefix)
}

func tokenFromTreeID(treeID int64) []byte {
	b := make([]byte, 8)
	// Converting between int64 and uint64 doesn't change
	// the sign bit, only the way it's interpreted.
	binary.LittleEndian.PutUint64(b, uint64(treeID))
	return b
}

func tokenIsFullLength(token []byte) bool {
	return util.TokenIsFullLength(util.TokenTypeTstore, token)
}

func treeIDFromToken(token []byte) int64 {
	if !tokenIsFullLength(token) {
		return 0
	}
	return int64(binary.LittleEndian.Uint64(token))
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

// RecordNew creates a new record.
//
// This function satisfies the Backend interface.
func (t *tstoreBackend) RecordNew(metadata []backend.MetadataStream, files []backend.File) (*backend.Record, error) {
	log.Tracef("RecordNew")

	// Verify record content
	err := metadataStreamsVerify(metadata)
	if err != nil {
		return nil, err
	}
	err = filesVerify(files, nil)
	if err != nil {
		return nil, err
	}

	// Call pre plugin hooks
	pre := plugins.HookNewRecordPre{
		Metadata: metadata,
		Files:    files,
	}
	b, err := json.Marshal(pre)
	if err != nil {
		return nil, err
	}
	err = t.tstore.PluginHookPre(0, []byte{},
		plugins.HookTypeNewRecordPre, string(b))
	if err != nil {
		return nil, err
	}

	// Create a new token
	var token []byte
	var treeID int64
	for retries := 0; retries < 10; retries++ {
		treeID, err = t.tstore.TreeNew()
		if err != nil {
			return nil, err
		}
		token = tokenFromTreeID(treeID)

		// Check for token prefix collisions
		if !t.prefixExists(token) {
			// Not a collision. Use this token.

			// Update the prefix cache. This must be done even if the
			// record creation fails since the tree will still exist in
			// tstore.
			t.prefixAdd(token)

			break
		}

		log.Infof("Token prefix collision %v, creating new token",
			util.TokenPrefix(token))
	}

	// Create record metadata
	rm, err := recordMetadataNew(token, files, backend.StateUnvetted,
		backend.StatusUnreviewed, 1, 1)
	if err != nil {
		return nil, err
	}

	// Save the record
	err = t.tstore.RecordSave(treeID, *rm, metadata, files)
	if err != nil {
		return nil, fmt.Errorf("RecordSave: %v", err)
	}

	// Call post plugin hooks
	post := plugins.HookNewRecordPost{
		Metadata:       metadata,
		Files:          files,
		RecordMetadata: *rm,
	}
	b, err = json.Marshal(post)
	if err != nil {
		return nil, err
	}
	t.tstore.PluginHookPost(treeID, token,
		plugins.HookTypeNewRecordPost, string(b))

	// Update the inventory cache
	t.inventoryAdd(backend.StateUnvetted, token, backend.StatusUnreviewed)

	// Get the full record to return
	r, err := t.RecordGet(token, 0)
	if err != nil {
		return nil, fmt.Errorf("RecordGet %x: %v", token, err)
	}

	return r, nil
}

// RecordEdit edits an existing record. This creates a new version of the
// record.
//
// This function satisfies the Backend interface.
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

	// Verify token is valid. The full length token must be used when
	// writing data.
	if !tokenIsFullLength(token) {
		return nil, backend.ErrTokenInvalid
	}

	// Verify record exists
	if !t.RecordExists(token) {
		return nil, backend.ErrRecordNotFound
	}

	// Apply the record changes and save the new version. The record
	// lock needs to be held for the remainder of the function.
	if t.isShutdown() {
		return nil, backend.ErrShutdown
	}
	m := t.recordMutex(token)
	m.Lock()
	defer m.Unlock()

	// Get existing record
	treeID := treeIDFromToken(token)
	r, err := t.tstore.RecordLatest(treeID)
	if err != nil {
		return nil, fmt.Errorf("RecordLatest %v: %v", treeID, err)
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

	// Call pre plugin hooks
	her := plugins.HookEditRecord{
		Current:        *r,
		RecordMetadata: *recordMD,
		Metadata:       metadata,
		Files:          files,
	}
	b, err := json.Marshal(her)
	if err != nil {
		return nil, err
	}
	err = t.tstore.PluginHookPre(treeID, token,
		plugins.HookTypeEditRecordPre, string(b))
	if err != nil {
		return nil, err
	}

	// Save record
	err = t.tstore.RecordSave(treeID, *recordMD, metadata, files)
	if err != nil {
		switch err {
		case backend.ErrRecordLocked, backend.ErrNoRecordChanges:
			return nil, err
		default:
			return nil, fmt.Errorf("RecordSave: %v", err)
		}
	}

	// Call post plugin hooks
	t.tstore.PluginHookPost(treeID, token,
		plugins.HookTypeEditRecordPost, string(b))

	// Return updated record
	r, err = t.tstore.RecordLatest(treeID)
	if err != nil {
		return nil, fmt.Errorf("RecordLatest %v: %v", treeID, err)
	}

	return r, nil
}

// RecordEditMetadata edits the metadata of a record without changing any
// record files. This creates a new iteration of the record, but not a new
// version of the record.
//
// This function satisfies the Backend interface.
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

	// Verify token is valid. The full length token must be used when
	// writing data.
	if !tokenIsFullLength(token) {
		return nil, backend.ErrTokenInvalid
	}

	// Verify record exists
	if !t.RecordExists(token) {
		return nil, backend.ErrRecordNotFound
	}

	// Apply the record changes and save the new version. The record
	// lock needs to be held for the remainder of the function.
	if t.isShutdown() {
		return nil, backend.ErrShutdown
	}
	m := t.recordMutex(token)
	m.Lock()
	defer m.Unlock()

	// Get existing record
	treeID := treeIDFromToken(token)
	r, err := t.tstore.RecordLatest(treeID)
	if err != nil {
		return nil, fmt.Errorf("RecordLatest %v: %v", treeID, err)
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
	hem := plugins.HookEditMetadata{
		Current:  *r,
		Metadata: metadata,
	}
	b, err := json.Marshal(hem)
	if err != nil {
		return nil, err
	}
	err = t.tstore.PluginHookPre(treeID, token,
		plugins.HookTypeEditMetadataPre, string(b))
	if err != nil {
		return nil, err
	}

	// Update metadata
	err = t.tstore.RecordMetadataSave(treeID, *recordMD, metadata)
	if err != nil {
		switch err {
		case backend.ErrRecordLocked, backend.ErrNoRecordChanges:
			return nil, err
		default:
			return nil, fmt.Errorf("RecordMetadataSave: %v", err)
		}
	}

	// Call post plugin hooks
	t.tstore.PluginHookPost(treeID, token,
		plugins.HookTypeEditMetadataPost, string(b))

	// Return updated record
	r, err = t.tstore.RecordLatest(treeID)
	if err != nil {
		return nil, fmt.Errorf("RecordLatest %v: %v", treeID, err)
	}

	return r, nil
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
//
// This function must be called WITH the record lock held.
func (t *tstoreBackend) setStatusPublic(token []byte, rm backend.RecordMetadata, metadata []backend.MetadataStream) error {
	// TODO tstore needs a publish method
	treeID := treeIDFromToken(token)
	return t.tstore.RecordMetadataSave(treeID, rm, metadata)
}

// setStatusArchived updates the status of a record to archived.
//
// This function must be called WITH the record lock held.
func (t *tstoreBackend) setStatusArchived(token []byte, rm backend.RecordMetadata, metadata []backend.MetadataStream) error {
	// Freeze the tree
	treeID := treeIDFromToken(token)
	err := t.tstore.TreeFreeze(treeID, rm, metadata)
	if err != nil {
		return fmt.Errorf("TreeFreeze %v: %v", treeID, err)
	}

	log.Debugf("Record frozen %x", token)

	// Nothing else needs to be done for a archived record

	return nil
}

// setStatusCensored updates the status of a record to censored.
//
// This function must be called WITH the record lock held.
func (t *tstoreBackend) setStatusCensored(token []byte, rm backend.RecordMetadata, metadata []backend.MetadataStream) error {
	// Freeze the tree
	treeID := treeIDFromToken(token)
	err := t.tstore.TreeFreeze(treeID, rm, metadata)
	if err != nil {
		return fmt.Errorf("TreeFreeze %v: %v", treeID, err)
	}

	log.Debugf("Record frozen %x", token)

	// Delete all record files
	err = t.tstore.RecordDel(treeID)
	if err != nil {
		return fmt.Errorf("RecordDel %v: %v", treeID, err)
	}

	log.Debugf("Record contents deleted %x", token)

	return nil
}

// RecordSetStatus sets the status of a record.
//
// This function satisfies the Backend interface.
func (t *tstoreBackend) RecordSetStatus(token []byte, status backend.StatusT, mdAppend, mdOverwrite []backend.MetadataStream) (*backend.Record, error) {
	log.Tracef("RecordSetStatus: %x %v", token, status)

	// Verify token is valid. The full length token must be used when
	// writing data.
	if !tokenIsFullLength(token) {
		return nil, backend.ErrTokenInvalid
	}

	// Verify record exists
	if !t.RecordExists(token) {
		return nil, backend.ErrRecordNotFound
	}

	// The existing record must be pulled and updated. The record
	// lock must be held for the rest of this function.
	if t.isShutdown() {
		return nil, backend.ErrShutdown
	}
	m := t.recordMutex(token)
	m.Lock()
	defer m.Unlock()

	// Get existing record
	treeID := treeIDFromToken(token)
	r, err := t.tstore.RecordLatest(treeID)
	if err != nil {
		return nil, fmt.Errorf("RecordLatest: %v", err)
	}
	currStatus := r.RecordMetadata.Status

	// Validate status change
	if !statusChangeIsAllowed(currStatus, status) {
		return nil, backend.StatusTransitionError{
			From: currStatus,
			To:   status,
		}
	}

	// Determine the state. Making a record public will also trigger
	// a state update to vetted.
	var state backend.StateT
	if status == backend.StatusPublic {
		state = backend.StateVetted
	} else {
		state = r.RecordMetadata.State
	}

	// Apply changes
	recordMD, err := recordMetadataNew(token, r.Files, state, status,
		r.RecordMetadata.Version, r.RecordMetadata.Iteration+1)
	if err != nil {
		return nil, err
	}
	metadata := metadataStreamsUpdate(r.Metadata, mdAppend, mdOverwrite)

	// Call pre plugin hooks
	hsrs := plugins.HookSetRecordStatus{
		Current:        *r,
		RecordMetadata: *recordMD,
		Metadata:       metadata,
	}
	b, err := json.Marshal(hsrs)
	if err != nil {
		return nil, err
	}
	err = t.tstore.PluginHookPre(treeID, token,
		plugins.HookTypeSetRecordStatusPre, string(b))
	if err != nil {
		return nil, err
	}

	// Update record status
	switch status {
	case backend.StatusPublic:
		err := t.setStatusPublic(token, *recordMD, metadata)
		if err != nil {
			return nil, err
		}
	case backend.StatusArchived:
		err := t.setStatusArchived(token, *recordMD, metadata)
		if err != nil {
			return nil, err
		}
	case backend.StatusCensored:
		err := t.setStatusCensored(token, *recordMD, metadata)
		if err != nil {
			return nil, err
		}
	default:
		// Should not happen
		return nil, fmt.Errorf("unknown status %v", status)
	}

	log.Debugf("Status updated %x from %v (%v) to %v (%v)",
		token, backend.Statuses[currStatus], currStatus,
		backend.Statuses[status], status)

	// Call post plugin hooks
	t.tstore.PluginHookPost(treeID, token,
		plugins.HookTypeSetRecordStatusPost, string(b))

	// Update inventory cache
	switch status {
	case backend.StatusPublic:
		// The state is updated to vetted when a record is made public
		t.inventoryMoveToVetted(token, status)
	default:
		t.inventoryUpdate(r.RecordMetadata.State, token, status)
	}

	// Return updated record
	r, err = t.tstore.RecordLatest(treeID)
	if err != nil {
		return nil, fmt.Errorf("RecordLatest %v: %v", treeID, err)
	}

	return r, nil
}

// RecordExists returns whether a record exists.
//
// This method relies on the the tstore tree exists call. It's possible for a
// tree to exist that does not correspond to a record in the rare case that a
// tree was created but an unexpected error, such as a network error, was
// encoutered prior to the record being saved to the tree. We ignore this edge
// case because:
//
// 1. A user has no way to obtain this token unless the trillian instance has
//    been opened to the public.
//
// 2. Even if they have the token they cannot do anything with it. Any attempt
//  	to read from the tree or write to the tree will return a RecordNotFound
//    error.
//
// Pulling the leaves from the tree to see if a record has been saved to the
// tree adds a large amount of overhead to this call that should be very light
// weight. Its for this reason that we rely on the tree exists call despite the
// edge case.
//
// This function satisfies the Backend interface.
func (t *tstoreBackend) RecordExists(token []byte) bool {
	log.Tracef("RecordExists: %x", token)

	treeID := treeIDFromToken(token)
	return t.tstore.TreeExists(treeID)
}

// RecordGet retrieves a record. If no version is provided then the most recent
// version will be returned.
//
// This function satisfies the Backend interface.
func (t *tstoreBackend) RecordGet(token []byte, version uint32) (*backend.Record, error) {
	log.Tracef("RecordGet: %x", token)

	treeID := treeIDFromToken(token)
	return t.tstore.Record(treeID, version)
}

// RecordGetBatch retreives a batch of records. Individual record errors are
// not returned.  If the record was not found then it will not be included in
// the returned map.
//
// This function satisfies the Backend interface.
func (t *tstoreBackend) RecordGetBatch(reqs []backend.RecordRequest) (map[string]backend.Record, error) {
	log.Tracef("RecordGetBatch")

	records := make(map[string]backend.Record, len(reqs))
	for _, v := range reqs {
		treeID := treeIDFromToken(v.Token)
		r, err := t.tstore.RecordPartial(treeID, v.Version,
			v.Filenames, v.OmitAllFiles)
		if err != nil {
			if err == backend.ErrRecordNotFound {
				// Record doesn't exist. This is ok. It will not be included
				// in the reply.
				continue
			}
			// An unexpected error occurred. Log it and continue.
			log.Debug("RecordPartial %v: %v", treeID, err)
			continue
		}

		// Update reply
		records[r.RecordMetadata.Token] = *r
	}

	return records, nil
}

// RecordTimestamps returns the timestamps for a record. If no version is provided
// then timestamps for the most recent version will be returned.
//
// This function satisfies the Backend interface.
func (t *tstoreBackend) RecordTimestamps(token []byte, version uint32) (*backend.RecordTimestamps, error) {
	log.Tracef("RecordTimestamps: %x %v", token, version)

	treeID := treeIDFromToken(token)
	return t.tstore.RecordTimestamps(treeID, version, token)
}

// Inventory returns the tokens of records in the inventory categorized by
// record state and record status. The tokens are ordered by the timestamp of
// their most recent status change, sorted from newest to oldest.
//
// The state, status, and page arguments can be provided to request a specific
// page of record tokens.
//
// If no status is provided then the most recent page of tokens for each
// statuses will be returned. All other arguments are ignored.
//
// This function satisfies the Backend interface.
func (t *tstoreBackend) Inventory(state backend.StateT, status backend.StatusT, pageSize, pageNumber uint32) (*backend.Inventory, error) {
	log.Tracef("InventoryByStatus: %v %v %v %v",
		state, status, pageSize, pageNumber)

	inv, err := t.invByStatus(state, status, pageSize, pageNumber)
	if err != nil {
		return nil, err
	}

	return &backend.Inventory{
		Unvetted: inv.Unvetted,
		Vetted:   inv.Vetted,
	}, nil
}

// InventoryTimeOrdered returns a page of record tokens sorted by timestamp of
// their most recent status change. The returned tokens are not sorted by
// status and will included all statuses.
//
// This function satisfies the Backend interface.
func (t *tstoreBackend) InventoryTimeOrdered(state backend.StateT, pageSize, pageNumber uint32) ([]string, error) {
	log.Tracef("InventoryTimeOrdered: %v %v %v", state, pageSize, pageNumber)

	return nil, fmt.Errorf("not implemented")
}

// PluginRegister registers a plugin.
//
// This function satisfies the Backend interface.
func (t *tstoreBackend) PluginRegister(p backend.Plugin) error {
	return t.tstore.PluginRegister(t, p)
}

// PluginSetup performs any required plugin setup.
//
// This function satisfies the Backend interface.
func (t *tstoreBackend) PluginSetup(pluginID string) error {
	log.Tracef("PluginSetup: %v", pluginID)

	return t.tstore.PluginSetup(pluginID)
}

// PluginCmdRead executes a read plugin command.
//
// This function satisfies the Backend interface.
func (t *tstoreBackend) PluginCmdRead(token []byte, pluginID, pluginCmd, payload string) (string, error) {
	log.Tracef("PluginCmdRead: %x %v %v", token, pluginID, pluginCmd)

	// The token is optional. If a token is not provided then a tree ID
	// will not be provided to the plugin.
	var treeID int64
	if len(token) > 0 {
		treeID = treeIDFromToken(token)

		// Verify record exists
		if !t.RecordExists(token) {
			return "", backend.ErrRecordNotFound
		}
	}

	if len(token) > 0 {
		log.Infof("Plugin '%v' read cmd '%v' on %x",
			pluginID, pluginCmd, token)
	} else {
		log.Infof("Plugin '%v' read cmd '%v'",
			pluginID, pluginCmd)
	}

	return t.tstore.PluginCmd(treeID, token, pluginID, pluginCmd, payload)
}

// PluginCmdWrite executes a write plugin command.
//
// This function satisfies the Backend interface.
func (t *tstoreBackend) PluginCmdWrite(token []byte, pluginID, pluginCmd, payload string) (string, error) {
	log.Tracef("PluginCmdWrite: %x %v %v", token, pluginID, pluginCmd)

	// Verify record exists
	if !t.RecordExists(token) {
		return "", backend.ErrRecordNotFound
	}

	// Hold the record lock for the remainder of this function. We
	// do this here in the backend so that the individual plugins
	// implementations don't need to worry about race conditions.
	m := t.recordMutex(token)
	m.Lock()
	defer m.Unlock()

	log.Infof("Plugin '%v' write cmd '%v' on %x",
		pluginID, pluginCmd, token)

	// Call pre plugin hooks
	treeID := treeIDFromToken(token)
	hp := plugins.HookPluginPre{
		PluginID: pluginID,
		Cmd:      pluginCmd,
		Payload:  payload,
	}
	b, err := json.Marshal(hp)
	if err != nil {
		return "", err
	}
	err = t.tstore.PluginHookPre(treeID, token,
		plugins.HookTypePluginPre, string(b))
	if err != nil {
		return "", err
	}

	// Execute plugin command
	reply, err := t.tstore.PluginCmd(treeID, token,
		pluginID, pluginCmd, payload)
	if err != nil {
		return "", err
	}

	// Call post plugin hooks
	hpp := plugins.HookPluginPost{
		PluginID: pluginID,
		Cmd:      pluginCmd,
		Payload:  payload,
		Reply:    reply,
	}
	b, err = json.Marshal(hpp)
	if err != nil {
		return "", err
	}
	t.tstore.PluginHookPost(treeID, token,
		plugins.HookTypePluginPost, string(b))

	return reply, nil
}

// PluginInventory returns all registered plugins.
//
// This function satisfies the Backend interface.
func (t *tstoreBackend) PluginInventory() []backend.Plugin {
	log.Tracef("Plugins")

	return t.tstore.Plugins()
}

// Close performs cleanup of the backend.
//
// This function satisfies the Backend interface.
func (t *tstoreBackend) Close() {
	log.Tracef("Close")

	t.Lock()
	defer t.Unlock()

	// Shutdown backend
	t.shutdown = true

	// Close tstore connections
	t.tstore.Close()
}

// setup builds the tstore backend caches.
func (t *tstoreBackend) setup() error {
	log.Tracef("setup")

	log.Infof("Building backend token prefix cache")

	// A record token is created using the unvetted tree ID so we
	// only need to retrieve the unvetted trees in order to build the
	// token prefix cache.
	treeIDs, err := t.tstore.TreesAll()
	if err != nil {
		return fmt.Errorf("TreesAll: %v", err)
	}

	log.Infof("%v records in the backend", len(treeIDs))

	for _, v := range treeIDs {
		token := tokenFromTreeID(v)
		t.prefixAdd(token)
	}

	return nil
}

// New returns a new tstoreBackend.
func New(appDir, dataDir string, anp *chaincfg.Params, trillianHost, trillianSigningKey, dbType, dbHost, dbPass, dbEncryptionKeyFile, dcrtimeHost, dcrtimeCert string) (*tstoreBackend, error) {
	// Setup tstore instances
	ts, err := tstore.New(appDir, dataDir, anp, trillianHost,
		trillianSigningKey, dbType, dbHost, dbPass, dbEncryptionKeyFile,
		dcrtimeHost, dcrtimeCert)
	if err != nil {
		return nil, fmt.Errorf("new tstore: %v", err)
	}

	// Setup backend
	t := tstoreBackend{
		appDir:     appDir,
		dataDir:    dataDir,
		tstore:     ts,
		prefixes:   make(map[string][]byte),
		recordMtxs: make(map[string]*sync.Mutex),
	}

	err = t.setup()
	if err != nil {
		return nil, fmt.Errorf("setup: %v", err)
	}

	return &t, nil
}
