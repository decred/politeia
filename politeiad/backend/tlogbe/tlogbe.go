// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlogbe

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/decred/dcrd/chaincfg/v3"
	v1 "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/api/v1/mime"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe/plugins"
	"github.com/decred/politeia/politeiad/backend/tlogbe/tlog"
	pdutil "github.com/decred/politeia/politeiad/util"
	"github.com/decred/politeia/util"
	"github.com/marcopeereboom/sbox"
	"github.com/subosito/gozaru"
)

// TODO testnet vs mainnet trillian databases
// TODO fsck
// TODO move memory caches to filesystem

const (
	defaultEncryptionKeyFilename = "tlogbe.key"

	// Tlog instance IDs
	tlogIDUnvetted = "unvetted"
	tlogIDVetted   = "vetted"
)

var (
	_ backend.Backend = (*tlogBackend)(nil)
)

// tlogBackend implements the backend.Backend interface.
type tlogBackend struct {
	sync.RWMutex
	activeNetParams *chaincfg.Params
	homeDir         string
	dataDir         string
	shutdown        bool
	unvetted        *tlog.Tlog
	vetted          *tlog.Tlog

	// prefixes contains the prefix to full token mapping for unvetted
	// records. The prefix is the first n characters of the hex encoded
	// record token, where n is defined by the TokenPrefixLength from
	// the politeiad API. Record lookups by token prefix are allowed.
	// This cache is used to prevent prefix collisions when creating
	// new tokens and to facilitate lookups by token prefix. This cache
	// is built on startup.
	prefixes map[string][]byte // [tokenPrefix]token

	// vettedTreeIDs contains the token to tree ID mapping for vetted
	// records. The token corresponds to the unvetted tree ID so
	// unvetted lookups can be done directly, but vetted lookups
	// required pulling the vetted tree pointer from the unvetted tree.
	// This cache memoizes those results and is lazy loaded.
	vettedTreeIDs map[string]int64 // [token]treeID

	// inventory contains the full record inventory grouped by record
	// status. Each list of tokens is sorted by the timestamp of the
	// status change from newest to oldest. This cache is built on
	// startup.
	inv inventory
}

func tokenFromTreeID(treeID int64) []byte {
	b := make([]byte, v1.TokenSizeTlog)
	// Converting between int64 and uint64 doesn't change
	// the sign bit, only the way it's interpreted.
	binary.LittleEndian.PutUint64(b, uint64(treeID))
	return b
}

func tokenIsFullLength(token []byte) bool {
	return util.TokenIsFullLength(util.TokenTypeTlog, token)
}

func treeIDFromToken(token []byte) int64 {
	if !tokenIsFullLength(token) {
		return 0
	}
	return int64(binary.LittleEndian.Uint64(token))
}

// fullLengthToken returns the full length token given the token prefix.
//
// This function must be called WITHOUT the lock held.
func (t *tlogBackend) fullLengthToken(prefix []byte) ([]byte, bool) {
	t.Lock()
	defer t.Unlock()

	token, ok := t.prefixes[util.TokenPrefix(prefix)]
	return token, ok
}

// unvettedTreeIDFromToken returns the unvetted tree ID for the provided token.
// This can be either the full length token or the token prefix.
//
// This function must be called WITHOUT the lock held.
func (t *tlogBackend) unvettedTreeIDFromToken(token []byte) int64 {
	if len(token) == util.TokenPrefixSize() {
		// This is a token prefix. Get the full token from the cache.
		var ok bool
		token, ok = t.fullLengthToken(token)
		if !ok {
			return 0
		}
	}
	return treeIDFromToken(token)
}

func (t *tlogBackend) prefixExists(fullToken []byte) bool {
	t.RLock()
	defer t.RUnlock()

	_, ok := t.prefixes[util.TokenPrefix(fullToken)]
	return ok
}

func (t *tlogBackend) prefixAdd(fullToken []byte) {
	t.Lock()
	defer t.Unlock()

	prefix := util.TokenPrefix(fullToken)
	t.prefixes[prefix] = fullToken

	log.Debugf("Add token prefix: %v", prefix)
}

func (t *tlogBackend) vettedTreeID(token []byte) (int64, bool) {
	t.RLock()
	defer t.RUnlock()

	treeID, ok := t.vettedTreeIDs[hex.EncodeToString(token)]
	return treeID, ok
}

func (t *tlogBackend) vettedTreeIDAdd(token string, treeID int64) {
	t.Lock()
	defer t.Unlock()

	t.vettedTreeIDs[token] = treeID

	log.Debugf("Add vetted tree ID: %v %v", token, treeID)
}

// vettedTreeIDFromToken returns the vetted tree ID that corresponds to the
// provided token. If a tree ID is not found then the returned bool will be
// false.
//
// This function must be called WITHOUT the lock held.
func (t *tlogBackend) vettedTreeIDFromToken(token []byte) (int64, bool) {
	// Check if the token is in the vetted cache. The vetted cache is
	// lazy loaded if the token is not present then we need to check
	// manually.
	vettedTreeID, ok := t.vettedTreeID(token)
	if ok {
		return vettedTreeID, true
	}

	// The token is derived from the unvetted tree ID. Check if the
	// unvetted record has a tree pointer. The tree pointer will be
	// the vetted tree ID.
	unvettedTreeID := t.unvettedTreeIDFromToken(token)
	vettedTreeID, ok = t.unvetted.TreePointer(unvettedTreeID)
	if !ok {
		// No tree pointer. This record either doesn't exist or is an
		// unvetted record.
		return 0, false
	}

	// Verify the vetted tree exists. This should not fail.
	if !t.vetted.TreeExists(vettedTreeID) {
		// We're in trouble!
		e := fmt.Sprintf("freeze record of unvetted tree %v points to "+
			"an invalid vetted tree %v", unvettedTreeID, vettedTreeID)
		panic(e)
	}

	// Update the vetted cache
	t.vettedTreeIDAdd(hex.EncodeToString(token), vettedTreeID)

	return vettedTreeID, true
}

// verifyContent verifies that all provided MetadataStream and File are sane.
func verifyContent(metadata []backend.MetadataStream, files []backend.File, filesDel []string) error {
	// Make sure all metadata is within maxima.
	for _, v := range metadata {
		if v.ID > v1.MetadataStreamsMax-1 {
			return backend.ContentVerificationError{
				ErrorCode: v1.ErrorStatusInvalidMDID,
				ErrorContext: []string{
					strconv.FormatUint(v.ID, 10),
				},
			}
		}
	}
	for i := range metadata {
		for j := range metadata {
			// Skip self and non duplicates.
			if i == j || metadata[i].ID != metadata[j].ID {
				continue
			}
			return backend.ContentVerificationError{
				ErrorCode: v1.ErrorStatusDuplicateMDID,
				ErrorContext: []string{
					strconv.FormatUint(metadata[i].ID, 10),
				},
			}
		}
	}

	// Prevent paths
	for i := range files {
		if filepath.Base(files[i].Name) != files[i].Name {
			return backend.ContentVerificationError{
				ErrorCode: v1.ErrorStatusInvalidFilename,
				ErrorContext: []string{
					files[i].Name,
				},
			}
		}
	}
	for _, v := range filesDel {
		if filepath.Base(v) != v {
			return backend.ContentVerificationError{
				ErrorCode: v1.ErrorStatusInvalidFilename,
				ErrorContext: []string{
					v,
				},
			}
		}
	}

	// Now check files
	if len(files) == 0 {
		return backend.ContentVerificationError{
			ErrorCode: v1.ErrorStatusEmpty,
		}
	}

	// Prevent bad filenames and duplicate filenames
	for i := range files {
		for j := range files {
			if i == j {
				continue
			}
			if files[i].Name == files[j].Name {
				return backend.ContentVerificationError{
					ErrorCode: v1.ErrorStatusDuplicateFilename,
					ErrorContext: []string{
						files[i].Name,
					},
				}
			}
		}
		// Check against filesDel
		for _, v := range filesDel {
			if files[i].Name == v {
				return backend.ContentVerificationError{
					ErrorCode: v1.ErrorStatusDuplicateFilename,
					ErrorContext: []string{
						files[i].Name,
					},
				}
			}
		}
	}

	for i := range files {
		if gozaru.Sanitize(files[i].Name) != files[i].Name {
			return backend.ContentVerificationError{
				ErrorCode: v1.ErrorStatusInvalidFilename,
				ErrorContext: []string{
					files[i].Name,
				},
			}
		}

		// Validate digest
		d, ok := util.ConvertDigest(files[i].Digest)
		if !ok {
			return backend.ContentVerificationError{
				ErrorCode: v1.ErrorStatusInvalidFileDigest,
				ErrorContext: []string{
					files[i].Name,
				},
			}
		}

		// Decode base64 payload
		var err error
		payload, err := base64.StdEncoding.DecodeString(files[i].Payload)
		if err != nil {
			return backend.ContentVerificationError{
				ErrorCode: v1.ErrorStatusInvalidBase64,
				ErrorContext: []string{
					files[i].Name,
				},
			}
		}

		// Calculate payload digest
		dp := util.Digest(payload)
		if !bytes.Equal(d[:], dp) {
			return backend.ContentVerificationError{
				ErrorCode: v1.ErrorStatusInvalidFileDigest,
				ErrorContext: []string{
					files[i].Name,
				},
			}
		}

		// Verify MIME
		detectedMIMEType := mime.DetectMimeType(payload)
		if detectedMIMEType != files[i].MIME {
			return backend.ContentVerificationError{
				ErrorCode: v1.ErrorStatusInvalidMIMEType,
				ErrorContext: []string{
					files[i].Name,
					detectedMIMEType,
				},
			}
		}

		if !mime.MimeValid(files[i].MIME) {
			return backend.ContentVerificationError{
				ErrorCode: v1.ErrorStatusUnsupportedMIMEType,
				ErrorContext: []string{
					files[i].Name,
					files[i].MIME,
				},
			}
		}
	}

	return nil
}

var (
	// statusChanges contains the allowed record status changes. If
	// statusChanges[currentStatus][newStatus] exists then the status
	// change is allowed.
	//
	// Note, the tlog backend does not make use of the status
	// MDStatusIterationUnvetted. The original purpose of this status
	// was to show when an unvetted record had been altered since
	// unvetted records were not versioned in the git backend. The tlog
	// backend versions unvetted records and thus does not need to use
	// this additional status.
	statusChanges = map[backend.MDStatusT]map[backend.MDStatusT]struct{}{
		// Unvetted status changes
		backend.MDStatusUnvetted: {
			backend.MDStatusVetted:   {},
			backend.MDStatusCensored: {},
		},

		// Vetted status changes
		backend.MDStatusVetted: {
			backend.MDStatusCensored: {},
			backend.MDStatusArchived: {},
		},

		// Statuses that do not allow any further transitions
		backend.MDStatusCensored: {},
		backend.MDStatusArchived: {},
	}
)

// statusChangeIsAllowed returns whether the provided status change is allowed
// by tlogbe.
func statusChangeIsAllowed(from, to backend.MDStatusT) bool {
	allowed, ok := statusChanges[from]
	if !ok {
		return false
	}
	_, ok = allowed[to]
	return ok
}

func recordMetadataNew(token []byte, files []backend.File, status backend.MDStatusT, iteration uint64) (*backend.RecordMetadata, error) {
	m, err := pdutil.MerkleRoot(files)
	if err != nil {
		return nil, err
	}
	return &backend.RecordMetadata{
		Version:   backend.VersionRecordMD,
		Iteration: iteration,
		Status:    status,
		Merkle:    hex.EncodeToString(m[:]),
		Timestamp: time.Now().Unix(),
		Token:     hex.EncodeToString(token),
	}, nil
}

// TODO test this function
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

// TODO test this function
func metadataStreamsUpdate(curr, mdAppend, mdOverwrite []backend.MetadataStream) []backend.MetadataStream {
	// Put current metadata into a map
	md := make(map[uint64]backend.MetadataStream, len(curr))
	for _, v := range curr {
		md[v.ID] = v
	}

	// Apply overwrites
	for _, v := range mdOverwrite {
		md[v.ID] = v
	}

	// Apply appends. Its ok if an append is specified but there is no
	// existing metadata for that metadata stream. In this case the
	// append data will become the full metadata stream.
	for _, v := range mdAppend {
		m, ok := md[v.ID]
		if !ok {
			// No existing metadata. Use append data as full metadata
			// stream.
			md[v.ID] = v
			continue
		}

		// Metadata exists. Append to it.
		buf := bytes.NewBuffer([]byte(m.Payload))
		buf.WriteString(v.Payload)
		m.Payload = buf.String()
		md[v.ID] = m
	}

	// Convert metadata back to a slice
	metadata := make([]backend.MetadataStream, 0, len(md))
	for _, v := range md {
		metadata = append(metadata, v)
	}

	return metadata
}

func (t *tlogBackend) isShutdown() bool {
	t.RLock()
	defer t.RUnlock()

	return t.shutdown
}

// New submites a new record. Records are considered unvetted until their
// status is changed to a public status.
//
// This function satisfies the backend.Backend interface.
func (t *tlogBackend) New(metadata []backend.MetadataStream, files []backend.File) (*backend.RecordMetadata, error) {
	log.Tracef("New")

	// Validate record contents
	err := verifyContent(metadata, files, []string{})
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
	err = t.unvetted.PluginHookPre(0, []byte{},
		plugins.HookTypeNewRecordPre, string(b))
	if err != nil {
		return nil, err
	}

	// Create a new token
	var token []byte
	var treeID int64
	for retries := 0; retries < 10; retries++ {
		treeID, err = t.unvetted.TreeNew()
		if err != nil {
			return nil, err
		}
		token = tokenFromTreeID(treeID)

		// Check for token prefix collisions
		if !t.prefixExists(token) {
			// Not a collision. Use this token.

			// Update the prefix cache. This must be done even if the
			// record creation fails since the tree will still exist in
			// tlog.
			t.prefixAdd(token)

			break
		}

		log.Infof("Token prefix collision %v, creating new token",
			util.TokenPrefix(token))
	}

	// Create record metadata
	rm, err := recordMetadataNew(token, files, backend.MDStatusUnvetted, 1)
	if err != nil {
		return nil, err
	}

	// Save the record
	err = t.unvetted.RecordSave(treeID, *rm, metadata, files)
	if err != nil {
		return nil, fmt.Errorf("RecordSave %x: %v", token, err)
	}

	// Call post plugin hooks
	post := plugins.HookNewRecordPost{
		Metadata:       metadata,
		Files:          files,
		RecordMetadata: rm,
	}
	b, err = json.Marshal(post)
	if err != nil {
		return nil, err
	}
	t.unvetted.PluginHookPost(treeID, token,
		plugins.HookTypeNewRecordPost, string(b))

	// Update the inventory cache
	t.inventoryAdd(stateUnvetted, token, backend.MDStatusUnvetted)

	return rm, nil
}

// This function satisfies the backend.Backend interface.
func (t *tlogBackend) UpdateUnvettedRecord(token []byte, mdAppend, mdOverwrite []backend.MetadataStream, filesAdd []backend.File, filesDel []string) (*backend.Record, error) {
	log.Tracef("UpdateUnvettedRecord: %x", token)

	// Validate record contents. Send in a single metadata array to
	// verify there are no dups.
	allMD := append(mdAppend, mdOverwrite...)
	err := verifyContent(allMD, filesAdd, filesDel)
	if err != nil {
		var cve backend.ContentVerificationError
		if !errors.As(err, &cve) {
			return nil, err
		}
		// Allow ErrorStatusEmpty which indicates no new files are being
		// added. This can happen when files are being deleted without
		// any new files being added.
		if cve.ErrorCode != v1.ErrorStatusEmpty {
			return nil, err
		}
	}

	// Verify token is valid. The full length token must be used when
	// writing data.
	if !tokenIsFullLength(token) {
		return nil, backend.ContentVerificationError{
			ErrorCode: v1.ErrorStatusInvalidToken,
		}
	}

	// Verify record exists and is unvetted
	if !t.UnvettedExists(token) {
		return nil, backend.ErrRecordNotFound
	}

	// Apply the record changes and save the new version. The lock
	// needs to be held for the remainder of the function.
	t.unvetted.Lock()
	defer t.unvetted.Unlock()
	if t.shutdown {
		return nil, backend.ErrShutdown
	}

	// Get existing record
	treeID := treeIDFromToken(token)
	r, err := t.unvetted.RecordLatest(treeID)
	if err != nil {
		return nil, fmt.Errorf("RecordLatest: %v", err)
	}

	// Apply changes
	metadata := metadataStreamsUpdate(r.Metadata, mdAppend, mdOverwrite)
	files := filesUpdate(r.Files, filesAdd, filesDel)

	// Create record metadata
	recordMD, err := recordMetadataNew(token, files,
		backend.MDStatusUnvetted, r.RecordMetadata.Iteration+1)
	if err != nil {
		return nil, err
	}

	// Call pre plugin hooks
	her := plugins.HookEditRecord{
		State:          plugins.RecordStateUnvetted,
		Current:        *r,
		RecordMetadata: *recordMD,
		Metadata:       metadata,
		Files:          files,
	}
	b, err := json.Marshal(her)
	if err != nil {
		return nil, err
	}
	err = t.unvetted.PluginHookPre(treeID, token,
		plugins.HookTypeEditRecordPre, string(b))
	if err != nil {
		return nil, err
	}

	// Save record
	err = t.unvetted.RecordSave(treeID, *recordMD, metadata, files)
	if err != nil {
		switch err {
		case backend.ErrRecordLocked, backend.ErrNoChanges:
			return nil, err
		default:
			return nil, fmt.Errorf("RecordSave: %v", err)
		}
	}

	// Call post plugin hooks
	t.unvetted.PluginHookPost(treeID, token,
		plugins.HookTypeEditRecordPost, string(b))

	// Return updated record
	r, err = t.unvetted.RecordLatest(treeID)
	if err != nil {
		return nil, fmt.Errorf("RecordLatest: %v", err)
	}

	return r, nil
}

// This function satisfies the backend.Backend interface.
func (t *tlogBackend) UpdateVettedRecord(token []byte, mdAppend, mdOverwrite []backend.MetadataStream, filesAdd []backend.File, filesDel []string) (*backend.Record, error) {
	log.Tracef("UpdateVettedRecord: %x", token)

	// Validate record contents. Send in a single metadata array to
	// verify there are no dups.
	allMD := append(mdAppend, mdOverwrite...)
	err := verifyContent(allMD, filesAdd, filesDel)
	if err != nil {
		var cve backend.ContentVerificationError
		if !errors.As(err, &cve) {
			return nil, err
		}
		// Allow ErrorStatusEmpty which indicates no new files are being
		// added. This can happen when files are being deleted without
		// any new files being added.
		if cve.ErrorCode != v1.ErrorStatusEmpty {
			return nil, err
		}
	}

	// Verify token is valid. The full length token must be used when
	// writing data.
	if !tokenIsFullLength(token) {
		return nil, backend.ContentVerificationError{
			ErrorCode: v1.ErrorStatusInvalidToken,
		}
	}

	// Get vetted tree ID
	treeID, ok := t.vettedTreeIDFromToken(token)
	if !ok {
		return nil, backend.ErrRecordNotFound
	}

	// Apply the record changes and save the new version. The lock
	// needs to be held for the remainder of the function.
	t.vetted.Lock()
	defer t.vetted.Unlock()
	if t.shutdown {
		return nil, backend.ErrShutdown
	}

	// Get existing record
	r, err := t.vetted.RecordLatest(treeID)
	if err != nil {
		return nil, fmt.Errorf("RecordLatest: %v", err)
	}

	// Apply changes
	metadata := metadataStreamsUpdate(r.Metadata, mdAppend, mdOverwrite)
	files := filesUpdate(r.Files, filesAdd, filesDel)

	// Create record metadata
	recordMD, err := recordMetadataNew(token, files,
		r.RecordMetadata.Status, r.RecordMetadata.Iteration+1)
	if err != nil {
		return nil, err
	}

	// Call pre plugin hooks
	her := plugins.HookEditRecord{
		State:          plugins.RecordStateVetted,
		Current:        *r,
		RecordMetadata: *recordMD,
		Metadata:       metadata,
		Files:          files,
	}
	b, err := json.Marshal(her)
	if err != nil {
		return nil, err
	}
	err = t.vetted.PluginHookPre(treeID, token,
		plugins.HookTypeEditRecordPre, string(b))
	if err != nil {
		return nil, err
	}

	// Save record
	err = t.vetted.RecordSave(treeID, *recordMD, metadata, files)
	if err != nil {
		switch err {
		case backend.ErrRecordLocked, backend.ErrNoChanges:
			return nil, err
		default:
			return nil, fmt.Errorf("RecordSave: %v", err)
		}
	}

	// Call post plugin hooks
	t.vetted.PluginHookPost(treeID, token,
		plugins.HookTypeEditRecordPost, string(b))

	// Return updated record
	r, err = t.vetted.RecordLatest(treeID)
	if err != nil {
		return nil, fmt.Errorf("RecordLatest: %v", err)
	}

	return r, nil
}

// This function satisfies the backend.Backend interface.
func (t *tlogBackend) UpdateUnvettedMetadata(token []byte, mdAppend, mdOverwrite []backend.MetadataStream) error {
	// Validate record contents. Send in a single metadata array to
	// verify there are no dups.
	allMD := append(mdAppend, mdOverwrite...)
	err := verifyContent(allMD, []backend.File{}, []string{})
	if err != nil {
		var cve backend.ContentVerificationError
		if !errors.As(err, &cve) {
			return err
		}
		// Allow ErrorStatusEmpty which indicates no new files are being
		// being added. This is expected since this is a metadata only
		// update.
		if cve.ErrorCode != v1.ErrorStatusEmpty {
			return err
		}
	}
	if len(mdAppend) == 0 && len(mdOverwrite) == 0 {
		return backend.ContentVerificationError{
			ErrorCode: v1.ErrorStatusNoChanges,
		}
	}

	// Verify token is valid. The full length token must be used when
	// writing data.
	if !tokenIsFullLength(token) {
		return backend.ContentVerificationError{
			ErrorCode: v1.ErrorStatusInvalidToken,
		}
	}

	// Verify record exists and is unvetted
	if !t.UnvettedExists(token) {
		return backend.ErrRecordNotFound
	}

	// Pull the existing record and apply the metadata updates. The
	// unvetted lock must be held for the remainder of this function.
	t.unvetted.Lock()
	defer t.unvetted.Unlock()
	if t.shutdown {
		return backend.ErrShutdown
	}

	// Get existing record
	treeID := treeIDFromToken(token)
	r, err := t.unvetted.RecordLatest(treeID)
	if err != nil {
		return fmt.Errorf("RecordLatest: %v", err)
	}

	// Call pre plugin hooks
	hem := plugins.HookEditMetadata{
		State:       plugins.RecordStateUnvetted,
		Current:     *r,
		MDAppend:    mdAppend,
		MDOverwrite: mdOverwrite,
	}
	b, err := json.Marshal(hem)
	if err != nil {
		return err
	}
	err = t.unvetted.PluginHookPre(treeID, token,
		plugins.HookTypeEditMetadataPre, string(b))
	if err != nil {
		return err
	}

	// Apply changes
	metadata := metadataStreamsUpdate(r.Metadata, mdAppend, mdOverwrite)

	// Update metadata
	err = t.unvetted.RecordMetadataSave(treeID, r.RecordMetadata, metadata)
	if err != nil {
		switch err {
		case backend.ErrRecordLocked, backend.ErrNoChanges:
			return err
		default:
			return fmt.Errorf("RecordMetadataSave: %v", err)
		}
	}

	// Call post plugin hooks
	t.unvetted.PluginHookPost(treeID, token,
		plugins.HookTypeEditMetadataPost, string(b))

	return nil
}

// This function satisfies the backend.Backend interface.
func (t *tlogBackend) UpdateVettedMetadata(token []byte, mdAppend, mdOverwrite []backend.MetadataStream) error {
	log.Tracef("UpdateVettedMetadata: %x", token)

	// Validate record contents. Send in a single metadata array to
	// verify there are no dups.
	allMD := append(mdAppend, mdOverwrite...)
	err := verifyContent(allMD, []backend.File{}, []string{})
	if err != nil {
		var cve backend.ContentVerificationError
		if !errors.As(err, &cve) {
			return err
		}
		// Allow ErrorStatusEmpty which indicates no new files are being
		// being added. This is expected since this is a metadata only
		// update.
		if cve.ErrorCode != v1.ErrorStatusEmpty {
			return err
		}
	}
	if len(mdAppend) == 0 && len(mdOverwrite) == 0 {
		return backend.ContentVerificationError{
			ErrorCode: v1.ErrorStatusNoChanges,
		}
	}

	// Verify token is valid. The full length token must be used when
	// writing data.
	if !tokenIsFullLength(token) {
		return backend.ContentVerificationError{
			ErrorCode: v1.ErrorStatusInvalidToken,
		}
	}

	// Get vetted tree ID
	treeID, ok := t.vettedTreeIDFromToken(token)
	if !ok {
		return backend.ErrRecordNotFound
	}

	// Pull the existing record and apply the metadata updates. The
	// vetted lock must be held for the remainder of this function.
	t.vetted.Lock()
	defer t.vetted.Unlock()
	if t.shutdown {
		return backend.ErrShutdown
	}

	// Get existing record
	r, err := t.vetted.RecordLatest(treeID)
	if err != nil {
		return fmt.Errorf("RecordLatest: %v", err)
	}

	// Call pre plugin hooks
	hem := plugins.HookEditMetadata{
		State:       plugins.RecordStateVetted,
		Current:     *r,
		MDAppend:    mdAppend,
		MDOverwrite: mdOverwrite,
	}
	b, err := json.Marshal(hem)
	if err != nil {
		return err
	}
	err = t.vetted.PluginHookPre(treeID, token,
		plugins.HookTypeEditMetadataPre, string(b))
	if err != nil {
		return err
	}

	// Apply changes
	metadata := metadataStreamsUpdate(r.Metadata, mdAppend, mdOverwrite)

	// Update metadata
	err = t.vetted.RecordMetadataSave(treeID, r.RecordMetadata, metadata)
	if err != nil {
		switch err {
		case backend.ErrRecordLocked, backend.ErrNoChanges:
			return err
		default:
			return fmt.Errorf("RecordMetadataSave: %v", err)
		}
	}

	// Call post plugin hooks
	t.vetted.PluginHookPost(treeID, token,
		plugins.HookTypeEditMetadataPost, string(b))

	return nil
}

// UnvettedExists returns whether the provided token corresponds to an unvetted
// record.
//
// This function satisfies the backend.Backend interface.
func (t *tlogBackend) UnvettedExists(token []byte) bool {
	log.Tracef("UnvettedExists %x", token)

	// Verify token is not in the vetted tree IDs cache. If it is then
	// we can be sure that this is not a unvetted record without having
	// to send any network requests.
	_, ok := t.vettedTreeID(token)
	if ok {
		return false
	}

	// Check for unvetted record
	treeID := t.unvettedTreeIDFromToken(token)
	return t.unvetted.RecordExists(treeID)
}

// This function satisfies the backend.Backend interface.
func (t *tlogBackend) VettedExists(token []byte) bool {
	log.Tracef("VettedExists %x", token)

	_, ok := t.vettedTreeIDFromToken(token)
	return ok
}

// This function must be called WITH the unvetted lock held.
func (t *tlogBackend) unvettedPublish(token []byte, rm backend.RecordMetadata, metadata []backend.MetadataStream, files []backend.File) error {
	// Create a vetted tree
	vettedTreeID, err := t.vetted.TreeNew()
	if err != nil {
		return err
	}

	// Save the record to the vetted tlog
	err = t.vetted.RecordSave(vettedTreeID, rm, metadata, files)
	if err != nil {
		return fmt.Errorf("vetted RecordSave: %v", err)
	}

	log.Debugf("Unvetted record %x copied to vetted tree %v",
		token, vettedTreeID)

	// Freeze the unvetted tree
	treeID := treeIDFromToken(token)
	err = t.unvetted.TreeFreeze(treeID, rm, metadata, vettedTreeID)
	if err != nil {
		return fmt.Errorf("TreeFreeze %v: %v", treeID, err)
	}

	log.Debugf("Unvetted record frozen %x", token)

	// Update the vetted cache
	t.vettedTreeIDAdd(hex.EncodeToString(token), vettedTreeID)

	return nil
}

// This function must be called WITH the unvetted lock held.
func (t *tlogBackend) unvettedCensor(token []byte, rm backend.RecordMetadata, metadata []backend.MetadataStream) error {
	// Freeze the tree
	treeID := treeIDFromToken(token)
	err := t.unvetted.TreeFreeze(treeID, rm, metadata, 0)
	if err != nil {
		return fmt.Errorf("TreeFreeze %v: %v", treeID, err)
	}

	log.Debugf("Unvetted record frozen %x", token)

	// Delete all record files
	err = t.unvetted.RecordDel(treeID)
	if err != nil {
		return fmt.Errorf("RecordDel %v: %v", treeID, err)
	}

	log.Debugf("Unvetted record files deleted %x", token)

	return nil
}

func (t *tlogBackend) SetUnvettedStatus(token []byte, status backend.MDStatusT, mdAppend, mdOverwrite []backend.MetadataStream) (*backend.Record, error) {
	log.Tracef("SetUnvettedStatus: %x %v (%v)",
		token, status, backend.MDStatus[status])

	// Verify token is valid. The full length token must be used when
	// writing data.
	if !tokenIsFullLength(token) {
		return nil, backend.ContentVerificationError{
			ErrorCode: v1.ErrorStatusInvalidToken,
		}
	}

	// Verify record exists and is unvetted
	if !t.UnvettedExists(token) {
		return nil, backend.ErrRecordNotFound
	}

	// The existing record must be pulled and updated. The unvetted
	// lock must be held for the rest of this function.
	t.unvetted.Lock()
	defer t.unvetted.Unlock()
	if t.shutdown {
		return nil, backend.ErrShutdown
	}

	// Get existing record
	treeID := treeIDFromToken(token)
	r, err := t.unvetted.RecordLatest(treeID)
	if err != nil {
		return nil, fmt.Errorf("RecordLatest: %v", err)
	}
	rm := r.RecordMetadata
	currStatus := rm.Status

	// Validate status change
	if !statusChangeIsAllowed(currStatus, status) {
		return nil, backend.StateTransitionError{
			From: currStatus,
			To:   status,
		}
	}

	// Apply status change
	rm.Status = status
	rm.Iteration += 1
	rm.Timestamp = time.Now().Unix()

	// Apply metadata changes
	metadata := metadataStreamsUpdate(r.Metadata, mdAppend, mdOverwrite)

	// Call pre plugin hooks
	hsrs := plugins.HookSetRecordStatus{
		State:          plugins.RecordStateUnvetted,
		Current:        *r,
		RecordMetadata: rm,
		Metadata:       metadata,
	}
	b, err := json.Marshal(hsrs)
	if err != nil {
		return nil, err
	}
	err = t.unvetted.PluginHookPre(treeID, token,
		plugins.HookTypeSetRecordStatusPre, string(b))
	if err != nil {
		return nil, err
	}

	// Update record
	switch status {
	case backend.MDStatusVetted:
		err := t.unvettedPublish(token, rm, metadata, r.Files)
		if err != nil {
			return nil, fmt.Errorf("unvettedPublish: %v", err)
		}
	case backend.MDStatusCensored:
		err := t.unvettedCensor(token, rm, metadata)
		if err != nil {
			return nil, fmt.Errorf("unvettedCensor: %v", err)
		}
	default:
		return nil, fmt.Errorf("unknown status: %v (%v)",
			backend.MDStatus[status], status)
	}

	// Call post plugin hooks
	t.unvetted.PluginHookPost(treeID, token,
		plugins.HookTypeSetRecordStatusPost, string(b))

	log.Debugf("Status change %x from %v (%v) to %v (%v)",
		token, backend.MDStatus[currStatus], currStatus,
		backend.MDStatus[status], status)

	// Update inventory cache
	if status == backend.MDStatusVetted {
		// Record was made public
		t.inventoryMoveToVetted(token, currStatus, status)
	} else {
		// All other status changes
		t.inventoryUpdate(stateUnvetted, token, currStatus, status)
	}

	// Return the updated record. If the record was made public it is
	// now a vetted record and must be fetched accordingly.
	if status == backend.MDStatusVetted {
		return t.GetVetted(token, "")
	}

	return t.GetUnvetted(token, "")
}

// This function must be called WITH the vetted lock held.
func (t *tlogBackend) vettedCensor(token []byte, rm backend.RecordMetadata, metadata []backend.MetadataStream) error {
	// Freeze the tree
	treeID, ok := t.vettedTreeID(token)
	if !ok {
		return fmt.Errorf("vetted record not found")
	}
	err := t.vetted.TreeFreeze(treeID, rm, metadata, 0)
	if err != nil {
		return fmt.Errorf("TreeFreeze %v: %v", treeID, err)
	}

	log.Debugf("Vetted record frozen %x", token)

	// Delete all record files
	err = t.vetted.RecordDel(treeID)
	if err != nil {
		return fmt.Errorf("RecordDel %v: %v", treeID, err)
	}

	log.Debugf("Vetted record files deleted %x", token)

	return nil
}

// This function must be called WITH the vetted lock held.
func (t *tlogBackend) vettedArchive(token []byte, rm backend.RecordMetadata, metadata []backend.MetadataStream) error {
	// Freeze the tree. Nothing else needs to be done for an archived
	// record.
	treeID, ok := t.vettedTreeID(token)
	if !ok {
		return fmt.Errorf("vetted record not found")
	}
	err := t.vetted.TreeFreeze(treeID, rm, metadata, 0)
	if err != nil {
		return fmt.Errorf("TreeFreeze %v: %v", treeID, err)
	}

	log.Debugf("Vetted record frozen %x", token)

	return nil
}

// This function satisfies the backend.Backend interface.
func (t *tlogBackend) SetVettedStatus(token []byte, status backend.MDStatusT, mdAppend, mdOverwrite []backend.MetadataStream) (*backend.Record, error) {
	log.Tracef("SetVettedStatus: %x %v (%v)",
		token, status, backend.MDStatus[status])

	// Verify token is valid. The full length token must be used when
	// writing data.
	if !tokenIsFullLength(token) {
		return nil, backend.ContentVerificationError{
			ErrorCode: v1.ErrorStatusInvalidToken,
		}
	}

	// Get vetted tree ID
	treeID, ok := t.vettedTreeIDFromToken(token)
	if !ok {
		return nil, backend.ErrRecordNotFound
	}

	// The existing record must be pulled and updated. The vetted lock
	// must be held for the rest of this function.
	t.vetted.Lock()
	defer t.vetted.Unlock()
	if t.shutdown {
		return nil, backend.ErrShutdown
	}

	// Get existing record
	r, err := t.vetted.RecordLatest(treeID)
	if err != nil {
		return nil, fmt.Errorf("RecordLatest: %v", err)
	}
	rm := r.RecordMetadata
	currStatus := rm.Status

	// Validate status change
	if !statusChangeIsAllowed(rm.Status, status) {
		return nil, backend.StateTransitionError{
			From: currStatus,
			To:   status,
		}
	}

	// Apply status change
	rm.Status = status
	rm.Iteration += 1
	rm.Timestamp = time.Now().Unix()

	// Apply metdata changes
	metadata := metadataStreamsUpdate(r.Metadata, mdAppend, mdOverwrite)

	// Call pre plugin hooks
	srs := plugins.HookSetRecordStatus{
		State:          plugins.RecordStateVetted,
		Current:        *r,
		RecordMetadata: rm,
		Metadata:       metadata,
	}
	b, err := json.Marshal(srs)
	if err != nil {
		return nil, err
	}
	err = t.vetted.PluginHookPre(treeID, token,
		plugins.HookTypeSetRecordStatusPre, string(b))
	if err != nil {
		return nil, err
	}

	// Update record
	switch status {
	case backend.MDStatusCensored:
		err := t.vettedCensor(token, rm, metadata)
		if err != nil {
			return nil, fmt.Errorf("vettedCensor: %v", err)
		}
	case backend.MDStatusArchived:
		err := t.vettedArchive(token, rm, metadata)
		if err != nil {
			return nil, fmt.Errorf("vettedArchive: %v", err)
		}
	default:
		return nil, fmt.Errorf("unknown status: %v (%v)",
			backend.MDStatus[status], status)
	}

	// Call post plugin hooks
	t.vetted.PluginHookPost(treeID, token,
		plugins.HookTypeSetRecordStatusPost, string(b))

	// Update inventory cache
	t.inventoryUpdate(stateVetted, token, currStatus, status)

	log.Debugf("Status change %x from %v (%v) to %v (%v)",
		token, backend.MDStatus[currStatus], currStatus,
		backend.MDStatus[status], status)

	// Return the updated record
	r, err = t.vetted.RecordLatest(treeID)
	if err != nil {
		return nil, fmt.Errorf("RecordLatest: %v", err)
	}

	return r, nil
}

// This function satisfies the backend.Backend interface.
func (t *tlogBackend) GetUnvetted(token []byte, version string) (*backend.Record, error) {
	log.Tracef("GetUnvetted: %x %v", token, version)

	if t.isShutdown() {
		return nil, backend.ErrShutdown
	}

	treeID := t.unvettedTreeIDFromToken(token)
	var v uint32
	if version != "" {
		u, err := strconv.ParseUint(version, 10, 64)
		if err != nil {
			return nil, backend.ErrRecordNotFound
		}
		v = uint32(u)
	}

	// Verify record exists and is unvetted
	if !t.UnvettedExists(token) {
		return nil, backend.ErrRecordNotFound
	}

	// Get unvetted record
	r, err := t.unvetted.Record(treeID, v)
	if err != nil {
		return nil, fmt.Errorf("unvetted record: %v", err)
	}

	return r, nil
}

// This function satisfies the backend.Backend interface.
func (t *tlogBackend) GetVetted(token []byte, version string) (*backend.Record, error) {
	log.Tracef("GetVetted: %x %v", token, version)

	if t.isShutdown() {
		return nil, backend.ErrShutdown
	}

	// Get tree ID
	treeID, ok := t.vettedTreeIDFromToken(token)
	if !ok {
		return nil, backend.ErrRecordNotFound
	}

	// Parse version
	var v uint32
	if version != "" {
		u, err := strconv.ParseUint(version, 10, 64)
		if err != nil {
			return nil, backend.ErrRecordNotFound
		}
		v = uint32(u)
	}

	r, err := t.vetted.Record(treeID, v)
	if err != nil {
		return nil, err
	}

	return r, nil
}

// This function satisfies the backend.Backend interface.
func (t *tlogBackend) GetUnvettedTimestamps(token []byte, version string) (*backend.RecordTimestamps, error) {
	log.Tracef("GetUnvettedTimestamps: %x %v", token, version)

	if t.isShutdown() {
		return nil, backend.ErrShutdown
	}

	treeID := t.unvettedTreeIDFromToken(token)
	var v uint32
	if version != "" {
		u, err := strconv.ParseUint(version, 10, 64)
		if err != nil {
			return nil, backend.ErrRecordNotFound
		}
		v = uint32(u)
	}

	// Verify record exists and is unvetted
	if !t.UnvettedExists(token) {
		return nil, backend.ErrRecordNotFound
	}

	// Get timestamps
	return t.unvetted.RecordTimestamps(treeID, v, token)
}

// This function satisfies the backend.Backend interface.
func (t *tlogBackend) GetVettedTimestamps(token []byte, version string) (*backend.RecordTimestamps, error) {
	log.Tracef("GetVettedTimestamps: %x %v", token, version)

	if t.isShutdown() {
		return nil, backend.ErrShutdown
	}

	// Get tree ID
	treeID, ok := t.vettedTreeIDFromToken(token)
	if !ok {
		return nil, backend.ErrRecordNotFound
	}

	// Parse version
	var v uint32
	if version != "" {
		u, err := strconv.ParseUint(version, 10, 64)
		if err != nil {
			return nil, backend.ErrRecordNotFound
		}
		v = uint32(u)
	}

	// Get timestamps
	return t.vetted.RecordTimestamps(treeID, v, token)
}

// InventoryByStatus returns the record tokens of all records in the inventory
// categorized by MDStatusT.
//
// This function satisfies the backend.Backend interface.
func (t *tlogBackend) InventoryByStatus() (*backend.InventoryByStatus, error) {
	log.Tracef("InventoryByStatus")

	inv := t.inventory()
	return &backend.InventoryByStatus{
		Unvetted: inv.unvetted,
		Vetted:   inv.vetted,
	}, nil
}

// RegisterUnvettedPlugin registers a plugin with the unvetted tlog instance.
//
// This function satisfies the backend.Backend interface.
func (t *tlogBackend) RegisterUnvettedPlugin(p backend.Plugin) error {
	log.Tracef("RegisterUnvettedPlugin: %v", p.ID)

	if t.isShutdown() {
		return backend.ErrShutdown
	}

	return t.unvetted.PluginRegister(t, p)
}

// RegisterVettedPlugin has not been implemented.
//
// This function satisfies the backend.Backend interface.
func (t *tlogBackend) RegisterVettedPlugin(p backend.Plugin) error {
	log.Tracef("RegisterVettedPlugin: %v", p.ID)

	if t.isShutdown() {
		return backend.ErrShutdown
	}

	return t.vetted.PluginRegister(t, p)
}

// SetupUnvettedPlugin performs plugin setup for a previously registered
// unvetted plugin.
//
// This function satisfies the backend.Backend interface.
func (t *tlogBackend) SetupUnvettedPlugin(pluginID string) error {
	log.Tracef("SetupUnvettedPlugin: %v", pluginID)

	if t.isShutdown() {
		return backend.ErrShutdown
	}

	return t.unvetted.PluginSetup(pluginID)
}

// SetupVettedPlugin performs plugin setup for a previously registered vetted
// plugin.
//
// This function satisfies the backend.Backend interface.
func (t *tlogBackend) SetupVettedPlugin(pluginID string) error {
	log.Tracef("SetupVettedPlugin: %v", pluginID)

	if t.isShutdown() {
		return backend.ErrShutdown
	}

	return t.vetted.PluginSetup(pluginID)
}

// UnvettedPluginCmd executes a plugin command on an unvetted record.
//
// This function satisfies the backend.Backend interface.
func (t *tlogBackend) UnvettedPluginCmd(token []byte, pluginID, cmd, payload string) (string, error) {
	log.Tracef("UnvettedPluginCmd: %x %v %v", token, pluginID, cmd)

	if t.isShutdown() {
		return "", backend.ErrShutdown
	}

	// The token is optional. If a token is not provided then a tree ID
	// will not be provided to the plugin.
	var treeID int64
	if token != nil {
		// Get tree ID
		treeID = t.unvettedTreeIDFromToken(token)

		// Verify record exists and is unvetted
		if !t.UnvettedExists(token) {
			return "", backend.ErrRecordNotFound
		}
	}

	// Call pre plugin hooks
	hp := plugins.HookPluginPre{
		State:    plugins.RecordStateUnvetted,
		PluginID: pluginID,
		Cmd:      cmd,
		Payload:  payload,
	}
	b, err := json.Marshal(hp)
	if err != nil {
		return "", err
	}
	err = t.unvetted.PluginHookPre(treeID, token,
		plugins.HookTypePluginPre, string(b))
	if err != nil {
		return "", err
	}

	reply, err := t.unvetted.PluginCmd(treeID, token, pluginID, cmd, payload)
	if err != nil {
		return "", err
	}

	// Call post plugin hooks
	hpp := plugins.HookPluginPost{
		State:    plugins.RecordStateUnvetted,
		PluginID: pluginID,
		Cmd:      cmd,
		Payload:  payload,
		Reply:    reply,
	}
	b, err = json.Marshal(hpp)
	if err != nil {
		return "", err
	}
	t.unvetted.PluginHookPost(treeID, token,
		plugins.HookTypePluginPost, string(b))

	return reply, nil
}

// VettedPluginCmd executes a plugin command on an unvetted record.
//
// This function satisfies the backend.Backend interface.
func (t *tlogBackend) VettedPluginCmd(token []byte, pluginID, cmd, payload string) (string, error) {
	log.Tracef("VettedPluginCmd: %x %v %v", token, pluginID, cmd)

	if t.isShutdown() {
		return "", backend.ErrShutdown
	}

	// The token is optional. If a token is not provided then a tree ID
	// will not be provided to the plugin.
	var treeID int64
	var ok bool
	if token != nil {
		// Get tree ID
		treeID, ok = t.vettedTreeIDFromToken(token)
		if !ok {
			return "", backend.ErrRecordNotFound
		}
	}

	// Call pre plugin hooks
	hp := plugins.HookPluginPre{
		State:    plugins.RecordStateVetted,
		PluginID: pluginID,
		Cmd:      cmd,
		Payload:  payload,
	}
	b, err := json.Marshal(hp)
	if err != nil {
		return "", err
	}
	err = t.vetted.PluginHookPre(treeID, token,
		plugins.HookTypePluginPre, string(b))
	if err != nil {
		return "", err
	}

	// Execute plugin command
	reply, err := t.vetted.PluginCmd(treeID, token, pluginID, cmd, payload)
	if err != nil {
		return "", err
	}

	// Call post plugin hooks
	hpp := plugins.HookPluginPost{
		State:    plugins.RecordStateVetted,
		PluginID: pluginID,
		Cmd:      cmd,
		Payload:  payload,
		Reply:    reply,
	}
	b, err = json.Marshal(hpp)
	if err != nil {
		return "", err
	}
	t.vetted.PluginHookPost(treeID, token,
		plugins.HookTypePluginPost, string(b))

	return reply, nil
}

// GetUnvettedPlugins returns the unvetted plugins that have been registered.
//
// This function satisfies the backend.Backend interface.
func (t *tlogBackend) GetUnvettedPlugins() []backend.Plugin {
	log.Tracef("GetUnvettedPlugins")

	return t.unvetted.Plugins()
}

// GetVettedPlugins returns the vetted plugins that have been registered.
//
// This function satisfies the backend.Backend interface.
func (t *tlogBackend) GetVettedPlugins() []backend.Plugin {
	log.Tracef("GetVettedPlugins")

	return t.vetted.Plugins()
}

// Inventory has been DEPRECATED.
//
// This function satisfies the backend.Backend interface.
func (t *tlogBackend) Inventory(vettedCount, vettedStart, unvettedCount uint, includeFiles, allVersions bool) ([]backend.Record, []backend.Record, error) {
	return nil, nil, fmt.Errorf("not implemented")
}

// GetPlugins has been DEPRECATED.
//
// This function satisfies the backend.Backend interface.
func (t *tlogBackend) GetPlugins() ([]backend.Plugin, error) {
	return nil, fmt.Errorf("not implemented")
}

// Plugin has been DEPRECATED.
//
// This function satisfies the backend.Backend interface.
func (t *tlogBackend) Plugin(pluginID, cmd, cmdID, payload string) (string, error) {
	return "", fmt.Errorf("not implemented")
}

// Close shuts the backend down and performs cleanup.
//
// This function satisfies the backend.Backend interface.
func (t *tlogBackend) Close() {
	log.Tracef("Close")

	t.Lock()
	defer t.Unlock()

	// Shutdown backend
	t.shutdown = true

	// Close tlog connections
	t.unvetted.Close()
	t.vetted.Close()
}

// setup creates the tlog backend caches.
func (t *tlogBackend) setup() error {
	log.Tracef("setup")

	// Get all trees
	treeIDs, err := t.unvetted.TreesAll()
	if err != nil {
		return fmt.Errorf("unvetted TreesAll: %v", err)
	}

	log.Infof("Building backend caches")

	// Build all memory caches
	for _, v := range treeIDs {
		token := tokenFromTreeID(v)

		log.Debugf("Building memory caches for %x", token)

		// Add tree to prefixes cache
		t.prefixAdd(token)

		// Identify whether the record is unvetted or vetted.
		isUnvetted := t.UnvettedExists(token)
		isVetted := t.VettedExists(token)

		// Get the record
		var r *backend.Record
		switch {
		case isUnvetted && isVetted:
			// Sanity check
			e := fmt.Sprintf("records is both unvetted and vetted: %x", token)
			panic(e)

		case isUnvetted:
			// Get unvetted record
			r, err = t.GetUnvetted(token, "")
			if err != nil {
				return fmt.Errorf("GetUnvetted %x: %v", token, err)
			}

			// Add record to the inventory cache
			t.inventoryAdd(stateUnvetted, token, r.RecordMetadata.Status)

		case isVetted:
			// Get vetted record
			r, err = t.GetVetted(token, "")
			if err != nil {
				return fmt.Errorf("GetUnvetted %x: %v", token, err)
			}

			// Add record to the inventory cache
			t.inventoryAdd(stateVetted, token, r.RecordMetadata.Status)

		default:
			// This is an empty tree. This can happen if there was an error
			// during record creation and the record failed to be appended
			// to the tree.
			log.Debugf("Empty tree found for token %x", token)
		}

	}

	return nil
}

// New returns a new tlogBackend.
func New(anp *chaincfg.Params, homeDir, dataDir, unvettedTrillianHost, unvettedTrillianKeyFile, vettedTrillianHost, vettedTrillianKeyFile, encryptionKeyFile, dcrtimeHost, dcrtimeCert string) (*tlogBackend, error) {
	// Setup encryption key file
	if encryptionKeyFile == "" {
		// No file path was given. Use the default path.
		encryptionKeyFile = filepath.Join(homeDir, defaultEncryptionKeyFilename)
	}
	if !util.FileExists(encryptionKeyFile) {
		// Encryption key file does not exist. Create one.
		log.Infof("Generating encryption key")
		key, err := sbox.NewKey()
		if err != nil {
			return nil, err
		}
		err = ioutil.WriteFile(encryptionKeyFile, key[:], 0400)
		if err != nil {
			return nil, err
		}
		util.Zero(key[:])
		log.Infof("Encryption key created: %v", encryptionKeyFile)
	}

	// Verify dcrtime host
	_, err := url.Parse(dcrtimeHost)
	if err != nil {
		return nil, fmt.Errorf("parse dcrtime host '%v': %v", dcrtimeHost, err)
	}
	log.Infof("Anchor host: %v", dcrtimeHost)

	// Setup tlog instances
	unvetted, err := tlog.New(tlogIDUnvetted, homeDir, dataDir, anp,
		unvettedTrillianHost, unvettedTrillianKeyFile, encryptionKeyFile,
		dcrtimeHost, dcrtimeCert)
	if err != nil {
		return nil, fmt.Errorf("new tlog unvetted: %v", err)
	}
	vetted, err := tlog.New(tlogIDVetted, homeDir, dataDir, anp,
		vettedTrillianHost, vettedTrillianKeyFile, "",
		dcrtimeHost, dcrtimeCert)
	if err != nil {
		return nil, fmt.Errorf("new tlog vetted: %v", err)
	}

	// Setup tlogbe
	t := tlogBackend{
		activeNetParams: anp,
		homeDir:         homeDir,
		dataDir:         dataDir,
		unvetted:        unvetted,
		vetted:          vetted,
		prefixes:        make(map[string][]byte),
		vettedTreeIDs:   make(map[string]int64),
		inv: inventory{
			unvetted: make(map[backend.MDStatusT][]string),
			vetted:   make(map[backend.MDStatusT][]string),
		},
	}

	err = t.setup()
	if err != nil {
		return nil, fmt.Errorf("setup: %v", err)
	}

	return &t, nil
}
