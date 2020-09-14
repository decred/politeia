// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlogbe

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/url"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/decred/dcrtime/merkle"
	pd "github.com/decred/politeia/politeiad/api/v1"
	v1 "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/api/v1/mime"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/util"
	"github.com/marcopeereboom/sbox"
	"github.com/subosito/gozaru"
)

// TODO testnet vs mainnet trillian databases
// TODO fsck
// TODO allow token prefix lookups
// TODO we need to be able to run multiple politeiad instances. Its ok if
//      we have a tree that seeds data between the instances.

const (
	defaultTrillianKeyFilename   = "trillian.key"
	defaultEncryptionKeyFilename = "tlogbe.key"
)

var (
	_ backend.Backend = (*TlogBackend)(nil)

	// statusChanges contains the allowed record status change
	// transitions. If statusChanges[currentStatus][newStatus] exists
	// then the status change is allowed.
	statusChanges = map[backend.MDStatusT]map[backend.MDStatusT]struct{}{
		// Unvetted status changes
		backend.MDStatusUnvetted: map[backend.MDStatusT]struct{}{
			backend.MDStatusIterationUnvetted: struct{}{},
			backend.MDStatusVetted:            struct{}{},
			backend.MDStatusCensored:          struct{}{},
		},
		backend.MDStatusIterationUnvetted: map[backend.MDStatusT]struct{}{
			backend.MDStatusVetted:   struct{}{},
			backend.MDStatusCensored: struct{}{},
		},

		// Vetted status changes
		backend.MDStatusVetted: map[backend.MDStatusT]struct{}{
			backend.MDStatusArchived: struct{}{},
			backend.MDStatusCensored: struct{}{},
		},

		// Statuses that do not allow any further transitions
		backend.MDStatusCensored: map[backend.MDStatusT]struct{}{},
		backend.MDStatusArchived: map[backend.MDStatusT]struct{}{},
	}
)

// plugin represents a tlogbe plugin.
type plugin struct {
	id       string
	version  string
	settings []backend.PluginSetting
	ctx      Plugin
}

// TlogBackend implements the Backend interface.
type TlogBackend struct {
	sync.RWMutex
	shutdown bool
	homeDir  string
	dataDir  string
	unvetted *tlog
	vetted   *tlog
	plugins  map[string]plugin // [pluginID]plugin

	// prefixes contains the token prefix to full token mapping for all
	// records. The prefix is the first n characters of the hex encoded
	// record token, where n is defined by the TokenPrefixLength from
	// the politeiad API. Record lookups by token prefix are allowed.
	// This cache is used to prevent prefix collisions when creating
	// new tokens and to facilitate lookups by token prefix.
	prefixes map[string][]byte // [tokenPrefix]token

	// vettedTreeIDs contains the token to tree ID mapping for vetted
	// records. The token corresponds to the unvetted tree ID so
	// unvetted lookups can be done directly, but vetted lookups
	// required pulling the freeze record from the unvetted tree to
	// get the vetted tree ID. This cache memoizes these results.
	vettedTreeIDs map[string]int64 // [token]treeID

	// inventory contains the full record inventory grouped by record
	// status. Each list of tokens is sorted by the timestamp of the
	// status change from newest to oldest.
	inventory map[backend.MDStatusT][]string
}

func tokenPrefix(token []byte) string {
	return hex.EncodeToString(token)[:pd.TokenPrefixLength]
}

func (t *TlogBackend) isShutdown() bool {
	t.RLock()
	defer t.RUnlock()

	return t.shutdown
}

func (t *TlogBackend) prefixExists(fullToken []byte) bool {
	t.RLock()
	defer t.RUnlock()

	_, ok := t.prefixes[tokenPrefix(fullToken)]
	return ok
}

func (t *TlogBackend) prefixAdd(fullToken []byte) {
	t.Lock()
	defer t.Unlock()

	prefix := tokenPrefix(fullToken)
	t.prefixes[prefix] = fullToken

	log.Debugf("Token prefix cached: %v", prefix)
}

func (t *TlogBackend) vettedTreeIDGet(token string) (int64, bool) {
	t.RLock()
	defer t.RUnlock()

	treeID, ok := t.vettedTreeIDs[token]
	return treeID, ok
}

func (t *TlogBackend) vettedTreeIDAdd(token string, treeID int64) {
	t.Lock()
	defer t.Unlock()

	t.vettedTreeIDs[token] = treeID

	log.Debugf("Vetted tree ID cached: %v %v", token, treeID)
}

func (t *TlogBackend) inventoryGet() map[backend.MDStatusT][]string {
	t.RLock()
	defer t.RUnlock()

	// Return a copy of the inventory
	inv := make(map[backend.MDStatusT][]string, len(t.inventory))
	for status, tokens := range t.inventory {
		tokensCopy := make([]string, len(tokens))
		for k, v := range tokens {
			tokensCopy[k] = v
		}
		inv[status] = tokensCopy
	}

	return inv
}

func (t *TlogBackend) inventoryAdd(token string, s backend.MDStatusT) {
	t.Lock()
	defer t.Unlock()

	t.inventory[s] = append([]string{token}, t.inventory[s]...)

	log.Debugf("Inventory cache added: %v %v", token, backend.MDStatus[s])
}

func (t *TlogBackend) inventoryUpdate(token string, currStatus, newStatus backend.MDStatusT) {
	t.Lock()
	defer t.Unlock()

	// Find the index of the token in its current status list
	var idx int
	for k, v := range t.inventory[currStatus] {
		if v == token {
			// Token found
			idx = k
		}
	}
	if idx == 0 {
		// Token was never found. This should not happen.
		e := fmt.Sprintf("inventoryUpdate: token not found: %v %v %v",
			token, currStatus, newStatus)
		panic(e)
	}

	// Remove the token from its current status list
	tokens := t.inventory[currStatus]
	t.inventory[currStatus] = append(tokens[:idx], tokens[idx+1:]...)

	// Prepend token to new status
	t.inventory[newStatus] = append([]string{token}, t.inventory[newStatus]...)

	log.Debugf("Inventory cache updated: %v %v to %v",
		token, backend.MDStatus[currStatus], backend.MDStatus[newStatus])
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

func merkleRoot(files []backend.File) (*[sha256.Size]byte, error) {
	hashes := make([]*[sha256.Size]byte, 0, len(files))
	for _, v := range files {
		b, err := hex.DecodeString(v.Digest)
		if err != nil {
			return nil, err
		}
		var d [sha256.Size]byte
		copy(d[:], b)
		hashes = append(hashes, &d)
	}
	return merkle.Root(hashes), nil
}

func recordMetadataNew(token []byte, files []backend.File, status backend.MDStatusT, iteration uint64) (*backend.RecordMetadata, error) {
	m, err := merkleRoot(files)
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
	// Apply deletes
	del := make(map[string]struct{}, len(filesDel))
	for _, fn := range filesDel {
		del[fn] = struct{}{}
	}
	f := make([]backend.File, 0, len(filesCurr)+len(filesAdd))
	for _, v := range filesCurr {
		if _, ok := del[v.Name]; ok {
			continue
		}
		f = append(f, v)
	}

	// Apply adds
	for _, v := range filesAdd {
		f = append(f, v)
	}

	return f
}

// TODO test this function
func metadataStreamsUpdate(mdCurr, mdAppend, mdOverwrite []backend.MetadataStream) []backend.MetadataStream {
	// Convert existing metadata to map
	md := make(map[uint64]backend.MetadataStream, len(mdCurr)+len(mdAppend))
	for _, v := range mdCurr {
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
		}

		// Metadata exists. Append to it.
		buf := bytes.NewBuffer([]byte(m.Payload))
		buf.WriteString(v.Payload)
		m.Payload = buf.String()
		md[v.ID] = m
	}

	// Convert metadata back to a slice
	metadata := make([]backend.MetadataStream, len(md))
	for _, v := range md {
		metadata = append(metadata, v)
	}

	return metadata
}

// New satisfies the Backend interface.
//
// This function satisfies the Backend interface.
func (t *TlogBackend) New(metadata []backend.MetadataStream, files []backend.File) (*backend.RecordMetadata, error) {
	log.Tracef("New")

	// Validate record contents
	err := verifyContent(metadata, files, []string{})
	if err != nil {
		return nil, err
	}

	// Create a new token
	var token []byte
	var treeID int64
	for retries := 0; retries < 10; retries++ {
		treeID, err = t.unvetted.treeNew()
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
			tokenPrefix(token))
	}

	// Create record metadata
	rm, err := recordMetadataNew(token, files, backend.MDStatusUnvetted, 1)
	if err != nil {
		return nil, err
	}

	// Call pre plugin hooks
	nr := NewRecord{
		RecordMetadata: *rm,
		Metadata:       metadata,
		Files:          files,
	}
	b, err := EncodeNewRecord(nr)
	if err != nil {
		return nil, err
	}
	err = t.pluginHook(HookNewRecordPre, string(b))
	if err != nil {
		return nil, err
	}

	// Save the record
	err = t.unvetted.recordSave(treeID, *rm, metadata, files)
	if err != nil {
		return nil, fmt.Errorf("recordSave %x: %v", token, err)
	}

	// Call post plugin hooks
	err = t.pluginHook(HookNewRecordPost, string(b))
	if err != nil {
		log.Errorf("New: pluginHook %v: %v", Hooks[HookNewRecordPost], err)
	}

	// Update the inventory cache
	t.inventoryAdd(hex.EncodeToString(token), backend.MDStatusUnvetted)

	log.Infof("New record %x", token)

	return rm, nil
}

// This function satisfies the Backend interface.
func (t *TlogBackend) UpdateUnvettedRecord(token []byte, mdAppend, mdOverwrite []backend.MetadataStream, filesAdd []backend.File, filesDel []string) (*backend.Record, error) {
	log.Tracef("UpdateUnvettedRecord: %x", token)

	// Validate record contents. Send in a single metadata array to
	// verify there are no dups.
	allMD := append(mdAppend, mdOverwrite...)
	err := verifyContent(allMD, filesAdd, filesDel)
	if err != nil {
		e, ok := err.(backend.ContentVerificationError)
		if !ok {
			return nil, err
		}
		// Allow ErrorStatusEmpty which indicates no new files are being
		// added. This can happen when files are being deleted without
		// any new files being added.
		if e.ErrorCode != pd.ErrorStatusEmpty {
			return nil, err
		}
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
	r, err := t.unvetted.recordLatest(treeID)
	if err != nil {
		if err == errRecordNotFound {
			return nil, backend.ErrRecordNotFound
		}
		return nil, fmt.Errorf("recordLatest: %v", err)
	}

	// Apply changes
	metadata := metadataStreamsUpdate(r.Metadata, mdAppend, mdOverwrite)
	files := filesUpdate(r.Files, filesAdd, filesDel)

	// Create record metadata
	recordMD, err := recordMetadataNew(token, files,
		backend.MDStatusIterationUnvetted, r.RecordMetadata.Iteration+1)
	if err != nil {
		return nil, err
	}

	// Call pre plugin hooks
	er := EditRecord{
		Current:        *r,
		RecordMetadata: *recordMD,
		MDAppend:       mdAppend,
		MDOverwrite:    mdOverwrite,
		FilesAdd:       filesAdd,
		FilesDel:       filesDel,
	}
	b, err := EncodeEditRecord(er)
	if err != nil {
		return nil, err
	}
	err = t.pluginHook(HookEditRecordPre, string(b))
	if err != nil {
		return nil, err
	}

	// Save record
	err = t.unvetted.recordSave(treeID, *recordMD, metadata, files)
	if err != nil {
		if err == errNoFileChanges {
			return nil, backend.ErrNoChanges
		}
		return nil, fmt.Errorf("recordSave: %v", err)
	}

	// Call post plugin hooks
	err = t.pluginHook(HookEditRecordPost, string(b))
	if err != nil {
		log.Errorf("pluginHook %v: %v", Hooks[HookEditRecordPost], err)
	}

	// Update inventory cache. The inventory will only need to be
	// updated if there was a status transition.
	if r.RecordMetadata.Status != recordMD.Status {
		// Status was changed
		t.inventoryUpdate(recordMD.Token, r.RecordMetadata.Status,
			recordMD.Status)
	}

	// Return updated record
	r, err = t.unvetted.recordLatest(treeID)
	if err != nil {
		return nil, fmt.Errorf("recordLatest: %v", err)
	}

	return r, nil
}

// This function satisfies the Backend interface.
func (t *TlogBackend) UpdateVettedRecord(token []byte, mdAppend, mdOverwrite []backend.MetadataStream, filesAdd []backend.File, filesDel []string) (*backend.Record, error) {
	log.Tracef("UpdateVettedRecord: %x", token)

	// Validate record contents. Send in a single metadata array to
	// verify there are no dups.
	allMD := append(mdAppend, mdOverwrite...)
	err := verifyContent(allMD, filesAdd, filesDel)
	if err != nil {
		e, ok := err.(backend.ContentVerificationError)
		if !ok {
			return nil, err
		}
		// Allow ErrorStatusEmpty which indicates no new files are being
		// added. This can happen when files are being deleted without
		// any new files being added.
		if e.ErrorCode != pd.ErrorStatusEmpty {
			return nil, err
		}
	}

	// Apply the record changes and save the new version. The lock
	// needs to be held for the remainder of the function.
	t.vetted.Lock()
	defer t.vetted.Unlock()
	if t.shutdown {
		return nil, backend.ErrShutdown
	}

	// Get existing record
	treeID := treeIDFromToken(token)
	r, err := t.vetted.recordLatest(treeID)
	if err != nil {
		if err == errRecordNotFound {
			return nil, backend.ErrRecordNotFound
		}
		return nil, fmt.Errorf("recordLatest: %v", err)
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
	er := EditRecord{
		Current:        *r,
		RecordMetadata: *recordMD,
		MDAppend:       mdAppend,
		MDOverwrite:    mdOverwrite,
		FilesAdd:       filesAdd,
		FilesDel:       filesDel,
	}
	b, err := EncodeEditRecord(er)
	if err != nil {
		return nil, err
	}
	err = t.pluginHook(HookEditRecordPre, string(b))
	if err != nil {
		return nil, err
	}

	// Save record
	err = t.vetted.recordSave(treeID, *recordMD, metadata, files)
	if err != nil {
		if err == errNoFileChanges {
			return nil, backend.ErrNoChanges
		}
		return nil, fmt.Errorf("recordSave: %v", err)
	}

	// Call post plugin hooks
	err = t.pluginHook(HookEditRecordPost, string(b))
	if err != nil {
		log.Errorf("pluginHook %v: %v", Hooks[HookEditRecordPost], err)
	}

	// Return updated record
	r, err = t.vetted.recordLatest(treeID)
	if err != nil {
		return nil, fmt.Errorf("recordLatest: %v", err)
	}

	return r, nil
}

// This function satisfies the Backend interface.
func (t *TlogBackend) UpdateUnvettedMetadata(token []byte, mdAppend, mdOverwrite []backend.MetadataStream) error {
	// Validate record contents. Send in a single metadata array to
	// verify there are no dups.
	allMD := append(mdAppend, mdOverwrite...)
	err := verifyContent(allMD, []backend.File{}, []string{})
	if err != nil {
		e, ok := err.(backend.ContentVerificationError)
		if !ok {
			return err
		}
		// Allow ErrorStatusEmpty which indicates no new files are being
		// being added. This is expected since this is a metadata only
		// update.
		if e.ErrorCode != pd.ErrorStatusEmpty {
			return err
		}
	}
	if len(mdAppend) == 0 && len(mdOverwrite) == 0 {
		return backend.ContentVerificationError{
			ErrorCode: pd.ErrorStatusNoChanges,
		}
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
	r, err := t.unvetted.recordLatest(treeID)
	if err != nil {
		if err == errRecordNotFound {
			return backend.ErrRecordNotFound
		}
		return fmt.Errorf("recordLatest: %v", err)
	}

	// Apply changes
	metadata := metadataStreamsUpdate(r.Metadata, mdAppend, mdOverwrite)

	// Update metadata
	err = t.unvetted.recordMetadataUpdate(treeID, r.RecordMetadata, metadata)
	if err != nil {
		return err
	}

	return nil
}

// This function satisfies the Backend interface.
func (t *TlogBackend) UpdateVettedMetadata(token []byte, mdAppend, mdOverwrite []backend.MetadataStream) error {
	log.Tracef("UpdateVettedMetadata: %x", token)

	// Validate record contents. Send in a single metadata array to
	// verify there are no dups.
	allMD := append(mdAppend, mdOverwrite...)
	err := verifyContent(allMD, []backend.File{}, []string{})
	if err != nil {
		e, ok := err.(backend.ContentVerificationError)
		if !ok {
			return err
		}
		// Allow ErrorStatusEmpty which indicates no new files are being
		// being added. This is expected since this is a metadata only
		// update.
		if e.ErrorCode != pd.ErrorStatusEmpty {
			return err
		}
	}
	if len(mdAppend) == 0 && len(mdOverwrite) == 0 {
		return backend.ContentVerificationError{
			ErrorCode: pd.ErrorStatusNoChanges,
		}
	}

	// Pull the existing record and apply the metadata updates. The
	// vetted lock must be held for the remainder of this function.
	t.vetted.Lock()
	defer t.vetted.Unlock()
	if t.shutdown {
		return backend.ErrShutdown
	}

	// Get existing record
	treeID := treeIDFromToken(token)
	r, err := t.vetted.recordLatest(treeID)
	if err != nil {
		if err == errRecordNotFound {
			return backend.ErrRecordNotFound
		}
		return fmt.Errorf("recordLatest: %v", err)
	}

	// Apply changes
	metadata := metadataStreamsUpdate(r.Metadata, mdAppend, mdOverwrite)

	// Update metadata
	err = t.vetted.recordMetadataUpdate(treeID, r.RecordMetadata, metadata)
	if err != nil {
		return err
	}

	return nil
}

// UnvettedExists returns whether the provided token corresponds to an unvetted
// record.
//
// This function satisfies the Backend interface.
func (t *TlogBackend) UnvettedExists(token []byte) bool {
	log.Tracef("UnvettedExists %x", token)

	// If the token is in the vetted cache then we know this is not an
	// unvetted record without having to make any network requests.
	_, ok := t.vettedTreeIDGet(hex.EncodeToString(token))
	if ok {
		return false
	}

	// Check if unvetted tree exists
	treeID := treeIDFromToken(token)
	if !t.unvetted.treeExists(treeID) {
		// Unvetted tree does not exists. No tree, no record.
		return false
	}

	// An unvetted tree exists. Check if a vetted tree also exists. If
	// one does then it means this record has been made public and is
	// no longer unvetted.
	if t.VettedExists(token) {
		return false
	}

	// Vetted record does not exist. This is an unvetted record.
	return true
}

// This function satisfies the Backend interface.
func (t *TlogBackend) VettedExists(token []byte) bool {
	log.Tracef("VettedExists %x", token)

	// Check if the token is in the vetted cache. The vetted cache is
	// lazy loaded if the token is not present then we need to check
	// manually.
	_, ok := t.vettedTreeIDGet(hex.EncodeToString(token))
	if ok {
		return true
	}

	// The token is derived from the unvetted tree ID. Check if the
	// token corresponds to an unvetted tree.
	treeID := treeIDFromToken(token)
	if !t.unvetted.treeExists(treeID) {
		// Unvetted tree does not exists. This token does not correspond
		// to any record.
		return false
	}

	// Unvetted tree exists. Get the freeze record to see if it
	// contains a pointer to a vetted tree.
	fr, err := t.unvetted.freezeRecord(treeID)
	if err != nil {
		if err == errFreezeRecordNotFound {
			// Unvetted tree exists and is not frozen. This is an unvetted
			// record.
			return false
		}
		log.Errorf("unvetted freezeRecord %v: %v", treeID, err)
		return false
	}
	if fr.TreeID == 0 {
		// Unvetted tree has been frozen but does not contain a pointer
		// to another tree. This means it was frozen for some other
		// reason (ex. censored). This is not a vetted record.
		return false
	}

	// Ensure the freeze record tree ID points to a valid vetted tree.
	// This should not fail.
	if !t.vetted.treeExists(fr.TreeID) {
		// We're in trouble!
		e := fmt.Sprintf("freeze record of unvetted tree %v points to "+
			"an invalid vetted tree %v", treeID, fr.TreeID)
		panic(e)
	}

	// Update the vetted cache
	t.vettedTreeIDAdd(hex.EncodeToString(token), fr.TreeID)

	return true
}

// This function satisfies the Backend interface.
func (t *TlogBackend) GetUnvetted(token []byte, version string) (*backend.Record, error) {
	log.Tracef("GetUnvetted: %x", token)

	if t.isShutdown() {
		return nil, backend.ErrShutdown
	}

	treeID := treeIDFromToken(token)
	v, err := strconv.ParseUint(version, 10, 64)
	if err != nil {
		return nil, backend.ErrRecordNotFound
	}

	return t.unvetted.recordVersion(treeID, uint32(v))
}

// This function satisfies the Backend interface.
func (t *TlogBackend) GetVetted(token []byte, version string) (*backend.Record, error) {
	log.Tracef("GetVetted: %x", token)

	if t.isShutdown() {
		return nil, backend.ErrShutdown
	}

	treeID := treeIDFromToken(token)
	v, err := strconv.ParseUint(version, 10, 64)
	if err != nil {
		return nil, backend.ErrRecordNotFound
	}

	return t.vetted.recordVersion(treeID, uint32(v))
}

// This function must be called WITH the unvetted lock held.
func (t *TlogBackend) unvettedPublish(token []byte, rm backend.RecordMetadata, metadata []backend.MetadataStream, files []backend.File) error {
	// Create a vetted tree
	var (
		vettedToken  []byte
		vettedTreeID int64
		err          error
	)
	for retries := 0; retries < 10; retries++ {
		vettedTreeID, err = t.vetted.treeNew()
		if err != nil {
			return err
		}
		vettedToken = tokenFromTreeID(vettedTreeID)

		// Check for token prefix collisions
		if !t.prefixExists(vettedToken) {
			// Not a collision. Update prefixes cache.
			t.prefixAdd(vettedToken)
			break
		}

		log.Infof("Token prefix collision %v, creating new token",
			tokenPrefix(vettedToken))
	}

	// Save the record to the vetted tlog
	err = t.vetted.recordSave(vettedTreeID, rm, metadata, files)
	if err != nil {
		return fmt.Errorf("vetted recordSave: %v", err)
	}

	log.Debugf("Unvetted record %x copied to vetted", token)

	// Freeze the unvetted tree
	fr := freezeRecord{
		TreeID: vettedTreeID,
	}
	treeID := treeIDFromToken(token)
	err = t.unvetted.treeFreeze(treeID, rm, metadata, fr)
	if err != nil {
		return fmt.Errorf("treeFreeze %v: %v", treeID, err)
	}

	log.Debugf("Unvetted record %x frozen", token)

	// Update the vetted cache
	t.vettedTreeIDAdd(hex.EncodeToString(token), vettedTreeID)

	return nil
}

// This function must be called WITH the unvetted lock held.
func (t *TlogBackend) unvettedCensor(token []byte, rm backend.RecordMetadata, metadata []backend.MetadataStream) error {
	// Freeze the tree
	treeID := treeIDFromToken(token)
	err := t.unvetted.treeFreeze(treeID, rm, metadata, freezeRecord{})
	if err != nil {
		return fmt.Errorf("treeFreeze %v: %v", treeID, err)
	}

	log.Debugf("Unvetted record %x frozen", token)

	// Delete all record files
	err = t.unvetted.recordDel(treeID)
	if err != nil {
		return fmt.Errorf("recordDel %v: %v", treeID, err)
	}

	log.Debug("Unvetted record %x files deleted", token)

	return nil
}

// This function must be called WITH the unvetted lock held.
func (t *TlogBackend) unvettedArchive(token []byte, rm backend.RecordMetadata, metadata []backend.MetadataStream) error {
	// Freeze the tree. Nothing else needs to be done for an archived
	// record.
	treeID := treeIDFromToken(token)
	err := t.unvetted.treeFreeze(treeID, rm, metadata, freezeRecord{})
	if err != nil {
		return err
	}

	log.Debugf("Unvetted record %x frozen", token)

	return nil
}

func (t *TlogBackend) SetUnvettedStatus(token []byte, status backend.MDStatusT, mdAppend, mdOverwrite []backend.MetadataStream) (*backend.Record, error) {
	log.Tracef("SetUnvettedStatus: %x %v (%v)",
		token, status, backend.MDStatus[status])

	// The existing record must be pulled and updated. The unvetted
	// lock must be held for the rest of this function.
	t.unvetted.Lock()
	defer t.unvetted.Unlock()
	if t.shutdown {
		return nil, backend.ErrShutdown
	}

	// Get existing record
	treeID := treeIDFromToken(token)
	r, err := t.unvetted.recordLatest(treeID)
	if err != nil {
		return nil, fmt.Errorf("recordLatest: %v", err)
	}
	rm := r.RecordMetadata
	oldStatus := rm.Status

	// Validate status change
	if !statusChangeIsAllowed(oldStatus, status) {
		return nil, backend.StateTransitionError{
			From: oldStatus,
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
	srs := SetRecordStatus{
		Current:        *r,
		RecordMetadata: rm,
		MDAppend:       mdAppend,
		MDOverwrite:    mdOverwrite,
	}
	b, err := EncodeSetRecordStatus(srs)
	if err != nil {
		return nil, err
	}
	err = t.pluginHook(HookSetRecordStatusPre, string(b))
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
	case backend.MDStatusArchived:
		err := t.unvettedArchive(token, rm, metadata)
		if err != nil {
			return nil, fmt.Errorf("unvettedArchive: %v", err)
		}
	default:
		return nil, fmt.Errorf("unknown status: %v (%v)",
			backend.MDStatus[status], status)
	}

	// Call post plugin hooks
	err = t.pluginHook(HookSetRecordStatusPost, string(b))
	if err != nil {
		log.Errorf("SetUnvettedStatus: pluginHook %v: %v",
			Hooks[HookSetRecordStatusPost], err)
	}

	// Update inventory cache
	t.inventoryUpdate(rm.Token, oldStatus, status)

	log.Debugf("Status change %x from %v (%v) to %v (%v)",
		token, backend.MDStatus[oldStatus], oldStatus,
		backend.MDStatus[status], status)

	// Return the updated record
	r, err = t.unvetted.recordLatest(treeID)
	if err != nil {
		return nil, fmt.Errorf("recordLatest: %v", err)
	}

	return r, nil
}

// This function must be called WITH the vetted lock held.
func (t *TlogBackend) vettedCensor(token []byte, rm backend.RecordMetadata, metadata []backend.MetadataStream) error {
	// Freeze the tree
	treeID := treeIDFromToken(token)
	err := t.vetted.treeFreeze(treeID, rm, metadata, freezeRecord{})
	if err != nil {
		return fmt.Errorf("treeFreeze %v: %v", treeID, err)
	}

	// Delete all record files
	err = t.vetted.recordDel(treeID)
	if err != nil {
		return fmt.Errorf("recordDel %v: %v", treeID, err)
	}

	return nil
}

// This function must be called WITH the vetted lock held.
func (t *TlogBackend) vettedArchive(token []byte, rm backend.RecordMetadata, metadata []backend.MetadataStream) error {
	// Freeze the tree. Nothing else needs to be done for an archived
	// record.
	treeID := treeIDFromToken(token)
	return t.vetted.treeFreeze(treeID, rm, metadata, freezeRecord{})
}

// This function satisfies the Backend interface.
func (t *TlogBackend) SetVettedStatus(token []byte, status backend.MDStatusT, mdAppend, mdOverwrite []backend.MetadataStream) (*backend.Record, error) {
	log.Tracef("SetVettedStatus: %x %v (%v)",
		token, status, backend.MDStatus[status])

	// The existing record must be pulled and updated. The vetted lock
	// must be held for the rest of this function.
	t.vetted.Lock()
	defer t.vetted.Unlock()
	if t.shutdown {
		return nil, backend.ErrShutdown
	}

	// Get existing record
	treeID := treeIDFromToken(token)
	r, err := t.vetted.recordLatest(treeID)
	if err != nil {
		return nil, fmt.Errorf("recordLatest: %v", err)
	}
	rm := r.RecordMetadata
	oldStatus := rm.Status

	// Validate status change
	if !statusChangeIsAllowed(rm.Status, status) {
		return nil, backend.StateTransitionError{
			From: oldStatus,
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
	srs := SetRecordStatus{
		Current:        *r,
		RecordMetadata: rm,
		MDAppend:       mdAppend,
		MDOverwrite:    mdOverwrite,
	}
	b, err := EncodeSetRecordStatus(srs)
	if err != nil {
		return nil, err
	}
	err = t.pluginHook(HookSetRecordStatusPre, string(b))
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
	err = t.pluginHook(HookSetRecordStatusPost, string(b))
	if err != nil {
		log.Errorf("SetVettedStatus: pluginHook %v: %v",
			Hooks[HookSetRecordStatusPost], err)
	}

	// Update inventory cache
	t.inventoryUpdate(rm.Token, oldStatus, status)

	log.Debugf("Status change %x from %v (%v) to %v (%v)",
		token, backend.MDStatus[oldStatus], oldStatus,
		backend.MDStatus[status], status)

	// Return the updated record
	r, err = t.vetted.recordLatest(treeID)
	if err != nil {
		return nil, fmt.Errorf("recordLatest: %v", err)
	}

	return r, nil
}

// Inventory is not currenctly implemented in tlogbe.
//
// This function satisfies the Backend interface.
func (t *TlogBackend) Inventory(vettedCount uint, unvettedCount uint, includeFiles, allVersions bool) ([]backend.Record, []backend.Record, error) {
	log.Tracef("Inventory: %v %v", includeFiles, allVersions)

	return nil, nil, fmt.Errorf("not implemented")
}

// InventoryByStatus returns the record tokens of all records in the inventory
// catagorized by MDStatusT.
//
// This function satisfies the Backend interface.
func (t *TlogBackend) InventoryByStatus() (*backend.InventoryByStatus, error) {
	log.Tracef("InventoryByStatus")

	inv := t.inventoryGet()
	return &backend.InventoryByStatus{
		Unvetted:          inv[backend.MDStatusUnvetted],
		IterationUnvetted: inv[backend.MDStatusIterationUnvetted],
		Vetted:            inv[backend.MDStatusVetted],
		Censored:          inv[backend.MDStatusCensored],
		Archived:          inv[backend.MDStatusArchived],
	}, nil
}

func (t *TlogBackend) pluginHook(h HookT, payload string) error {
	// Pass hook event and payload to each plugin
	for _, v := range t.plugins {
		err := v.ctx.Hook(h, payload)
		if err != nil {
			return fmt.Errorf("Hook %v: %v", v.id, err)
		}
	}

	return nil
}

// GetPlugins returns the backend plugins that have been registered and their
// settings.
//
// This function satisfies the Backend interface.
func (t *TlogBackend) GetPlugins() ([]backend.Plugin, error) {
	log.Tracef("GetPlugins")

	plugins := make([]backend.Plugin, 0, len(t.plugins))
	for _, v := range t.plugins {
		plugins = append(plugins, backend.Plugin{
			ID:       v.id,
			Version:  v.version,
			Settings: v.settings,
		})
	}

	return plugins, nil
}

// Plugin is a pass-through function for plugin commands.
//
// This function satisfies the Backend interface.
func (t *TlogBackend) Plugin(pluginID, command, payload string) (string, error) {
	log.Tracef("Plugin: %v", command)

	if t.isShutdown() {
		return "", backend.ErrShutdown
	}

	// Get plugin
	plugin, ok := t.plugins[pluginID]
	if !ok {
		return "", backend.ErrPluginInvalid
	}

	// Execute plugin command
	reply, err := plugin.ctx.Cmd(command, payload)
	if err != nil {
		return "", err
	}

	return reply, nil
}

// Close shuts the backend down and performs cleanup.
//
// This function satisfies the Backend interface.
func (t *TlogBackend) Close() {
	log.Tracef("Close")

	t.Lock()
	defer t.Unlock()

	// Shutdown backend
	t.shutdown = true

	// Close out tlog connections
	t.unvetted.close()
	t.vetted.close()
}

func (t *TlogBackend) setup() error {
	// Get all trees
	trees, err := t.unvetted.trillian.treesAll()
	if err != nil {
		return fmt.Errorf("unvetted treesAll: %v", err)
	}

	// Build all memory caches
	for _, v := range trees {
		// Add tree to prefixes cache
		token := tokenFromTreeID(v.TreeId)
		t.prefixAdd(token)

		// Check if the tree needs to be added to the vettedTreeIDs cache
		// by checking the freeze record of the unvetted tree.
		var vettedTreeID int64
		fr, err := t.unvetted.freezeRecord(v.TreeId)
		switch err {
		case errFreezeRecordNotFound:
			// No freeze record means this is not a vetted record.
			// Nothing to do. Continue.
		case nil:
			// A freeze record exists. If a pointer to a vetted tree has
			// been set, add it to the vettedTreeIDs cache.
			if fr.TreeID != 0 {
				vettedTreeID = fr.TreeID
				t.vettedTreeIDAdd(hex.EncodeToString(token), vettedTreeID)
			}
		default:
			// All other errors
			return fmt.Errorf("freezeRecord %v: %v", v.TreeId, err)
		}

		// Add record to the inventory cache
		var r *backend.Record
		if vettedTreeID != 0 {
			r, err = t.GetVetted(token, "")
			if err != nil {
				return fmt.Errorf("GetVetted %x: %v", token, err)
			}
		} else {
			r, err = t.GetUnvetted(token, "")
			if err != nil {
				return fmt.Errorf("GetUnvetted %x: %v", token, err)
			}
		}
		t.inventoryAdd(hex.EncodeToString(token), r.RecordMetadata.Status)
	}

	return nil
}

// New returns a new TlogBackend.
func New(homeDir, dataDir, dcrtimeHost, encryptionKeyFile, unvettedTrillianHost, unvettedTrillianKeyFile, vettedTrillianHost, vettedTrillianKeyFile string) (*TlogBackend, error) {
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
	unvetted, err := newTlog("unvetted", homeDir, dataDir, unvettedTrillianHost,
		unvettedTrillianKeyFile, dcrtimeHost, encryptionKeyFile)
	if err != nil {
		return nil, fmt.Errorf("newTlog unvetted: %v", err)
	}
	vetted, err := newTlog("vetted", homeDir, dataDir, vettedTrillianHost,
		vettedTrillianKeyFile, dcrtimeHost, "")
	if err != nil {
		return nil, fmt.Errorf("newTlog vetted: %v", err)
	}

	// Setup tlogbe
	t := TlogBackend{
		homeDir:       homeDir,
		dataDir:       dataDir,
		unvetted:      unvetted,
		vetted:        vetted,
		plugins:       make(map[string]plugin),
		prefixes:      make(map[string][]byte),
		vettedTreeIDs: make(map[string]int64),
		inventory: map[backend.MDStatusT][]string{
			backend.MDStatusUnvetted:          make([]string, 0),
			backend.MDStatusIterationUnvetted: make([]string, 0),
			backend.MDStatusVetted:            make([]string, 0),
			backend.MDStatusCensored:          make([]string, 0),
			backend.MDStatusArchived:          make([]string, 0),
		},
	}

	err = t.setup()
	if err != nil {
		return nil, fmt.Errorf("setup: %v", err)
	}

	return &t, nil
}
