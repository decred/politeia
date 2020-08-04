// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlogbe

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/decred/dcrtime/merkle"
	pd "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe/store/filesystem"
	"github.com/decred/politeia/util"
	"github.com/marcopeereboom/sbox"
)

// TODO populate token prefixes cache on startup
// TODO testnet vs mainnet trillian databases
// TODO fsck
// TODO allow token prefix lookups

const (
	defaultTrillianKeyFilename   = "trillian.key"
	defaultEncryptionKeyFilename = "tlogbe.key"

	recordsDirname = "records"
)

var (
	_ backend.Backend = (*Tlogbe)(nil)

	// statusChanges contains the allowed record status changes.
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

// Tlogbe implements the Backend interface.
type Tlogbe struct {
	sync.RWMutex
	shutdown bool
	homeDir  string
	dataDir  string
	unvetted *tlog
	vetted   *tlog
	plugins  []backend.Plugin

	// prefixes contains the token prefix to full token mapping for all
	// records. The prefix is the first n characters of the hex encoded
	// record token, where n is defined by the TokenPrefixLength from
	// the politeiad API. Record lookups by token prefix are allowed.
	// This cache is loaded on tlogbe startup and is used to prevent
	// prefix collisions when creating new tokens and to facilitate
	// lookups by token prefix.
	prefixes map[string][]byte // [tokenPrefix]fullToken

	// vettedTreeIDs contains the token to tree ID mapping for vetted
	// records. The token corresponds to the unvetted tree ID so
	// unvetted lookups can be done directly, but vetted lookups
	// required pulling the freeze record from the unvetted tree to
	// get the vetted tree ID. This cache memoizes these results.
	vettedTreeIDs map[string]int64 // [token]treeID
}

func tokenPrefix(token []byte) string {
	return hex.EncodeToString(token)[:pd.TokenPrefixLength]
}

func (t *Tlogbe) prefixExists(fullToken []byte) bool {
	t.RLock()
	defer t.RUnlock()

	_, ok := t.prefixes[tokenPrefix(fullToken)]
	return ok
}

func (t *Tlogbe) prefixSet(fullToken []byte) {
	t.Lock()
	defer t.Unlock()

	prefix := tokenPrefix(fullToken)
	t.prefixes[tokenPrefix(fullToken)] = fullToken

	log.Debugf("Token prefix cached: %v", prefix)
}

func (t *Tlogbe) vettedTreeIDGet(token string) (int64, bool) {
	t.RLock()
	defer t.RUnlock()

	treeID, ok := t.vettedTreeIDs[token]
	return treeID, ok
}

func (t *Tlogbe) vettedTreeIDSet(token string, treeID int64) {
	t.Lock()
	defer t.Unlock()

	t.vettedTreeIDs[token] = treeID

	log.Debugf("Vetted tree ID cached: %v %v", token, treeID)
}

// statusChangeIsAllowed returns whether the provided status change is allowed
// by tlogbe. An invalid 'from' status will panic since the 'from' status
// represents the existing status of a record and should never be invalid.
func statusChangeIsAllowed(from, to backend.MDStatusT) bool {
	allowed, ok := statusChanges[from]
	if !ok {
		e := fmt.Sprintf("status invalid: %v", from)
		panic(e)
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
func (t *Tlogbe) New(metadata []backend.MetadataStream, files []backend.File) (*backend.RecordMetadata, error) {
	log.Tracef("New")

	// Validate record contents
	err := backend.VerifyContent(metadata, files, []string{})
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
			// Not a collision. Update token prefixes cache.
			t.prefixSet(token)
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

	// Save the record
	err = t.unvetted.recordSave(treeID, *rm, metadata, files)
	if err != nil {
		return nil, fmt.Errorf("recordSave %x: %v", token, err)
	}

	log.Infof("New record %x", token)

	return rm, nil
}

// This function satisfies the Backend interface.
func (t *Tlogbe) UpdateUnvettedRecord(token []byte, mdAppend, mdOverwrite []backend.MetadataStream, filesAdd []backend.File, filesDel []string) (*backend.Record, error) {
	log.Tracef("UpdateUnvettedRecord: %x", token)

	// Validate record contents. Send in a single metadata array to
	// verify there are no dups.
	allMD := append(mdAppend, mdOverwrite...)
	err := backend.VerifyContent(allMD, filesAdd, filesDel)
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

	// Save record
	err = t.unvetted.recordSave(treeID, *recordMD, metadata, files)
	if err != nil {
		if err == errNoFileChanges {
			return nil, backend.ErrNoChanges
		}
		return nil, fmt.Errorf("recordSave: %v", err)
	}

	// TODO Call plugin hooks

	// Return updated record
	r, err = t.unvetted.recordLatest(treeID)
	if err != nil {
		return nil, fmt.Errorf("recordLatest: %v", err)
	}

	return r, nil
}

// This function satisfies the Backend interface.
func (t *Tlogbe) UpdateVettedRecord(token []byte, mdAppend, mdOverwrite []backend.MetadataStream, filesAdd []backend.File, filesDel []string) (*backend.Record, error) {
	log.Tracef("UpdateVettedRecord: %x", token)

	// Validate record contents. Send in a single metadata array to
	// verify there are no dups.
	allMD := append(mdAppend, mdOverwrite...)
	err := backend.VerifyContent(allMD, filesAdd, filesDel)
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

	// Save record
	err = t.vetted.recordSave(treeID, *recordMD, metadata, files)
	if err != nil {
		if err == errNoFileChanges {
			return nil, backend.ErrNoChanges
		}
		return nil, fmt.Errorf("recordSave: %v", err)
	}

	// TODO Call plugin hooks

	// Return updated record
	r, err = t.vetted.recordLatest(treeID)
	if err != nil {
		return nil, fmt.Errorf("recordLatest: %v", err)
	}

	return r, nil
}

// This function satisfies the Backend interface.
func (t *Tlogbe) UpdateUnvettedMetadata(token []byte, mdAppend, mdOverwrite []backend.MetadataStream) error {
	// Validate record contents. Send in a single metadata array to
	// verify there are no dups.
	allMD := append(mdAppend, mdOverwrite...)
	err := backend.VerifyContent(allMD, []backend.File{}, []string{})
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
	return t.unvetted.recordMetadataUpdate(treeID, r.RecordMetadata, metadata)
}

// This function satisfies the Backend interface.
func (t *Tlogbe) UpdateVettedMetadata(token []byte, mdAppend, mdOverwrite []backend.MetadataStream) error {
	log.Tracef("UpdateVettedMetadata: %x", token)

	// Validate record contents. Send in a single metadata array to
	// verify there are no dups.
	allMD := append(mdAppend, mdOverwrite...)
	err := backend.VerifyContent(allMD, []backend.File{}, []string{})
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
	return t.vetted.recordMetadataUpdate(treeID, r.RecordMetadata, metadata)
}

// UnvettedExists returns whether the provided token corresponds to an unvetted
// record.
//
// This function satisfies the Backend interface.
func (t *Tlogbe) UnvettedExists(token []byte) bool {
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
func (t *Tlogbe) VettedExists(token []byte) bool {
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
	t.vettedTreeIDSet(hex.EncodeToString(token), fr.TreeID)

	return true
}

// This function satisfies the Backend interface.
func (t *Tlogbe) GetUnvetted(token []byte, version string) (*backend.Record, error) {
	log.Tracef("GetUnvetted: %x", token)

	treeID := treeIDFromToken(token)
	v, err := strconv.ParseUint(version, 10, 64)
	if err != nil {
		return nil, backend.ErrRecordNotFound
	}

	return t.unvetted.recordVersion(treeID, uint32(v))
}

// This function satisfies the Backend interface.
func (t *Tlogbe) GetVetted(token []byte, version string) (*backend.Record, error) {
	log.Tracef("GetVetted: %x", token)

	treeID := treeIDFromToken(token)
	v, err := strconv.ParseUint(version, 10, 64)
	if err != nil {
		return nil, backend.ErrRecordNotFound
	}

	return t.vetted.recordVersion(treeID, uint32(v))
}

// This function must be called WITH the unvetted lock held.
func (t *Tlogbe) unvettedPublish(token []byte, rm backend.RecordMetadata, metadata []backend.MetadataStream, files []backend.File) error {
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
			t.prefixSet(vettedToken)
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
	t.vettedTreeIDSet(hex.EncodeToString(token), vettedTreeID)

	return nil
}

// This function must be called WITH the unvetted lock held.
func (t *Tlogbe) unvettedCensor(token []byte, rm backend.RecordMetadata, metadata []backend.MetadataStream) error {
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
func (t *Tlogbe) unvettedArchive(token []byte, rm backend.RecordMetadata, metadata []backend.MetadataStream) error {
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

func (t *Tlogbe) SetUnvettedStatus(token []byte, status backend.MDStatusT, mdAppend, mdOverwrite []backend.MetadataStream) (*backend.Record, error) {
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

	// Validate status change
	if !statusChangeIsAllowed(rm.Status, status) {
		return nil, backend.StateTransitionError{
			From: rm.Status,
			To:   status,
		}
	}

	log.Debugf("Status change %x from %v (%v) to %v (%v)",
		token, backend.MDStatus[rm.Status], rm.Status,
		backend.MDStatus[status], status)

	// Apply status change
	rm.Status = status
	rm.Iteration += 1
	rm.Timestamp = time.Now().Unix()

	// Apply metdata changes
	metadata := metadataStreamsUpdate(r.Metadata, mdAppend, mdOverwrite)

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

	// Return the updated record
	r, err = t.unvetted.recordLatest(treeID)
	if err != nil {
		return nil, fmt.Errorf("recordLatest: %v", err)
	}

	return r, nil
}

// This function must be called WITH the vetted lock held.
func (t *Tlogbe) vettedCensor(token []byte, rm backend.RecordMetadata, metadata []backend.MetadataStream) error {
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
func (t *Tlogbe) vettedArchive(token []byte, rm backend.RecordMetadata, metadata []backend.MetadataStream) error {
	// Freeze the tree. Nothing else needs to be done for an archived
	// record.
	treeID := treeIDFromToken(token)
	return t.vetted.treeFreeze(treeID, rm, metadata, freezeRecord{})
}

// This function satisfies the Backend interface.
func (t *Tlogbe) SetVettedStatus(token []byte, status backend.MDStatusT, mdAppend, mdOverwrite []backend.MetadataStream) (*backend.Record, error) {
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

	// Validate status change
	if !statusChangeIsAllowed(rm.Status, status) {
		return nil, backend.StateTransitionError{
			From: rm.Status,
			To:   status,
		}
	}

	log.Debugf("Status change %x from %v (%v) to %v (%v)",
		token, backend.MDStatus[rm.Status], rm.Status,
		backend.MDStatus[status], status)

	// Apply status change
	rm.Status = status
	rm.Iteration += 1
	rm.Timestamp = time.Now().Unix()

	// Apply metdata changes
	metadata := metadataStreamsUpdate(r.Metadata, mdAppend, mdOverwrite)

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

	// Return the updated record
	r, err = t.vetted.recordLatest(treeID)
	if err != nil {
		return nil, fmt.Errorf("recordLatest: %v", err)
	}

	return r, nil
}

// This function satisfies the Backend interface.
func (t *Tlogbe) Inventory(vettedCount uint, unvettedCount uint, includeFiles, allVersions bool) ([]backend.Record, []backend.Record, error) {
	log.Tracef("Inventory: %v %v", includeFiles, allVersions)

	// TODO implement inventory

	// return vetted, unvetted, nil
	return nil, nil, nil
}

func (t *Tlogbe) GetPlugins() ([]backend.Plugin, error) {
	log.Tracef("GetPlugins")

	// TODO implement plugins

	return t.plugins, nil
}

// Add commandID to Plugin
func (t *Tlogbe) Plugin(pluginID, command, payload string) (string, string, error) {
	log.Tracef("Plugin: %v", command)

	// TODO implement plugins

	return "", "", nil
}

func (t *Tlogbe) Close() {
	log.Tracef("Close")

	t.Lock()
	defer t.Unlock()

	// Shutdown backend
	t.shutdown = true

	// Close out tlog connections
	t.unvetted.close()
	t.vetted.close()
}

func New(homeDir, dataDir, trillianHost, trillianKeyFile, dcrtimeHost, encryptionKeyFile string) (*Tlogbe, error) {
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

	// Setup trillian client
	tlog, err := trillianClientNew(homeDir, trillianHost, trillianKeyFile)
	if err != nil {
		return nil, err
	}

	// Setup key-value store
	fp := filepath.Join(dataDir, recordsDirname)
	err = os.MkdirAll(fp, 0700)
	if err != nil {
		return nil, err
	}
	store := filesystem.New(fp)

	// Load encryption key
	f, err := os.Open(encryptionKeyFile)
	if err != nil {
		return nil, err
	}
	var key [32]byte
	n, err := f.Read(key[:])
	if n != len(key) {
		return nil, fmt.Errorf("invalid encryption key length")
	}
	if err != nil {
		return nil, err
	}
	f.Close()
	encryptionKey := encryptionKeyNew(&key)

	log.Infof("Encryption key loaded")

	// Setup dcrtime host
	_, err = url.Parse(dcrtimeHost)
	if err != nil {
		return nil, fmt.Errorf("parse dcrtime host '%v': %v", dcrtimeHost, err)
	}
	log.Infof("Anchor host: %v", dcrtimeHost)

	_ = encryptionKey
	_ = dcrtimeHost
	_ = store
	_ = tlog
	t := Tlogbe{
		homeDir: homeDir,
		dataDir: dataDir,
		// cron:    cron.New(),
	}

	/*
		// Launch cron
		log.Infof("Launch cron anchor job")
		err = t.cron.AddFunc(anchorSchedule, func() {
			// t.anchorTrees()
		})
		if err != nil {
			return nil, err
		}
		t.cron.Start()
	*/

	return &t, nil
}
