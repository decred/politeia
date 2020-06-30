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
	"sync"
	"time"

	"github.com/decred/dcrtime/merkle"
	pd "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe/store/filesystem"
	"github.com/decred/politeia/util"
	"github.com/marcopeereboom/sbox"
)

// TODO Add UpdateUnvettedMetadata to backend interface
// TODO populate token prefixes cache on startup
// TODO testnet vs mainnet trillian databases
// TODO lock on the token level
// TODO fsck
// TODO allow token prefix lookups

const (
	defaultTrillianKeyFilename   = "trillian.key"
	defaultEncryptionKeyFilename = "tlogbe.key"

	recordsDirname = "records"
)

var (
	_ backend.Backend = (*tlogbe)(nil)

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
		},

		// Statuses that do not allow any further transitions
		backend.MDStatusCensored: map[backend.MDStatusT]struct{}{},
		backend.MDStatusArchived: map[backend.MDStatusT]struct{}{},
	}
)

// tlogbe implements the Backend interface.
type tlogbe struct {
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
	// This cache is used to prevent prefix collisions when creating
	// new tokens and to facilitate lookups by token prefix. This cache
	// is loaded on tlogbe startup.
	prefixes map[string][]byte // [tokenPrefix]fullToken

	// vettedTrees contains the token to tree ID mapping for vetted
	// records. The token corresponds to the unvetted tree ID so
	// unvetted lookups can be done directly, but vetted lookups
	// required pulling the freeze record from the unvetted tree to
	// get the vetted tree ID. This cache memoizes these results.
	vettedTrees map[string]int64 // [token]treeID
}

func (t *tlogbe) prefixExists(fullToken []byte) bool {
	t.RLock()
	defer t.RUnlock()

	prefix := hex.EncodeToString(fullToken)[:pd.TokenPrefixLength]
	_, ok := t.prefixes[prefix]
	return ok
}

func (t *tlogbe) prefixSet(fullToken []byte) {
	t.Lock()
	defer t.Unlock()

	prefix := hex.EncodeToString(fullToken)[:pd.TokenPrefixLength]
	t.prefixes[prefix] = fullToken
}

func (t *tlogbe) vettedTreesGet(token string) (int64, bool) {
	t.RLock()
	defer t.RUnlock()

	treeID, ok := t.vettedTrees[token]
	return treeID, ok
}

func (t *tlogbe) vettedTreesSet(token string, treeID int64) {
	t.Lock()
	defer t.Unlock()

	t.vettedTrees[token] = treeID

	log.Debugf("vettedTreesSet: %v %v", token, treeID)
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
// TODO when does the signature get checked
func (t *tlogbe) New(metadata []backend.MetadataStream, files []backend.File) (*backend.RecordMetadata, error) {
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
			// Not a collision
			break
		}

		log.Infof("Token prefix collision %x, creating new token", token)
	}

	// Create record metadata
	rm, err := recordMetadataNew(token, files, backend.MDStatusUnvetted, 1)
	if err != nil {
		return nil, err
	}

	// Save the new version of the record
	err = t.unvetted.recordSave(treeID, *rm, metadata, files)
	if err != nil {
		return nil, fmt.Errorf("recordSave %x: %v", token, err)
	}

	log.Infof("New record %x", token)

	return rm, nil
}

// TODO Add UpdateUnvettedMetadata

func (t *tlogbe) UpdateUnvettedRecord(token []byte, mdAppend, mdOverwrite []backend.MetadataStream, filesAdd []backend.File, filesDel []string) (*backend.Record, error) {
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

	t.Lock()
	defer t.Unlock()
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

	// Get updated record
	r, err = t.unvetted.recordLatest(treeID)
	if err != nil {
		return nil, fmt.Errorf("recordLatest: %v", err)
	}

	return r, nil
}

func (t *tlogbe) UpdateVettedRecord(token []byte, mdAppend, mdOverwrite []backend.MetadataStream, filesAdd []backend.File, filesDel []string) (*backend.Record, error) {
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

	t.Lock()
	defer t.Unlock()
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
	err = t.unvetted.recordSave(treeID, *recordMD, metadata, files)
	if err != nil {
		if err == errNoFileChanges {
			return nil, backend.ErrNoChanges
		}
		return nil, fmt.Errorf("recordSave: %v", err)
	}

	// TODO Call plugin hooks

	// Get updated record
	r, err = t.unvetted.recordLatest(treeID)
	if err != nil {
		return nil, fmt.Errorf("recordLatest: %v", err)
	}

	return r, nil
}

func (t *tlogbe) UpdateVettedMetadata(token []byte, mdAppend, mdOverwrite []backend.MetadataStream) error {
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

	t.Lock()
	defer t.Unlock()
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

func (t *tlogbe) UpdateReadme(content string) error {
	return fmt.Errorf("not implemented")
}

// unvettedRecordExists returns whether the provided token corresponds to an
// unvetted record.
func (t *tlogbe) unvettedExists(token []byte) bool {
	// TODO
	return false
}

func (t *tlogbe) UnvettedExists(token []byte) bool {
	log.Tracef("UnvettedExists %x", token)
	// TODO must check that it exists and it is not a vetted record too
	// Checking if its frozen is not enough. A unvetted tree will be
	// frozen when it is censored or abandoned.

	return false
}

func (t *tlogbe) vettedExists(token []byte) bool {
	tk := hex.EncodeToString(token)
	if _, ok := t.vettedTreesGet(tk); ok {
		return true
	}

	// Just because the token is not in the vetted trees cache does not
	// mean a vetted tree does not exist. The cache is lazy loaded.
	// Check if there is an unvetted tree for the token and if the last
	// leaf of the unvetted tree is a freeze record.
	treeID := treeIDFromToken(token)
	fr, err := t.unvetted.freezeRecord(treeID)
	if err != nil {
		if err == errFreezeRecordNotFound {
			// Unvetted tree is not frozen. Record is still unvetted.
			return false
		}

		// Unexpected error
		e := fmt.Sprintf("vettedExists %x: freezeRecord: %v", token, err)
		panic(e)
	}

	// Unvetted tree is frozen. Check if the freeze record points to a
	// vetted tree ID or if it is blank. A vetted tree ID indicates the
	// record was made public. A blank tree ID indicates the tree was
	// frozen for some other reason such as if the record was censored
	// or abandoned.
	if fr.TreeID == 0 {
		// No vetted tree pointer found
		return false
	}

	// Ensure vetted record exists
	if !t.vetted.treeExists(fr.TreeID) {
		// Uh oh. A freeze record points to this tree ID but the tree
		// does not exist. Not good.
		e := fmt.Sprintf("freeze record points to invalid tree %v", fr.TreeID)
		panic(e)
	}

	// Cache the vetted tree ID
	t.vettedTreesSet(hex.EncodeToString(token), fr.TreeID)

	return true
}

func (t *tlogbe) VettedExists(token []byte) bool {
	log.Tracef("VettedExists %x", token)

	return false
}

func (t *tlogbe) GetUnvetted(token []byte) (*backend.Record, error) {
	log.Tracef("GetUnvetted: %x", token)

	return nil, nil
}

func (t *tlogbe) GetVetted(token []byte, version string) (*backend.Record, error) {
	log.Tracef("GetVetted: %x", token)

	return nil, nil
}

// This function must be called with the read/write lock held.
func (t *tlogbe) unvettedPublish(token []byte, rm backend.RecordMetadata, metadata []backend.MetadataStream, files []backend.File) error {
	// Create a vetted record
	// TODO check for collisions
	treeID, err := t.vetted.treeNew()
	if err != nil {
		return fmt.Errorf("vetted recordNew: %v", err)
	}

	// Save the record as vetted
	err = t.vetted.recordSave(treeID, rm, metadata, files)
	if err != nil {
		return fmt.Errorf("vetted recordSave: %v", err)
	}

	// Freeze the unvetted tree
	fr := freezeRecord{
		TreeID: treeID,
	}
	_ = fr

	return nil
}

// This function must be called with the read/write lock held.
func (t *tlogbe) unvettedCensor() error {
	// Freeze tree
	// Delete the censored blobs
	return nil
}

// This function must be called with the read/write lock held.
func (t *tlogbe) unvettedArchive() error {
	// Freeze tree
	return nil
}

func (t *tlogbe) SetUnvettedStatus(token []byte, status backend.MDStatusT, mdAppend, mdOverwrite []backend.MetadataStream) (*backend.Record, error) {
	log.Tracef("SetUnvettedStatus: %x %v (%v)",
		token, status, backend.MDStatus[status])

	t.Lock()
	defer t.Unlock()
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

	switch status {
	case backend.MDStatusVetted:
		err := t.unvettedPublish(token, rm, metadata, r.Files)
		if err != nil {
			return nil, fmt.Errorf("publish: %v", err)
		}
	case backend.MDStatusCensored:
		err := t.unvettedCensor()
		if err != nil {
			return nil, fmt.Errorf("censor: %v", err)
		}
	case backend.MDStatusArchived:
		err := t.unvettedArchive()
		if err != nil {
			return nil, fmt.Errorf("archive: %v", err)
		}
	default:
		return nil, fmt.Errorf("unknown status: %v (%v)",
			backend.MDStatus[status], status)
	}

	// Return the record
	r, err = t.unvetted.recordLatest(treeID)
	if err != nil {
		return nil, fmt.Errorf("recordLatest: %v", err)
	}

	return r, nil
}

// This function must be called with the read/write lock held.
func (t *tlogbe) vettedCensor() error {
	// Freeze tree
	// Delete the censored blobs
	return nil
}

// This function must be called with the read/write lock held.
func (t *tlogbe) vettedArchive() error {
	// Freeze tree
	return nil
}

func (t *tlogbe) SetVettedStatus(token []byte, status backend.MDStatusT, mdAppend, mdOverwrite []backend.MetadataStream) (*backend.Record, error) {
	log.Tracef("SetVettedStatus: %x %v (%v)",
		token, status, backend.MDStatus[status])

	t.Lock()
	defer t.Unlock()
	if t.shutdown {
		return nil, backend.ErrShutdown
	}

	/*
		// Validate status change
		if !statusChangeIsAllowed(rm.Status, status) {
			return nil, backend.StateTransitionError{
				From: rm.Status,
				To:   status,
			}
		}

		log.Debugf("Status change %x from %v (%v) to %v (%v)", token,
			backend.MDStatus[rm.Status], rm.Status, backend.MDStatus[status], status)

		// Apply status change
		rm.Status = status
		rm.Iteration += 1
		rm.Timestamp = time.Now().Unix()

		// Update metadata
	*/

	return nil, nil
}

func (t *tlogbe) Inventory(vettedCount uint, branchCount uint, includeFiles, allVersions bool) ([]backend.Record, []backend.Record, error) {
	log.Tracef("Inventory: %v %v", includeFiles, allVersions)

	// return vetted, unvetted, nil
	return nil, nil, nil
}

func (t *tlogbe) GetPlugins() ([]backend.Plugin, error) {
	log.Tracef("GetPlugins")

	// TODO implement plugins

	return t.plugins, nil
}

func (t *tlogbe) Plugin(command, payload string) (string, string, error) {
	log.Tracef("Plugin: %v", command)

	// TODO implement plugins

	return "", "", nil
}

func (t *tlogbe) Close() {
	log.Tracef("Close")

	t.Lock()
	defer t.Unlock()

	// Shutdown backend
	t.shutdown = true

	// Close out tlog connections
	t.unvetted.close()
	t.vetted.close()
}

func New(homeDir, dataDir, trillianHost, trillianKeyFile, dcrtimeHost, encryptionKeyFile string) (*tlogbe, error) {
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
	t := tlogbe{
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
