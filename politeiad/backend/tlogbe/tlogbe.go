package tlogbe

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/decred/dcrtime/merkle"
	pd "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/backend"
	tlog "github.com/decred/politeia/tlog/api/v1"
	tlogutil "github.com/decred/politeia/tlog/util"
	"github.com/decred/politeia/util"
	"github.com/google/trillian"
	"github.com/google/trillian/client"
	tcrypto "github.com/google/trillian/crypto"
)

// TODO do we need to be able to recreate the indexes from scratch?

// tlogbe implements the Backend interface.
type tlogbe struct {
	sync.RWMutex

	dataDir      string
	trillianHost string
	dcrtimeHost  string
	dcrtimeCert  string
	testnet      bool

	publicKeyFilename string                 // Remote server identity filename
	publicKey         crypto.PublicKey       // Remote server signing key
	myID              *identity.FullIdentity // tlogbe identity

	client trillian.TrillianLogClient
	admin  trillian.TrillianAdminClient

	client *http.Client

	// TODO these need to be persistent
	unvetted map[string]map[uint]record // [token][version]record
	vetted   map[string]map[uint]record // [token][version]record
}

const (
	dataDescriptorFile           = "file"
	dataDescriptorRecordMetadata = "recordmetadata"
	dataDescriptorMetadataStream = "metadatastream"
)

// record represents a tlog index for a backend Record.
type record struct {
	metadata  string            // RecordMetadata merkle hash
	files     map[string]string // [filename]merkleHash
	mdstreams map[uint64]string // [mdstreamID]merkleHash
}

func tokenFromTreeID(treeID int64) string {
	b := make([]byte, binary.MaxVarintLen64)
	binary.LittleEndian.PutUint64(b, uint64(treeID))
	return hex.EncodeToString(b)
}

func treeIDFromToken(token string) (int64, error) {
	b, err := hex.DecodeString(token)
	if err != nil {
		return 0, err
	}
	return int64(binary.LittleEndian.Uint64(b)), nil
}

func recordCopy(rv record) record {
	files := make(map[string]string, len(rv.files))
	mdstreams := make(map[uint64]string, len(rv.mdstreams))
	for k, v := range rv.files {
		files[k] = v
	}
	for k, v := range rv.mdstreams {
		mdstreams[k] = v
	}
	return record{
		metadata:  rv.metadata,
		files:     files,
		mdstreams: mdstreams,
	}
}

func (t *tlogbe) unvettedExists(token string) bool {
	t.RLock()
	defer t.RUnlock()

	_, ok := t.unvetted[token]
	return ok
}

// unvettedGetLatest returns the lastest version of the record index for the
// provided token.
//
// This function must be called WITHOUT the read lock held.
func (t *tlogbe) unvettedGetLatest(token string) (*record, error) {
	t.RLock()
	defer t.RUnlock()

	latest := uint(len(t.unvetted[token]))
	r, ok := t.unvetted[token][latest]
	if !ok {
		return nil, backend.ErrRecordNotFound
	}
	return &r, nil
}

// unvettedAdd adds the provided record to the unvetted index as a new version.
//
// This function must be called WITHOUT the lock held.
func (t *tlogbe) unvettedAdd(token string, r record) {
	t.Lock()
	defer t.Unlock()

	versions, ok := t.unvetted[token]
	if !ok {
		t.unvetted[token] = make(map[uint]record)
	}

	t.unvetted[token][uint(len(versions)+1)] = r
}

func (t *tlogbe) vettedExists(token string) bool {
	t.RLock()
	defer t.Unlock()

	_, ok := t.vetted[token]
	return ok
}

// errorFromResponse extracts a user-readable string from the response from
// tlog, which will contain a JSON error.
func errorFromResponse(r *http.Response) (string, error) {
	var errMsg string
	decoder := json.NewDecoder(r.Body)
	if r.StatusCode == http.StatusInternalServerError {
		var e tlog.ErrorReply
		if err := decoder.Decode(&e); err != nil {
			return "", err
		}
		errMsg = fmt.Sprintf("%v", e.ErrorCode)
	} else {
		var e tlog.UserError
		if err := decoder.Decode(&e); err != nil {
			return "", err
		}
		errMsg = tlog.ErrorStatus[e.ErrorCode] + " "
		if e.ErrorContext != nil && len(e.ErrorContext) > 0 {
			errMsg += strings.Join(e.ErrorContext, ", ")
		}
	}

	return errMsg, nil
}

// makeRequests sends an http request to the tlog rpc host using the given
// request parameters.
func (t *tlogbe) makeRequest(method string, route string, body interface{}) ([]byte, error) {
	var (
		reqBody []byte
		err     error
	)
	if body != nil {
		reqBody, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
	}

	fullRoute := t.rpcHost + route
	req, err := http.NewRequest(method, fullRoute, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(t.rpcUser, t.rpcPass)
	r, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		e, err := errorFromResponse(r)
		if err != nil {
			return nil, fmt.Errorf("%v", r.Status)
		}
		return nil, fmt.Errorf("%v: %v", r.Status, e)
	}

	return util.ConvertBodyToByteArray(r.Body, false), nil
}

func (t *tlogbe) recordNew(entries []tlog.RecordEntry) (*tlog.RecordNewReply, error) {
	log.Tracef("recordNew")

	// Send request
	rn := tlog.RecordNew{
		RecordEntries: entries,
	}
	respBody, err := t.makeRequest(http.MethodPost, tlog.RouteRecordNew, rn)
	if err != nil {
		return nil, err
	}

	// Decode and verify response
	var rnr tlog.RecordNewReply
	err = json.Unmarshal(respBody, &rnr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal RecordNewReply: %v", err)
	}
	verifier, err := client.NewLogVerifierFromTree(&rnr.Tree)
	if err != nil {
		return nil, err
	}
	_, err = tcrypto.VerifySignedLogRoot(verifier.PubKey,
		crypto.SHA256, &rnr.InitialRoot)
	if err != nil {
		return nil, fmt.Errorf("invalid InitialRoot %v: %v",
			rnr.Tree.TreeId, err)
	}
	lrSTH, err := tcrypto.VerifySignedLogRoot(verifier.PubKey,
		crypto.SHA256, &rnr.STH)
	if err != nil {
		return nil, fmt.Errorf("invalid STH %v: %v",
			rnr.Tree.TreeId, err)
	}
	for _, v := range rnr.Proofs {
		err := tlogutil.QueuedLeafProofVerify(t.publicKey, lrSTH, v)
		if err != nil {
			return nil, fmt.Errorf("invalid QueuedLeafProof %v %x: %v",
				rnr.Tree.TreeId, v.QueuedLeaf.Leaf.MerkleLeafHash, err)
		}
	}

	return &rnr, err
}

func (t *tlogbe) recordAppend(treeID int64, entries []tlog.RecordEntry) (*tlog.RecordAppendReply, error) {
	log.Tracef("recordAppend: %v", treeID)

	// Send request
	ra := tlog.RecordAppend{
		Id:            treeID,
		RecordEntries: entries,
	}
	respBody, err := t.makeRequest(http.MethodPost, tlog.RouteRecordAppend, ra)
	if err != nil {
		return nil, err
	}

	// Decode and verify response
	var rar tlog.RecordAppendReply
	err = json.Unmarshal(respBody, &rar)
	if err != nil {
		return nil, fmt.Errorf("unmarshal RecordAppendReply: %v", err)
	}
	lrv1, err := tcrypto.VerifySignedLogRoot(t.publicKey,
		crypto.SHA256, &rar.STH)
	if err != nil {
		return nil, fmt.Errorf("invalid STH %v: %v",
			treeID, err)
	}
	for _, v := range rar.Proofs {
		err := tlogutil.QueuedLeafProofVerify(t.publicKey, lrv1, v)
		if err != nil {
			return nil, fmt.Errorf("invalid QueuedLeafProof %v %x: %v",
				treeID, v.QueuedLeaf.Leaf.MerkleLeafHash, err)
		}
	}

	return &rar, nil
}

func (t *tlogbe) recordEntryProofs(treeID int64, merkleHashes []string) ([]tlog.RecordEntryProof, error) {
	log.Tracef("recordEntryProofs: %v %v", treeID, merkleHashes)

	// Prepare request
	entries := make([]tlog.RecordEntryIdentifier, 0, len(merkleHashes))
	for _, v := range merkleHashes {
		entries = append(entries, tlog.RecordEntryIdentifier{
			Id:         treeID,
			MerkleHash: v,
		})
	}
	reg := tlog.RecordEntriesGet{
		Entries: entries,
	}

	// Send request
	respBody, err := t.makeRequest(http.MethodGet,
		tlog.RouteRecordEntriesGet, reg)
	if err != nil {
		return nil, err
	}

	// Decode and verify response
	var reply tlog.RecordEntriesGetReply
	err = json.Unmarshal(respBody, &reply)
	if err != nil {
		return nil, fmt.Errorf("unmarshal RecordEntriesGetReply: %v", err)
	}
	for _, v := range reply.Proofs {
		err := tlogutil.RecordEntryProofVerify(t.publicKey, v)
		if err != nil {
			return nil, fmt.Errorf("invalid RecordEntryProof %v %x: %v",
				treeID, v.Leaf.MerkleLeafHash, err)
		}
	}

	return reply.Proofs, nil
}

func (t *tlogbe) convertRecordEntryFromFile(f backend.File) (*tlog.RecordEntry, error) {
	data, err := json.Marshal(f)
	if err != nil {
		return nil, err
	}
	hint, err := json.Marshal(
		tlog.DataDescriptor{
			Type:       tlog.DataTypeStructure,
			Descriptor: dataDescriptorFile,
		})
	if err != nil {
		return nil, err
	}
	re := tlogutil.RecordEntryNew(t.myID, hint, data)
	return &re, nil
}

func (t *tlogbe) convertRecordEntryFromMetadataStream(ms backend.MetadataStream) (*tlog.RecordEntry, error) {
	data, err := json.Marshal(ms)
	if err != nil {
		return nil, err
	}
	hint, err := json.Marshal(
		tlog.DataDescriptor{
			Type:       tlog.DataTypeStructure,
			Descriptor: dataDescriptorMetadataStream,
		})
	if err != nil {
		return nil, err
	}
	re := tlogutil.RecordEntryNew(t.myID, hint, data)
	return &re, nil
}

func (t *tlogbe) convertRecordEntryFromRecordMetadata(rm backend.RecordMetadata) (*tlog.RecordEntry, error) {
	data, err := json.Marshal(rm)
	if err != nil {
		return nil, err
	}
	hint, err := json.Marshal(
		tlog.DataDescriptor{
			Type:       tlog.DataTypeStructure,
			Descriptor: dataDescriptorRecordMetadata,
		})
	if err != nil {
		return nil, err
	}
	re := tlogutil.RecordEntryNew(t.myID, hint, data)
	return &re, nil
}

func (t *tlogbe) convertRecordEntriesFromFiles(files []backend.File) ([]tlog.RecordEntry, error) {
	entries := make([]tlog.RecordEntry, 0, len(files))
	for _, v := range files {
		re, err := t.convertRecordEntryFromFile(v)
		if err != nil {
			return nil, err
		}
		entries = append(entries, *re)
	}
	return entries, nil
}

func (t *tlogbe) convertRecordEntriesFromMetadataStreams(streams []backend.MetadataStream) ([]tlog.RecordEntry, error) {
	entries := make([]tlog.RecordEntry, 0, len(streams))
	for _, v := range streams {
		re, err := t.convertRecordEntryFromMetadataStream(v)
		if err != nil {
			return nil, err
		}
		entries = append(entries, *re)
	}
	return entries, nil
}

func recordMetadataNew(files []backend.File, token string, status backend.MDStatusT, iteration uint64) (*backend.RecordMetadata, error) {
	hashes := make([]*[sha256.Size]byte, 0, len(files))
	for _, v := range files {
		var d [sha256.Size]byte
		copy(d[:], v.Digest)
		hashes = append(hashes, &d)
	}

	m := *merkle.Root(hashes)
	return &backend.RecordMetadata{
		Version:   backend.VersionRecordMD,
		Iteration: iteration,
		Status:    status,
		Merkle:    hex.EncodeToString(m[:]),
		Timestamp: time.Now().Unix(),
		Token:     token,
	}, nil
}

// New satisfies the Backend interface.
func (t *tlogbe) New(mdstreams []backend.MetadataStream, files []backend.File) (*backend.RecordMetadata, error) {
	log.Tracef("New")

	// TODO Validate files

	// Generate token
	// TODO use treeID as token
	// TODO handle token prefix collisions
	tokenb, err := util.Random(pd.TokenSize)
	if err != nil {
		return nil, err
	}
	token := hex.EncodeToString(tokenb)

	// Prepare tlog record entries
	reMDStreams, err := t.convertRecordEntriesFromMetadataStreams(mdstreams)
	if err != nil {
		return nil, err
	}
	reFiles, err := t.convertRecordEntriesFromFiles(files)
	if err != nil {
		return nil, err
	}
	entries := append(reMDStreams, reFiles...)

	rm, err := recordMetadataNew(files, token, backend.MDStatusUnvetted, 1)
	if err != nil {
		return nil, err
	}
	reMetadata, err := t.convertRecordEntryFromRecordMetadata(*rm)
	if err != nil {
		return nil, err
	}
	entries = append(entries, *reMetadata)

	// Create new tlog record
	rnr, err := t.recordNew(entries)
	if err != nil {
		return nil, err
	}

	// Create a new record index
	r := record{
		files:     make(map[string]string, len(files)),
		mdstreams: make(map[uint64]string, len(mdstreams)),
	}
	for _, v := range rnr.Proofs {
		hash := hex.EncodeToString(v.QueuedLeaf.Leaf.LeafValue)
		merkle := hex.EncodeToString(v.QueuedLeaf.Leaf.MerkleLeafHash)

		// Check if proof is for the RecordMetadata
		if reMetadata.Hash == hash {
			r.metadata = merkle
			continue
		}

		// Check if proof is for any of the files
		for i, re := range reFiles {
			if re.Hash == hash {
				// files slice shares the same ordering as reFiles
				r.files[files[i].Name] = merkle
				continue
			}
		}

		// Check if proof is for any of the mdstreams
		for i, re := range reMDStreams {
			if re.Hash == hash {
				// mdstreams slice shares the same ordering as reMDStreams
				r.mdstreams[mdstreams[i].ID] = merkle
				continue
			}
		}

		return nil, fmt.Errorf("unknown proof hash %v %v %v",
			rnr.Tree.TreeId, hash, merkle)
	}

	// Save record index
	t.unvettedAdd(token, r)

	log.Debugf("New %v %v", token, rnr.Tree.TreeId)

	return rm, nil
}

func convertMetadataStreamFromRecordEntry(re tlog.RecordEntry) (*backend.MetadataStream, error) {
	// TODO this should be in the calling function
	// Decode and validate the DataHint
	b, err := base64.StdEncoding.DecodeString(re.DataHint)
	if err != nil {
		return nil, fmt.Errorf("decode DataHint: %v", err)
	}
	var dd tlog.DataDescriptor
	err = json.Unmarshal(b, &dd)
	if err != nil {
		return nil, fmt.Errorf("unmarshal DataHint: %v", err)
	}
	if dd.Descriptor != dataDescriptorMetadataStream {
		return nil, fmt.Errorf("unexpected data descriptor: got %v, want %v",
			dd.Descriptor, dataDescriptorMetadataStream)
	}

	// Decode the MetadataStream
	b, err = base64.StdEncoding.DecodeString(re.Data)
	if err != nil {
		return nil, fmt.Errorf("decode Data: %v", err)
	}
	var ms backend.MetadataStream
	err = json.Unmarshal(b, &ms)
	if err != nil {
		return nil, fmt.Errorf("unmarshal MetadataStream: %v", err)
	}

	return &ms, nil
}

func convertMetadataStreamsFromRecordEntryProofs(proofs []tlog.RecordEntryProof) ([]backend.MetadataStream, error) {
	mdstreams := make([]backend.MetadataStream, 0, len(proofs))
	for _, v := range proofs {
		md, err := convertMetadataStreamFromRecordEntry(*v.RecordEntry)
		if err != nil {
			return nil, fmt.Errorf("convertMetadataStreamFromRecordEntry %x: %v",
				v.Leaf.MerkleLeafHash, err)
		}
		mdstreams = append(mdstreams, *md)
	}
	return mdstreams, nil
}

// recordUpdate...
// This function assumes that the contents have already been validated.
//
// This function must be called with the lock held.
func (t *tlogbe) recordUpdate(token string, mdAppend, mdOverwrite []backend.MetadataStream, filesAdd []backend.File, filesDel []string) (*record, error) {
	versions, ok := t.unvetted[token]
	if !ok {
		return nil, backend.ErrRecordNotFound
	}

	treeID, err := treeIDFromToken(token)
	if err != nil {
		return nil, err
	}

	// Make a copy of the most recent record. This will serve as
	// the basis for the new version of the record.
	r := recordCopy(versions[uint(len(versions))])

	// entries will be be used to aggregate all new and updated
	// files that need to be appended to tlog.
	entries := make([]tlog.RecordEntry, 0, 64)

	// Fetch mdstreams for the mdstream append work
	merkles := make([]string, 0, len(mdAppend))
	for _, v := range mdAppend {
		m, ok := r.mdstreams[v.ID]
		if !ok {
			return nil, fmt.Errorf("append mdstream %v not found", v.ID)
		}
		merkles = append(merkles, m)
	}
	proofs, err := t.recordEntryProofs(treeID, merkles)
	if err != nil {
		return nil, fmt.Errorf("recordEntryProofs: %v", err)
	}
	ms, err := convertMetadataStreamsFromRecordEntryProofs(proofs)
	if err != nil {
		return nil, err
	}
	mdstreams := make(map[uint64]backend.MetadataStream, len(ms))
	for _, v := range ms {
		mdstreams[v.ID] = v
	}

	// This map is used to correlate the MetadataStream to the
	// tlog returned LogLeaf when we create the index.
	hashesMDStreams := make(map[string]backend.MetadataStream,
		len(mdAppend)+len(mdOverwrite))

	// Prepare work for mdstream appends
	for i, v := range mdAppend {
		m, ok := mdstreams[v.ID]
		if !ok {
			return nil, fmt.Errorf("tlog entry not found for mdstream %v", v.ID)
		}
		m.Payload += v.Payload
		re, err := t.convertRecordEntryFromMetadataStream(m)
		if err != nil {
			return nil, err
		}
		hashesMDStreams[re.Hash] = mdAppend[i]
		entries = append(entries, *re)
	}

	// Prepare work for mdstream overwrites
	for _, v := range mdOverwrite {
		re, err := t.convertRecordEntryFromMetadataStream(v)
		if err != nil {
			return nil, err
		}
		entries = append(entries, *re)
	}

	// This map is used to correlate the File to the tlog returned
	// LogLeaf when we create the index.
	hashesFiles := make(map[string]backend.File, len(filesAdd))

	// Prepare work for file adds
	for i, v := range filesAdd {
		re, err := t.convertRecordEntryFromFile(v)
		if err != nil {
			return nil, err
		}
		hashesFiles[re.Hash] = filesAdd[i]
		entries = append(entries, *re)
	}

	// Apply file deletes
	del := make(map[string]struct{}, len(filesDel))
	for _, fn := range filesDel {
		del[fn] = struct{}{}
	}
	for fn := range r.files {
		if _, ok := del[fn]; ok {
			delete(r.files, fn)
		}
	}

	// Append new and updated files to tlog
	rar, err := t.recordAppend(treeID, entries)
	if err != nil {
		return nil, fmt.Errorf("recordAppend: %v", err)
	}

	// Update record index
	for _, v := range rar.Proofs {
		hash := hex.EncodeToString(v.QueuedLeaf.Leaf.LeafValue)
		merkle := hex.EncodeToString(v.QueuedLeaf.Leaf.MerkleLeafHash)

		m, ok := hashesMDStreams[hash]
		if ok {
			r.mdstreams[m.ID] = merkle
			continue
		}

		f, ok := hashesFiles[hash]
		if ok {
			r.files[f.Name] = merkle
			continue
		}

		// Proof doesn't correspond to any of the record
		// entries we appended.
		return nil, fmt.Errorf("unknown LogLeaf %v", hash)
	}

	return &r, nil
}

func (t *tlogbe) updateUnvettedRecord(token string, mdAppend, mdOverwrite []backend.MetadataStream, filesAdd []backend.File, filesDel []string) error {
	// TODO copy verifyContents() from gitbe

	t.Lock()
	defer t.Unlock()

	r, err := t.recordUpdate(token, mdAppend, mdOverwrite,
		filesAdd, filesDel)
	if err != nil {
		return err
	}

	// Save the index of the new record version
	version := len(t.unvetted[token])
	t.unvetted[token][uint(version+1)] = *r

	return nil
}

func (t *tlogbe) record(token string, r record) (*backend.Record, error) {
	// Aggregate merkle hashes
	merkles := make([]string, 0, len(r.files)+len(r.mdstreams)+1)
	merkles = append(merkles, r.metadata)
	for _, v := range r.files {
		merkles = append(merkles, v)
	}
	for _, v := range r.mdstreams {
		merkles = append(merkles, v)
	}

	treeID, err := treeIDFromToken(token)
	if err != nil {
		return nil, err
	}

	// Fetch record entry proofs
	proofs, err := t.recordEntryProofs(treeID, merkles)
	if err != nil {
		return nil, err
	}

	// Decode the record entries into their appropriate types
	var rm backend.RecordMetadata
	files := make([]backend.File, 0, len(proofs))
	mdstreams := make([]backend.MetadataStream, 0, len(proofs))
	for _, v := range proofs {
		// Decode and unmarshal the data hint
		b, err := base64.StdEncoding.DecodeString(v.RecordEntry.DataHint)
		if err != nil {
			return nil, err
		}
		var dd tlog.DataDescriptor
		err = json.Unmarshal(b, &dd)
		if err != nil {
			return nil, fmt.Errorf("unmarshal DataHint %x: %v",
				v.Leaf.MerkleLeafHash, err)
		}

		// Decode and unmarshal the data
		datab, err := base64.StdEncoding.DecodeString(v.RecordEntry.Data)
		if err != nil {
			return nil, err
		}
		switch dd.Descriptor {
		case dataDescriptorFile:
			var f backend.File
			err = json.Unmarshal(datab, &f)
			if err != nil {
				return nil, fmt.Errorf("unmarshal File %x: %v",
					v.Leaf.MerkleLeafHash, err)
			}
			files = append(files, f)
		case dataDescriptorRecordMetadata:
			err = json.Unmarshal(datab, &rm)
			if err != nil {
				return nil, fmt.Errorf("unmarshal RecordMetadata %x: %v",
					v.Leaf.MerkleLeafHash, err)
			}
		case dataDescriptorMetadataStream:
			var ms backend.MetadataStream
			err = json.Unmarshal(datab, &ms)
			if err != nil {
				return nil, fmt.Errorf("unmarshal MetadataStream %x: %v",
					v.Leaf.MerkleLeafHash, err)
			}
			mdstreams = append(mdstreams, ms)
		default:
			return nil, fmt.Errorf("unknown data descriptor %x %v",
				v.Leaf.MerkleLeafHash, dd.Descriptor)
		}
	}

	return &backend.Record{
		RecordMetadata: rm,
		Files:          files,
		Metadata:       mdstreams,
	}, nil
}

func (t *tlogbe) UpdateUnvettedRecord(tokenb []byte, mdAppend, mdOverwrite []backend.MetadataStream, filesAdd []backend.File, filesDel []string) (*backend.Record, error) {
	log.Tracef("UpdateUnvettedRecord: %x", tokenb)

	token := hex.EncodeToString(tokenb)
	if !t.unvettedExists(token) {
		return nil, backend.ErrRecordNotFound
	}

	err := t.updateUnvettedRecord(token, mdAppend, mdOverwrite,
		filesAdd, filesDel)
	if err != nil {
		return nil, err
	}

	r, err := t.unvettedGetLatest(token)
	if err != nil {
		return nil, err
	}

	return t.record(token)
}

func (t *tlogbe) UpdateVettedRecord([]byte, []backend.MetadataStream, []backend.MetadataStream, []backend.File, []string) (*backend.Record, error) {
	return nil, nil
}

func (t *tlogbe) UpdateVettedMetadata([]byte, []backend.MetadataStream, []backend.MetadataStream) error {
	return nil
}

func (t *tlogbe) UpdateReadme(string) error {
	return nil
}

func (t *tlogbe) UnvettedExists(tokenb []byte) bool {
	log.Tracef("UnvettedExists %x", tokenb)

	return t.unvettedExists(hex.EncodeToString(tokenb))
}

func (t *tlogbe) VettedExists(tokenb []byte) bool {
	log.Tracef("VettedExists %x", tokenb)

	return t.vettedExists(hex.EncodeToString(tokenb))
}

func (t *tlogbe) GetUnvetted([]byte) (*backend.Record, error) {
	return nil, nil
}

func (t *tlogbe) GetVetted([]byte, string) (*backend.Record, error) {
	return nil, nil
}

func (t *tlogbe) SetUnvettedStatus([]byte, backend.MDStatusT, []backend.MetadataStream, []backend.MetadataStream) (*backend.Record, error) {
	return nil, nil
}

func (t *tlogbe) SetVettedStatus([]byte, backend.MDStatusT, []backend.MetadataStream, []backend.MetadataStream) (*backend.Record, error) {
	return nil, nil
}

func (t *tlogbe) Inventory(uint, uint, bool, bool) ([]backend.Record, []backend.Record, error) {
	return nil, nil, nil
}

func (t *tlogbe) GetPlugins() ([]backend.Plugin, error) {
	return nil, nil
}

func (t *tlogbe) Plugin(string, string) (string, string, error) {
	return "", "", nil
}

func (t *tlogbe) Close() {}

func tlogbeNew(rpcUser, rpcPass, rpcHost, rpcCert string, testnet bool) (*tlogbe, error) {
	client, err := util.NewClient(false, rpcCert)
	if err != nil {
		return nil, err
	}
	return &tlogbe{
		rpcUser:  rpcUser,
		rpcPass:  rpcPass,
		rpcHost:  rpcHost,
		rpcCert:  rpcCert,
		client:   client,
		testnet:  testnet,
		unvetted: make(map[string]map[uint]record),
		vetted:   make(map[string]map[uint]record),
	}, nil
}
