// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package testpoliteiad

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/decred/dcrtime/merkle"
	decred "github.com/thi4go/politeia/decredplugin"
	v1 "github.com/thi4go/politeia/politeiad/api/v1"
	"github.com/thi4go/politeia/politeiad/api/v1/identity"
	"github.com/thi4go/politeia/politeiad/cache"
	"github.com/thi4go/politeia/util"
	"github.com/gorilla/mux"
)

var (
	errRecordNotFound = errors.New("record not found")
)

// TestPoliteiad provides an implementation of the politeiad api that can be
// used for testing politeiad clients.  The api is implemented using an
// httptest server and all records and plugin data is stored in memory.
type TestPoliteiad struct {
	sync.RWMutex

	URL            string // Base url of form http://ipaddr:port
	PublicIdentity *identity.PublicIdentity

	identity *identity.FullIdentity
	server   *httptest.Server
	cache    cache.Cache
	records  map[string]map[string]v1.Record // [token][version]Record

	// Decred plugin
	authorizeVotes   map[string]map[string]decred.AuthorizeVote // [token][version]AuthorizeVote
	startVotes       map[string]decred.StartVoteV2              // [token]StartVote
	startVoteReplies map[string]decred.StartVoteReply           // [token]StartVoteReply
}

func respondWithUserError(w http.ResponseWriter,
	errorCode v1.ErrorStatusT, errorContext []string) {
	util.RespondWithJSON(w, http.StatusBadRequest, v1.UserErrorReply{
		ErrorCode:    errorCode,
		ErrorContext: errorContext,
	})
}

// merkleRoot returns a hex encoded merkle root of the passed in files.
func merkleRoot(files []v1.File) (string, error) {
	if len(files) == 0 {
		return "", fmt.Errorf("no files")
	}

	digests := make([]*[sha256.Size]byte, len(files))
	for i, f := range files {
		// Compute file digest
		b, err := base64.StdEncoding.DecodeString(f.Payload)
		if err != nil {
			return "", fmt.Errorf("decode payload for file %v: %v",
				f.Name, err)
		}
		digest := util.Digest(b)

		// Compare against digest that came with the file
		d, ok := util.ConvertDigest(f.Digest)
		if !ok {
			return "", fmt.Errorf("invalid digest: file:%v digest:%v",
				f.Name, f.Digest)
		}
		if !bytes.Equal(digest, d[:]) {
			return "", fmt.Errorf("digests do not match for file %v",
				f.Name)
		}

		// Digest is valid
		digests[i] = &d
	}

	// Compute merkle root
	return hex.EncodeToString(merkle.Root(digests)[:]), nil
}

// addRecord adds a record to the records store.
//
// This function must be called without the lock held.
func (p *TestPoliteiad) addRecord(r v1.Record) {
	p.Lock()
	defer p.Unlock()

	_, ok := p.records[r.CensorshipRecord.Token]
	if !ok {
		p.records[r.CensorshipRecord.Token] = make(map[string]v1.Record)
	}

	p.records[r.CensorshipRecord.Token][r.Version] = r
}

// updateRecord updates a record in the record store.
func (p *TestPoliteiad) updateRecord(r v1.Record) {
	p.Lock()
	defer p.Unlock()

	p.records[r.CensorshipRecord.Token][r.Version] = r
}

// record returns the latest version of the specified record.
//
// This function must be called with the lock held.
func (p *TestPoliteiad) record(token string) (*v1.Record, error) {
	records, ok := p.records[token]
	if !ok {
		return nil, errRecordNotFound
	}

	var latest int
	for version := range records {
		v, err := strconv.Atoi(version)
		if err != nil {
			return nil, fmt.Errorf("parse version '%v' failed: %v",
				version, err)
		}

		if v > latest {
			latest = v
		}
	}

	// Sanity check
	if latest == 0 {
		return nil, errRecordNotFound
	}

	r := records[strconv.Itoa(latest)]
	return &r, nil
}

func (p *TestPoliteiad) handleNewRecord(w http.ResponseWriter, r *http.Request) {
	// Decode request
	var t v1.NewRecord
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&t); err != nil {
		util.RespondWithJSON(w, http.StatusBadRequest, err)
		return
	}

	// Verify challenge
	challenge, err := hex.DecodeString(t.Challenge)
	if err != nil || len(challenge) != v1.ChallengeSize {
		respondWithUserError(w, v1.ErrorStatusInvalidChallenge, nil)
		return
	}

	// Prepare response
	tokenb, err := util.Random(v1.TokenSize)
	if err != nil {
		util.RespondWithJSON(w, http.StatusInternalServerError, err)
		return
	}

	merkle, err := merkleRoot(t.Files)
	if err != nil {
		util.RespondWithJSON(w, http.StatusInternalServerError, err)
		return
	}

	token := hex.EncodeToString(tokenb)
	sig := p.identity.SignMessage([]byte(merkle + token))
	resp := p.identity.SignMessage(challenge)
	cr := v1.CensorshipRecord{
		Merkle:    merkle,
		Token:     token,
		Signature: hex.EncodeToString(sig[:]),
	}

	// Add record to politeiad store
	p.addRecord(v1.Record{
		Status:           v1.RecordStatusNotReviewed,
		Timestamp:        time.Now().Unix(),
		Version:          "1",
		Metadata:         t.Metadata,
		Files:            t.Files,
		CensorshipRecord: cr,
	})

	// Send response
	util.RespondWithJSON(w, http.StatusOK, v1.NewRecordReply{
		Response:         hex.EncodeToString(resp[:]),
		CensorshipRecord: cr,
	})
}

func (p *TestPoliteiad) handleUpdateVettedRecord(w http.ResponseWriter, r *http.Request) {
	var t v1.UpdateRecord
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&t); err != nil {
		util.RespondWithJSON(w, http.StatusBadRequest, err)
		return
	}

	challenge, err := hex.DecodeString(t.Challenge)
	if err != nil || len(challenge) != v1.ChallengeSize {
		respondWithUserError(w, v1.ErrorStatusInvalidChallenge, nil)
		return
	}

	prop, _ := p.record(t.Token)
	version, _ := strconv.Atoi(prop.Version)
	updatedVersion := strconv.Itoa(version + 1)

	updated := v1.Record{
		Status:           prop.Status,
		Timestamp:        time.Now().Unix(),
		CensorshipRecord: prop.CensorshipRecord,
		Version:          updatedVersion,
		Metadata:         t.MDOverwrite,
		Files:            t.FilesAdd,
	}

	// Update record in store
	p.updateRecord(updated)

	// Update record in cache
	err = p.cache.UpdateRecord(convertRecordToCache(updated))
	if err != nil {
		util.RespondWithJSON(w, http.StatusInternalServerError, err)
		return
	}

	response := p.identity.SignMessage(challenge)
	util.RespondWithJSON(w, http.StatusOK, v1.UpdateRecordReply{
		Response: hex.EncodeToString(response[:]),
	})
}

func (p *TestPoliteiad) handleSetUnvettedStatus(w http.ResponseWriter, r *http.Request) {
	// Decode request
	var t v1.SetUnvettedStatus
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&t); err != nil {
		respondWithUserError(w, v1.ErrorStatusInvalidRequestPayload, nil)
		return
	}

	// Verify challenge
	challenge, err := hex.DecodeString(t.Challenge)
	if err != nil || len(challenge) != v1.ChallengeSize {
		respondWithUserError(w, v1.ErrorStatusInvalidChallenge, nil)
		return
	}
	response := p.identity.SignMessage(challenge)

	// Validate token
	_, err = util.ConvertStringToken(t.Token)
	if err != nil {
		respondWithUserError(w, v1.ErrorStatusInvalidRequestPayload, nil)
		return
	}

	// Lookup record
	rc, err := p.record(t.Token)
	if err != nil {
		if err == errRecordNotFound {
			respondWithUserError(w, v1.ErrorStatusRecordFound, nil)
			return
		}

		util.RespondWithJSON(w, http.StatusInternalServerError, err)
		return
	}

	// Overwrite specified metadata
	for i, j := range rc.Metadata {
		for _, v := range t.MDOverwrite {
			if j.ID == v.ID {
				rc.Metadata[i] = v
			}
		}
	}

	// Update record
	rc.Status = t.Status
	rc.Timestamp = time.Now().Unix()
	rc.Metadata = append(rc.Metadata, t.MDAppend...)
	p.addRecord(*rc)

	// Update cache
	s := convertRecordStatusToCache(rc.Status)
	m := convertMetadataStreamsToCache(rc.Metadata)
	err = p.cache.UpdateRecordStatus(t.Token, rc.Version,
		s, rc.Timestamp, m)
	if err != nil {
		log.Printf("cache update record status: %v", err)
	}

	// Send response
	util.RespondWithJSON(w, http.StatusOK,
		v1.SetUnvettedStatusReply{
			Response: hex.EncodeToString(response[:]),
		})
}

func (p *TestPoliteiad) handlePluginCommand(w http.ResponseWriter, r *http.Request) {
	// Decode request
	var t v1.PluginCommand
	decoder := json.NewDecoder(r.Body)

	if err := decoder.Decode(&t); err != nil {
		respondWithUserError(w, v1.ErrorStatusInvalidRequestPayload, nil)
		return
	}

	// Verify challenge
	challenge, err := hex.DecodeString(t.Challenge)
	if err != nil || len(challenge) != v1.ChallengeSize {
		respondWithUserError(w, v1.ErrorStatusInvalidChallenge, nil)
		return
	}
	response := p.identity.SignMessage(challenge)

	payload, err := p.decredExec(t)
	if err != nil {
		respondWithUserError(w, v1.ErrorStatusInvalidRequestPayload, nil)
		return
	}

	util.RespondWithJSON(w, http.StatusOK,
		v1.PluginCommandReply{
			Response:  hex.EncodeToString(response[:]),
			ID:        t.ID,
			Command:   t.Command,
			CommandID: t.CommandID,
			Payload:   payload,
		})
}

func (p *TestPoliteiad) handleSetVettedStatus(w http.ResponseWriter, r *http.Request) {
	// Decode request
	var t v1.SetVettedStatus
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&t); err != nil {
		respondWithUserError(w, v1.ErrorStatusInvalidRequestPayload, nil)
		return
	}

	// Verify challenge
	challenge, err := hex.DecodeString(t.Challenge)
	if err != nil || len(challenge) != v1.ChallengeSize {
		respondWithUserError(w, v1.ErrorStatusInvalidChallenge, nil)
		return
	}
	response := p.identity.SignMessage(challenge)

	// Validate token
	_, err = util.ConvertStringToken(t.Token)
	if err != nil {
		respondWithUserError(w, v1.ErrorStatusInvalidRequestPayload, nil)
		return
	}

	// Lookup record
	rc, err := p.record(t.Token)
	if err != nil {
		if err == errRecordNotFound {
			respondWithUserError(w, v1.ErrorStatusRecordFound, nil)
			return
		}

		util.RespondWithJSON(w, http.StatusInternalServerError, err)
		return
	}

	// Overwrite specified metadata
	for i, j := range rc.Metadata {
		for _, v := range t.MDOverwrite {
			if j.ID == v.ID {
				rc.Metadata[i] = v
			}
		}
	}

	// Update record
	rc.Status = t.Status
	rc.Timestamp = time.Now().Unix()
	rc.Metadata = append(rc.Metadata, t.MDAppend...)
	p.addRecord(*rc)

	// Update cache
	s := convertRecordStatusToCache(rc.Status)
	m := convertMetadataStreamsToCache(rc.Metadata)
	err = p.cache.UpdateRecordStatus(t.Token, rc.Version,
		s, rc.Timestamp, m)
	if err != nil {
		log.Printf("cache update record status: %v", err)
	}

	// Send response
	util.RespondWithJSON(w, http.StatusOK,
		v1.SetUnvettedStatusReply{
			Response: hex.EncodeToString(response[:]),
		})
}

// Plugin is a pass through function for plugin commands. The plugin command
// is executed in politeiad and is then passed to the cache. This function
// is intended to be used as a way to setup test data.
func (p *TestPoliteiad) Plugin(t *testing.T, pc v1.PluginCommand) {
	t.Helper()

	// Execute plugin command
	var payload string
	var err error
	switch pc.ID {
	case decred.ID:
		payload, err = p.decredExec(pc)
	default:
		t.Fatalf("invalid plugin")
	}

	if err != nil {
		t.Fatal(err)
	}

	// Send plugin cmd to cache
	_, err = p.cache.PluginExec(
		cache.PluginCommand{
			ID:             pc.ID,
			Command:        pc.Command,
			CommandPayload: pc.Payload,
			ReplyPayload:   payload,
		})
	if err != nil {
		t.Fatal(err)
	}
}

// AddRecord adds a record to the politeiad records store and to the cache.
// This function is intended to be used as a way to setup test data.
func (p *TestPoliteiad) AddRecord(t *testing.T, r v1.Record) {
	t.Helper()

	// Add record to memory store
	p.addRecord(r)

	// Add record to cache
	err := p.cache.NewRecord(convertRecordToCache(r))
	if err != nil {
		t.Fatal(err)
	}
}

// Close shuts down the httptest server.
func (p *TestPoliteiad) Close() {
	p.server.Close()
}

// New returns a new TestPoliteiad context.
func New(t *testing.T, c cache.Cache) *TestPoliteiad {
	t.Helper()

	// Setup politeiad identity
	id, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}

	// Init context
	p := TestPoliteiad{
		PublicIdentity:   &id.Public,
		identity:         id,
		cache:            c,
		records:          make(map[string]map[string]v1.Record),
		authorizeVotes:   make(map[string]map[string]decred.AuthorizeVote),
		startVotes:       make(map[string]decred.StartVoteV2),
		startVoteReplies: make(map[string]decred.StartVoteReply),
	}

	// Setup routes
	router := mux.NewRouter()
	router.HandleFunc(v1.NewRecordRoute, p.handleNewRecord)
	router.HandleFunc(v1.UpdateVettedRoute, p.handleUpdateVettedRecord)
	router.HandleFunc(v1.SetUnvettedStatusRoute, p.handleSetUnvettedStatus)
	router.HandleFunc(v1.SetVettedStatusRoute, p.handleSetVettedStatus)
	router.HandleFunc(v1.PluginCommandRoute, p.handlePluginCommand)

	// Setup the test server
	p.server = httptest.NewServer(router)
	p.URL = p.server.URL

	return &p
}
