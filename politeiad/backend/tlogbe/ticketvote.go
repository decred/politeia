// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlogbe

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/dcrec/secp256k1/v3/ecdsa"
	"github.com/decred/dcrd/dcrutil/v3"
	"github.com/decred/dcrd/wire"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe/store"
	"github.com/decred/politeia/politeiad/plugins/dcrdata"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	"github.com/decred/politeia/util"
)

const (
	// Plugin setting IDs
	pluginSettingVoteDurationMin = "votedurationmin"
	pluginSettingVoteDurationMax = "votedurationmax"

	// Filenames of cached data saved to the plugin data dir. Brackets
	// are used to indicate a variable that should be replaced in the
	// filename.
	filenameSummary = "{token}-summary.json"

	// Blob entry data descriptors
	dataDescriptorAuthDetails     = "authdetails"
	dataDescriptorVoteDetails     = "votedetails"
	dataDescriptorCastVoteDetails = "castvotedetails"

	// Prefixes that are appended to key-value store keys before
	// storing them in the log leaf ExtraData field.
	keyPrefixAuthDetails     = "authdetails:"
	keyPrefixVoteDetails     = "votedetails:"
	keyPrefixCastVoteDetails = "castvotedetails:"
)

var (
	_ pluginClient = (*ticketVotePlugin)(nil)
)

// TODO holding the lock before verifying the token can allow the mutexes to
// be spammed. Create an infinite amount of them with invalid tokens. The fix
// is to check if the record exists in the mutexes function to ensure a token
// is valid before holding the lock on it.

// TODO verify all writes only accept full length tokens

// ticketVotePlugin satisfies the pluginClient interface.
type ticketVotePlugin struct {
	sync.Mutex
	backend         backend.Backend
	tlog            tlogClient
	activeNetParams *chaincfg.Params

	// Plugin settings
	voteDurationMin uint32 // In blocks
	voteDurationMax uint32 // In blocks

	// dataDir is the ticket vote plugin data directory. The only data
	// that is stored here is cached data that can be re-created at any
	// time by walking the trillian trees. Ex, the vote summary once a
	// record vote has ended.
	dataDir string

	// identity contains the full identity that the plugin uses to
	// create receipts, i.e. signatures of user provided data that
	// prove the backend received and processed a plugin command.
	identity *identity.FullIdentity

	// inv contains the record inventory categorized by vote status.
	// The inventory will only contain public, non-abandoned records.
	// This cache is built on startup.
	inv voteInventory

	// votes contains the cast votes of ongoing record votes. This
	// cache is built on startup and record entries are removed once
	// the vote has ended and the vote summary has been saved.
	votes map[string]map[string]string // [token][ticket]voteBit

	// Mutexes contains a mutex for each record and are used to lock
	// the trillian tree for a given record to prevent concurrent
	// ticket vote plugin updates to the same tree. They are not used
	// to update any of the ticket vote plugin memory caches. These
	// mutexes are lazy loaded.
	mutexes map[string]*sync.Mutex // [string]mutex
}

// voteInventory contains the record inventory categorized by vote status. The
// authorized and started lists are updated in real-time since ticket vote
// plugin commands initiate those actions. The unauthorized and finished lists
// are lazy loaded since those lists depends on external state.
type voteInventory struct {
	unauthorized []string          // Unauthorized tokens
	authorized   []string          // Authorized tokens
	started      map[string]uint32 // [token]endHeight
	finished     []string          // Finished tokens
	bestBlock    uint32            // Height of last inventory update
}

func (p *ticketVotePlugin) inventorySetToAuthorized(token string) {
	p.Lock()
	defer p.Unlock()

	// Remove the token from the unauthorized list. The unauthorize
	// list is lazy loaded so it may or may not exist.
	var i int
	var found bool
	for k, v := range p.inv.unauthorized {
		if v == token {
			i = k
			found = true
			break
		}
	}
	if found {
		// Remove the token from unauthorized
		u := p.inv.unauthorized
		u = append(u[:i], u[i+1:]...)
		p.inv.unauthorized = u

		log.Debugf("ticketvote: removed from unauthorized inv: %v", token)
	}

	// Prepend the token to the authorized list
	a := p.inv.authorized
	a = append([]string{token}, a...)
	p.inv.authorized = a

	log.Debugf("ticketvote: added to authorized inv: %v", token)
}

func (p *ticketVotePlugin) inventorySetToUnauthorized(token string) {
	p.Lock()
	defer p.Unlock()

	// Remove the token from the authorized list if it exists. Going
	// from authorized to unauthorized can happen when a vote
	// authorization is revoked.
	var i int
	var found bool
	for k, v := range p.inv.authorized {
		if v == token {
			i = k
			found = true
			break
		}
	}
	if found {
		// Remove the token from authorized
		a := p.inv.authorized
		a = append(a[:i], a[i+1:]...)
		p.inv.authorized = a

		log.Debugf("ticketvote: removed from authorized inv: %v", token)
	}

	// Prepend the token to the unauthorized list
	u := p.inv.unauthorized
	u = append([]string{token}, u...)
	p.inv.unauthorized = u

	log.Debugf("ticketvote: added to unauthorized inv: %v", token)
}

func (p *ticketVotePlugin) inventorySetToStarted(token string, t ticketvote.VoteT, endHeight uint32) {
	p.Lock()
	defer p.Unlock()

	switch t {
	case ticketvote.VoteTypeStandard:
		// Remove the token from the authorized list. The token should
		// always be in the authorized list prior to the vote being
		// started for standard votes so panicing when this is not the
		// case is ok.
		var i int
		var found bool
		for k, v := range p.inv.authorized {
			if v == token {
				i = k
				found = true
				break
			}
		}
		if !found {
			e := fmt.Sprintf("token not found in authorized list: %v", token)
			panic(e)
		}

		a := p.inv.authorized
		a = append(a[:i], a[i+1:]...)
		p.inv.authorized = a

		log.Debugf("ticketvote: removed from authorized inv: %v", token)

	case ticketvote.VoteTypeRunoff:
		// A runoff vote does not require the submission votes be
		// authorized prior to the vote starting. The token might be in
		// the unauthorized list, but its also possible that its not
		// since the unauthorized list is lazy loaded and it might not
		// have been added yet. Remove it only if it is found.
		var i int
		var found bool
		for k, v := range p.inv.unauthorized {
			if v == token {
				i = k
				found = true
				break
			}
		}
		if found {
			// Remove the token from unauthorized
			u := p.inv.unauthorized
			u = append(u[:i], u[i+1:]...)
			p.inv.unauthorized = u

			log.Debugf("ticketvote: removed from unauthorized inv: %v", token)
		}

	default:
		e := fmt.Sprintf("invalid vote type %v", t)
		panic(e)
	}

	// Add the token to the started list
	p.inv.started[token] = endHeight

	log.Debugf("ticketvote: added to started inv: %v", token)
}

func (p *ticketVotePlugin) inventory(bestBlock uint32) (*voteInventory, error) {
	p.Lock()
	defer p.Unlock()

	// Check backend inventory for new records
	invBackend, err := p.backend.InventoryByStatus()
	if err != nil {
		return nil, fmt.Errorf("InventoryByStatus: %v", err)
	}

	// Find number of records in the vetted inventory
	var vettedInvCount int
	for _, tokens := range invBackend.Vetted {
		vettedInvCount += len(tokens)
	}

	// Find number of records in the vote inventory
	voteInvCount := len(p.inv.unauthorized) + len(p.inv.authorized) +
		len(p.inv.started) + len(p.inv.finished)

	// The vetted inventory count and the vote inventory count should
	// be the same. If they're not then it means we there are records
	// missing from vote inventory.
	if vettedInvCount != voteInvCount {
		// Records are missing from the vote inventory. Put all ticket
		// vote inventory records into a map so we can easily find what
		// backend records are missing.
		all := make(map[string]struct{}, voteInvCount)
		for _, v := range p.inv.unauthorized {
			all[v] = struct{}{}
		}
		for _, v := range p.inv.authorized {
			all[v] = struct{}{}
		}
		for k := range p.inv.started {
			all[k] = struct{}{}
		}
		for _, v := range p.inv.finished {
			all[v] = struct{}{}
		}

		// Add missing records to the vote inventory
		for _, tokens := range invBackend.Vetted {
			for _, v := range tokens {
				if _, ok := all[v]; ok {
					// Record is already in the vote inventory
					continue
				}
				// We can assume that the record vote status is unauthorized
				// since it would have already been added to the vote
				// inventory during the authorization request if one had
				// occurred.
				p.inv.unauthorized = append(p.inv.unauthorized, v)

				log.Debugf("ticketvote: added to unauthorized inv: %v", v)
			}
		}
	}

	// The records are moved to their correct vote status category in
	// the inventory on authorization, revoking the authorization, and
	// on starting the vote. We can assume these lists are already
	// up-to-date. The last thing we must check for is whether any
	// votes have finished since the last inventory update.

	// Check if the inventory has been updated for this block height.
	if p.inv.bestBlock == bestBlock {
		// Inventory already updated. Nothing else to do.
		goto reply
	}

	// Inventory has not been updated for this block height. Check if
	// any proposal votes have finished.
	for token, endHeight := range p.inv.started {
		if bestBlock >= endHeight {
			// Vote has finished. Remove it from the started list.
			delete(p.inv.started, token)

			log.Debugf("ticketvote: removed from started inv: %v", token)

			// Add it to the finished list
			p.inv.finished = append(p.inv.finished, token)

			log.Debugf("ticketvote: added to finished inv: %v", token)
		}
	}

	// Update best block
	p.inv.bestBlock = bestBlock

	log.Debugf("ticketvote: inv updated for best block %v", bestBlock)

reply:
	// Return a copy of the inventory
	var (
		unauthorized = make([]string, len(p.inv.unauthorized))
		authorized   = make([]string, len(p.inv.authorized))
		started      = make(map[string]uint32, len(p.inv.started))
		finished     = make([]string, len(p.inv.finished))
	)
	copy(unauthorized, p.inv.unauthorized)
	copy(authorized, p.inv.authorized)
	copy(finished, p.inv.finished)
	for k, v := range p.inv.started {
		started[k] = v
	}

	return &voteInventory{
		unauthorized: unauthorized,
		authorized:   authorized,
		started:      started,
		finished:     finished,
		bestBlock:    p.inv.bestBlock,
	}, nil
}

func (p *ticketVotePlugin) cachedVotes(token []byte) map[string]string {
	p.Lock()
	defer p.Unlock()

	// Return a copy of the map
	cv, ok := p.votes[hex.EncodeToString(token)]
	if !ok {
		return map[string]string{}
	}
	c := make(map[string]string, len(cv))
	for k, v := range cv {
		c[k] = v
	}

	return c
}

func (p *ticketVotePlugin) cachedVotesSet(token, ticket, voteBit string) {
	p.Lock()
	defer p.Unlock()

	_, ok := p.votes[token]
	if !ok {
		p.votes[token] = make(map[string]string, 40960) // Ticket pool size
	}

	p.votes[token][ticket] = voteBit

	log.Debugf("ticketvote: added vote to cache: %v %v %v",
		token, ticket, voteBit)
}

func (p *ticketVotePlugin) cachedVotesDel(token string) {
	p.Lock()
	defer p.Unlock()

	delete(p.votes, token)

	log.Debugf("ticketvote: deleted votes cache: %v", token)
}

// cachedSummaryPath accepts both full tokens and token prefixes, however it
// always uses the token prefix when generatig the path.
func (p *ticketVotePlugin) cachedSummaryPath(token string) (string, error) {
	// Use token prefix
	t, err := tokenDecodeAnyLength(token)
	if err != nil {
		return "", err
	}
	token = tokenPrefix(t)
	fn := strings.Replace(filenameSummary, "{token}", token, 1)
	return filepath.Join(p.dataDir, fn), nil
}

func (p *ticketVotePlugin) cachedSummary(token string) (*ticketvote.Summary, error) {
	p.Lock()
	defer p.Unlock()

	fp, err := p.cachedSummaryPath(token)
	if err != nil {
		return nil, err
	}
	b, err := ioutil.ReadFile(fp)
	if err != nil {
		var e *os.PathError
		if errors.As(err, &e) && !os.IsExist(err) {
			// File does't exist
			return nil, errRecordNotFound
		}
		return nil, err
	}

	var s ticketvote.Summary
	err = json.Unmarshal(b, &s)
	if err != nil {
		return nil, err
	}

	return &s, nil
}

func (p *ticketVotePlugin) cachedSummarySave(token string, s ticketvote.Summary) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}

	p.Lock()
	defer p.Unlock()

	fp, err := p.cachedSummaryPath(token)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(fp, b, 0664)
	if err != nil {
		return err
	}

	log.Debugf("ticketvote: saved votes summary: %v", token)

	return nil
}

// mutex returns the mutex for the specified record.
func (p *ticketVotePlugin) mutex(token string) *sync.Mutex {
	p.Lock()
	defer p.Unlock()

	m, ok := p.mutexes[token]
	if !ok {
		// Mutexes is lazy loaded
		m = &sync.Mutex{}
		p.mutexes[token] = m
	}

	return m
}

func convertTicketVoteErrFromSignatureErr(err error) backend.PluginUserError {
	var e util.SignatureError
	var s ticketvote.ErrorStatusT
	if errors.As(err, &e) {
		switch e.ErrorCode {
		case util.ErrorStatusPublicKeyInvalid:
			s = ticketvote.ErrorStatusPublicKeyInvalid
		case util.ErrorStatusSignatureInvalid:
			s = ticketvote.ErrorStatusSignatureInvalid
		}
	}
	return backend.PluginUserError{
		PluginID:     ticketvote.ID,
		ErrorCode:    int(s),
		ErrorContext: e.ErrorContext,
	}
}

func convertAuthDetailsFromBlobEntry(be store.BlobEntry) (*ticketvote.AuthDetails, error) {
	// Decode and validate data hint
	b, err := base64.StdEncoding.DecodeString(be.DataHint)
	if err != nil {
		return nil, fmt.Errorf("decode DataHint: %v", err)
	}
	var dd store.DataDescriptor
	err = json.Unmarshal(b, &dd)
	if err != nil {
		return nil, fmt.Errorf("unmarshal DataHint: %v", err)
	}
	if dd.Descriptor != dataDescriptorAuthDetails {
		return nil, fmt.Errorf("unexpected data descriptor: got %v, want %v",
			dd.Descriptor, dataDescriptorAuthDetails)
	}

	// Decode data
	b, err = base64.StdEncoding.DecodeString(be.Data)
	if err != nil {
		return nil, fmt.Errorf("decode Data: %v", err)
	}
	hash, err := hex.DecodeString(be.Hash)
	if err != nil {
		return nil, fmt.Errorf("decode hash: %v", err)
	}
	if !bytes.Equal(util.Digest(b), hash) {
		return nil, fmt.Errorf("data is not coherent; got %x, want %x",
			util.Digest(b), hash)
	}
	var ad ticketvote.AuthDetails
	err = json.Unmarshal(b, &ad)
	if err != nil {
		return nil, fmt.Errorf("unmarshal AuthDetails: %v", err)
	}

	return &ad, nil
}

func convertVoteDetailsFromBlobEntry(be store.BlobEntry) (*ticketvote.VoteDetails, error) {
	// Decode and validate data hint
	b, err := base64.StdEncoding.DecodeString(be.DataHint)
	if err != nil {
		return nil, fmt.Errorf("decode DataHint: %v", err)
	}
	var dd store.DataDescriptor
	err = json.Unmarshal(b, &dd)
	if err != nil {
		return nil, fmt.Errorf("unmarshal DataHint: %v", err)
	}
	if dd.Descriptor != dataDescriptorVoteDetails {
		return nil, fmt.Errorf("unexpected data descriptor: got %v, want %v",
			dd.Descriptor, dataDescriptorVoteDetails)
	}

	// Decode data
	b, err = base64.StdEncoding.DecodeString(be.Data)
	if err != nil {
		return nil, fmt.Errorf("decode Data: %v", err)
	}
	hash, err := hex.DecodeString(be.Hash)
	if err != nil {
		return nil, fmt.Errorf("decode hash: %v", err)
	}
	if !bytes.Equal(util.Digest(b), hash) {
		return nil, fmt.Errorf("data is not coherent; got %x, want %x",
			util.Digest(b), hash)
	}
	var vd ticketvote.VoteDetails
	err = json.Unmarshal(b, &vd)
	if err != nil {
		return nil, fmt.Errorf("unmarshal VoteDetails: %v", err)
	}

	return &vd, nil
}

func convertCastVoteDetailsFromBlobEntry(be store.BlobEntry) (*ticketvote.CastVoteDetails, error) {
	// Decode and validate data hint
	b, err := base64.StdEncoding.DecodeString(be.DataHint)
	if err != nil {
		return nil, fmt.Errorf("decode DataHint: %v", err)
	}
	var dd store.DataDescriptor
	err = json.Unmarshal(b, &dd)
	if err != nil {
		return nil, fmt.Errorf("unmarshal DataHint: %v", err)
	}
	if dd.Descriptor != dataDescriptorCastVoteDetails {
		return nil, fmt.Errorf("unexpected data descriptor: got %v, want %v",
			dd.Descriptor, dataDescriptorCastVoteDetails)
	}

	// Decode data
	b, err = base64.StdEncoding.DecodeString(be.Data)
	if err != nil {
		return nil, fmt.Errorf("decode Data: %v", err)
	}
	hash, err := hex.DecodeString(be.Hash)
	if err != nil {
		return nil, fmt.Errorf("decode hash: %v", err)
	}
	if !bytes.Equal(util.Digest(b), hash) {
		return nil, fmt.Errorf("data is not coherent; got %x, want %x",
			util.Digest(b), hash)
	}
	var cv ticketvote.CastVoteDetails
	err = json.Unmarshal(b, &cv)
	if err != nil {
		return nil, fmt.Errorf("unmarshal CastVoteDetails: %v", err)
	}

	return &cv, nil
}

func convertBlobEntryFromAuthDetails(ad ticketvote.AuthDetails) (*store.BlobEntry, error) {
	data, err := json.Marshal(ad)
	if err != nil {
		return nil, err
	}
	hint, err := json.Marshal(
		store.DataDescriptor{
			Type:       store.DataTypeStructure,
			Descriptor: dataDescriptorAuthDetails,
		})
	if err != nil {
		return nil, err
	}
	be := store.NewBlobEntry(hint, data)
	return &be, nil
}

func convertBlobEntryFromVoteDetails(vd ticketvote.VoteDetails) (*store.BlobEntry, error) {
	data, err := json.Marshal(vd)
	if err != nil {
		return nil, err
	}
	hint, err := json.Marshal(
		store.DataDescriptor{
			Type:       store.DataTypeStructure,
			Descriptor: dataDescriptorVoteDetails,
		})
	if err != nil {
		return nil, err
	}
	be := store.NewBlobEntry(hint, data)
	return &be, nil
}

func convertBlobEntryFromCastVoteDetails(cv ticketvote.CastVoteDetails) (*store.BlobEntry, error) {
	data, err := json.Marshal(cv)
	if err != nil {
		return nil, err
	}
	hint, err := json.Marshal(
		store.DataDescriptor{
			Type:       store.DataTypeStructure,
			Descriptor: dataDescriptorCastVoteDetails,
		})
	if err != nil {
		return nil, err
	}
	be := store.NewBlobEntry(hint, data)
	return &be, nil
}

func (p *ticketVotePlugin) authorizeSave(ad ticketvote.AuthDetails) error {
	token, err := hex.DecodeString(ad.Token)
	if err != nil {
		return err
	}

	// Prepare blob
	be, err := convertBlobEntryFromAuthDetails(ad)
	if err != nil {
		return err
	}
	h, err := hex.DecodeString(be.Hash)
	if err != nil {
		return err
	}
	b, err := store.Blobify(*be)
	if err != nil {
		return err
	}

	// Save blob
	merkles, err := p.tlog.save(tlogIDVetted, token, keyPrefixAuthDetails,
		[][]byte{b}, [][]byte{h}, false)
	if err != nil {
		return fmt.Errorf("save: %v", err)
	}
	if len(merkles) != 1 {
		return fmt.Errorf("invalid merkle leaf hash count; got %v, want 1",
			len(merkles))
	}

	return nil
}

func (p *ticketVotePlugin) authorizes(token []byte) ([]ticketvote.AuthDetails, error) {
	// Retrieve blobs
	blobs, err := p.tlog.blobsByKeyPrefix(tlogIDVetted, token,
		keyPrefixAuthDetails)
	if err != nil {
		return nil, err
	}

	// Decode blobs
	auths := make([]ticketvote.AuthDetails, 0, len(blobs))
	for _, v := range blobs {
		be, err := store.Deblob(v)
		if err != nil {
			return nil, err
		}
		a, err := convertAuthDetailsFromBlobEntry(*be)
		if err != nil {
			return nil, err
		}
		auths = append(auths, *a)
	}

	// Sort from oldest to newest
	sort.SliceStable(auths, func(i, j int) bool {
		return auths[i].Timestamp < auths[j].Timestamp
	})

	return auths, nil
}

func (p *ticketVotePlugin) voteDetailsSave(vd ticketvote.VoteDetails) error {
	token, err := hex.DecodeString(vd.Params.Token)
	if err != nil {
		return err
	}

	// Prepare blob
	be, err := convertBlobEntryFromVoteDetails(vd)
	if err != nil {
		return err
	}
	h, err := hex.DecodeString(be.Hash)
	if err != nil {
		return err
	}
	b, err := store.Blobify(*be)
	if err != nil {
		return err
	}

	// Save blob
	merkles, err := p.tlog.save(tlogIDVetted, token, keyPrefixVoteDetails,
		[][]byte{b}, [][]byte{h}, false)
	if err != nil {
		return fmt.Errorf("Save: %v", err)
	}
	if len(merkles) != 1 {
		return fmt.Errorf("invalid merkle leaf hash count; got %v, want 1",
			len(merkles))
	}

	return nil
}

func (p *ticketVotePlugin) voteDetails(token []byte) (*ticketvote.VoteDetails, error) {
	// Retrieve blobs
	blobs, err := p.tlog.blobsByKeyPrefix(tlogIDVetted, token,
		keyPrefixVoteDetails)
	if err != nil {
		return nil, err
	}
	switch len(blobs) {
	case 0:
		// A vote details does not exist
		return nil, nil
	case 1:
		// A vote details exists; continue
	default:
		// This should not happen. There should only ever be a max of
		// one vote details.
		return nil, fmt.Errorf("multiple vote detailss found (%v) for record %x",
			len(blobs), token)
	}

	// Decode blob
	be, err := store.Deblob(blobs[0])
	if err != nil {
		return nil, err
	}
	vd, err := convertVoteDetailsFromBlobEntry(*be)
	if err != nil {
		return nil, err
	}

	return vd, nil
}

func (p *ticketVotePlugin) castVoteSave(cv ticketvote.CastVoteDetails) error {
	token, err := hex.DecodeString(cv.Token)
	if err != nil {
		return err
	}

	// Prepare blob
	be, err := convertBlobEntryFromCastVoteDetails(cv)
	if err != nil {
		return err
	}
	h, err := hex.DecodeString(be.Hash)
	if err != nil {
		return err
	}
	b, err := store.Blobify(*be)
	if err != nil {
		return err
	}

	// Save blob
	merkles, err := p.tlog.save(tlogIDVetted, token, keyPrefixCastVoteDetails,
		[][]byte{b}, [][]byte{h}, false)
	if err != nil {
		return fmt.Errorf("save: %v", err)
	}
	if len(merkles) != 1 {
		return fmt.Errorf("invalid merkle leaf hash count; got %v, want 1",
			len(merkles))
	}

	return nil
}

func (p *ticketVotePlugin) castVotes(token []byte) ([]ticketvote.CastVoteDetails, error) {
	// Retrieve blobs
	blobs, err := p.tlog.blobsByKeyPrefix(tlogIDVetted, token,
		keyPrefixCastVoteDetails)
	if err != nil {
		return nil, err
	}

	// Decode blobs
	votes := make([]ticketvote.CastVoteDetails, 0, len(blobs))
	for _, v := range blobs {
		be, err := store.Deblob(v)
		if err != nil {
			return nil, err
		}
		cv, err := convertCastVoteDetailsFromBlobEntry(*be)
		if err != nil {
			return nil, err
		}
		votes = append(votes, *cv)
	}

	// Sort by ticket hash
	sort.SliceStable(votes, func(i, j int) bool {
		return votes[i].Ticket < votes[j].Ticket
	})

	return votes, nil
}

// bestBlock fetches the best block from the dcrdata plugin and returns it. If
// the dcrdata connection is not active, an error will be returned.
func (p *ticketVotePlugin) bestBlock() (uint32, error) {
	// Get best block
	payload, err := dcrdata.EncodeBestBlock(dcrdata.BestBlock{})
	if err != nil {
		return 0, err
	}
	reply, err := p.backend.Plugin(dcrdata.ID,
		dcrdata.CmdBestBlock, "", string(payload))
	if err != nil {
		return 0, fmt.Errorf("Plugin %v %v: %v",
			dcrdata.ID, dcrdata.CmdBestBlock, err)
	}

	// Handle response
	bbr, err := dcrdata.DecodeBestBlockReply([]byte(reply))
	if err != nil {
		return 0, err
	}
	if bbr.Status != dcrdata.StatusConnected {
		// The dcrdata connection is down. The best block cannot be
		// trusted as being accurate.
		return 0, fmt.Errorf("dcrdata connection is down")
	}
	if bbr.Height == 0 {
		return 0, fmt.Errorf("invalid best block height 0")
	}

	return bbr.Height, nil
}

// bestBlockUnsafe fetches the best block from the dcrdata plugin and returns
// it. If the dcrdata connection is not active, an error WILL NOT be returned.
// The dcrdata cached best block height will be returned even though it may be
// stale. Use bestBlock() if the caller requires a guarantee that the best
// block is not stale.
func (p *ticketVotePlugin) bestBlockUnsafe() (uint32, error) {
	// Get best block
	payload, err := dcrdata.EncodeBestBlock(dcrdata.BestBlock{})
	if err != nil {
		return 0, err
	}
	reply, err := p.backend.Plugin(dcrdata.ID,
		dcrdata.CmdBestBlock, "", string(payload))
	if err != nil {
		return 0, fmt.Errorf("Plugin %v %v: %v",
			dcrdata.ID, dcrdata.CmdBestBlock, err)
	}

	// Handle response
	bbr, err := dcrdata.DecodeBestBlockReply([]byte(reply))
	if err != nil {
		return 0, err
	}
	if bbr.Height == 0 {
		return 0, fmt.Errorf("invalid best block height 0")
	}

	return bbr.Height, nil
}

type commitmentAddr struct {
	ticket string // Ticket hash
	addr   string // Commitment address
	err    error  // Error if one occurred
}

func (p *ticketVotePlugin) largestCommitmentAddrs(tickets []string) ([]commitmentAddr, error) {
	// Get tx details
	tt := dcrdata.TxsTrimmed{
		TxIDs: tickets,
	}
	payload, err := dcrdata.EncodeTxsTrimmed(tt)
	if err != nil {
		return nil, err
	}
	reply, err := p.backend.Plugin(dcrdata.ID,
		dcrdata.CmdTxsTrimmed, "", string(payload))
	if err != nil {
		return nil, fmt.Errorf("Plugin %v %v: %v",
			dcrdata.ID, dcrdata.CmdTxsTrimmed, err)
	}
	ttr, err := dcrdata.DecodeTxsTrimmedReply([]byte(reply))
	if err != nil {
		return nil, err
	}

	// Find the largest commitment address for each tx
	addrs := make([]commitmentAddr, 0, len(ttr.Txs))
	for _, tx := range ttr.Txs {
		var (
			bestAddr string  // Addr with largest commitment amount
			bestAmt  float64 // Largest commitment amount
			addrErr  error   // Error if one is encountered
		)
		for _, vout := range tx.Vout {
			scriptPubKey := vout.ScriptPubKeyDecoded
			switch {
			case scriptPubKey.CommitAmt == nil:
				// No commitment amount; continue
			case len(scriptPubKey.Addresses) == 0:
				// No commitment address; continue
			case *scriptPubKey.CommitAmt > bestAmt:
				// New largest commitment address found
				bestAddr = scriptPubKey.Addresses[0]
				bestAmt = *scriptPubKey.CommitAmt
			}
		}
		if bestAddr == "" || bestAmt == 0.0 {
			addrErr = fmt.Errorf("no largest commitment address found")
		}

		// Store result
		addrs = append(addrs, commitmentAddr{
			ticket: tx.TxID,
			addr:   bestAddr,
			err:    addrErr,
		})
	}

	return addrs, nil
}

// startReply fetches all required data and returns a StartReply.
func (p *ticketVotePlugin) startReply(duration uint32) (*ticketvote.StartReply, error) {
	// Get the best block height
	bb, err := p.bestBlock()
	if err != nil {
		return nil, fmt.Errorf("bestBlock: %v", err)
	}

	// Find the snapshot height. Subtract the ticket maturity from the
	// block height to get into unforkable territory.
	ticketMaturity := uint32(p.activeNetParams.TicketMaturity)
	snapshotHeight := bb - ticketMaturity

	// Fetch the block details for the snapshot height. We need the
	// block hash in order to fetch the ticket pool snapshot.
	bd := dcrdata.BlockDetails{
		Height: snapshotHeight,
	}
	payload, err := dcrdata.EncodeBlockDetails(bd)
	if err != nil {
		return nil, err
	}
	reply, err := p.backend.Plugin(dcrdata.ID,
		dcrdata.CmdBlockDetails, "", string(payload))
	if err != nil {
		return nil, fmt.Errorf("Plugin %v %v: %v",
			dcrdata.ID, dcrdata.CmdBlockDetails, err)
	}
	bdr, err := dcrdata.DecodeBlockDetailsReply([]byte(reply))
	if err != nil {
		return nil, err
	}
	if bdr.Block.Hash == "" {
		return nil, fmt.Errorf("invalid block hash for height %v", snapshotHeight)
	}
	snapshotHash := bdr.Block.Hash

	// Fetch the ticket pool snapshot
	tp := dcrdata.TicketPool{
		BlockHash: snapshotHash,
	}
	payload, err = dcrdata.EncodeTicketPool(tp)
	if err != nil {
		return nil, err
	}
	reply, err = p.backend.Plugin(dcrdata.ID,
		dcrdata.CmdTicketPool, "", string(payload))
	if err != nil {
		return nil, fmt.Errorf("Plugin %v %v: %v",
			dcrdata.ID, dcrdata.CmdTicketPool, err)
	}
	tpr, err := dcrdata.DecodeTicketPoolReply([]byte(reply))
	if err != nil {
		return nil, err
	}
	if len(tpr.Tickets) == 0 {
		return nil, fmt.Errorf("no tickets found for block %v %v",
			snapshotHeight, snapshotHash)
	}

	// The start block height has the ticket maturity subtracted from
	// it to prevent forking issues. This means we the vote starts in
	// the past. The ticket maturity needs to be added to the end block
	// height to correct for this.
	endBlockHeight := snapshotHeight + duration + ticketMaturity

	return &ticketvote.StartReply{
		StartBlockHeight: snapshotHeight,
		StartBlockHash:   snapshotHash,
		EndBlockHeight:   endBlockHeight,
		EligibleTickets:  tpr.Tickets,
	}, nil
}

// voteMessageVerify verifies a cast vote message is properly signed. Copied
// from: github.com/decred/dcrd/blob/0fc55252f912756c23e641839b1001c21442c38a/rpcserver.go#L5605
func (p *ticketVotePlugin) voteMessageVerify(address, message, signature string) (bool, error) {
	// Decode the provided address.
	addr, err := dcrutil.DecodeAddress(address, p.activeNetParams)
	if err != nil {
		return false, fmt.Errorf("Could not decode address: %v",
			err)
	}

	// Only P2PKH addresses are valid for signing.
	if _, ok := addr.(*dcrutil.AddressPubKeyHash); !ok {
		return false, fmt.Errorf("Address is not a pay-to-pubkey-hash "+
			"address: %v", address)
	}

	// Decode base64 signature.
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, fmt.Errorf("Malformed base64 encoding: %v", err)
	}

	// Validate the signature - this just shows that it was valid at all.
	// we will compare it with the key next.
	var buf bytes.Buffer
	wire.WriteVarString(&buf, 0, "Decred Signed Message:\n")
	wire.WriteVarString(&buf, 0, message)
	expectedMessageHash := chainhash.HashB(buf.Bytes())
	pk, wasCompressed, err := ecdsa.RecoverCompact(sig,
		expectedMessageHash)
	if err != nil {
		// Mirror Bitcoin Core behavior, which treats error in
		// RecoverCompact as invalid signature.
		return false, nil
	}

	// Reconstruct the pubkey hash.
	dcrPK := pk
	var serializedPK []byte
	if wasCompressed {
		serializedPK = dcrPK.SerializeCompressed()
	} else {
		serializedPK = dcrPK.SerializeUncompressed()
	}
	a, err := dcrutil.NewAddressSecpPubKey(serializedPK, p.activeNetParams)
	if err != nil {
		// Again mirror Bitcoin Core behavior, which treats error in
		// public key reconstruction as invalid signature.
		return false, nil
	}

	// Return boolean if addresses match.
	return a.Address() == address, nil
}

func (p *ticketVotePlugin) castVoteSignatureVerify(cv ticketvote.CastVote, addr string) error {
	msg := cv.Token + cv.Ticket + cv.VoteBit

	// Convert hex signature to base64. The voteMessageVerify function
	// expects base64.
	b, err := hex.DecodeString(cv.Signature)
	if err != nil {
		return fmt.Errorf("invalid hex")
	}
	sig := base64.StdEncoding.EncodeToString(b)

	// Verify message
	validated, err := p.voteMessageVerify(addr, msg, sig)
	if err != nil {
		return err
	}
	if !validated {
		return fmt.Errorf("could not verify message")
	}

	return nil
}

func (p *ticketVotePlugin) cmdAuthorize(payload string) (string, error) {
	log.Tracef("ticketvote cmdAuthorize: %v", payload)

	// Decode payload
	a, err := ticketvote.DecodeAuthorize([]byte(payload))
	if err != nil {
		return "", err
	}

	// Verify token
	token, err := tokenDecode(a.Token)
	if err != nil {
		return "", backend.PluginUserError{
			PluginID:  ticketvote.ID,
			ErrorCode: int(ticketvote.ErrorStatusTokenInvalid),
		}
	}

	// Verify signature
	version := strconv.FormatUint(uint64(a.Version), 10)
	msg := a.Token + version + string(a.Action)
	err = util.VerifySignature(a.Signature, a.PublicKey, msg)
	if err != nil {
		return "", convertTicketVoteErrFromSignatureErr(err)
	}

	// Verify action
	switch a.Action {
	case ticketvote.AuthActionAuthorize:
		// This is allowed
	case ticketvote.AuthActionRevoke:
		// This is allowed
	default:
		e := fmt.Sprintf("%v not a valid action", a.Action)
		return "", backend.PluginUserError{
			PluginID:     ticketvote.ID,
			ErrorCode:    int(ticketvote.ErrorStatusAuthorizationInvalid),
			ErrorContext: []string{e},
		}
	}

	// The previous authorize votes must be retrieved to validate the
	// new autorize vote. The lock must be held for the remainder of
	// this function.
	m := p.mutex(a.Token)
	m.Lock()
	defer m.Unlock()

	// Get any previous authorizations to verify that the new action
	// is allowed based on the previous action.
	auths, err := p.authorizes(token)
	if err != nil {
		return "", err
	}
	var prevAction ticketvote.AuthActionT
	if len(auths) > 0 {
		prevAction = ticketvote.AuthActionT(auths[len(auths)-1].Action)
	}
	switch {
	case len(auths) == 0:
		// No previous actions. New action must be an authorize.
		if a.Action != ticketvote.AuthActionAuthorize {
			return "", backend.PluginUserError{
				PluginID:     ticketvote.ID,
				ErrorCode:    int(ticketvote.ErrorStatusAuthorizationInvalid),
				ErrorContext: []string{"no prev action; action must be authorize"},
			}
		}
	case prevAction == ticketvote.AuthActionAuthorize &&
		a.Action != ticketvote.AuthActionRevoke:
		// Previous action was a authorize. This action must be revoke.
		return "", backend.PluginUserError{
			PluginID:     ticketvote.ID,
			ErrorCode:    int(ticketvote.ErrorStatusAuthorizationInvalid),
			ErrorContext: []string{"prev action was authorize"},
		}
	case prevAction == ticketvote.AuthActionRevoke &&
		a.Action != ticketvote.AuthActionAuthorize:
		// Previous action was a revoke. This action must be authorize.
		return "", backend.PluginUserError{
			PluginID:     ticketvote.ID,
			ErrorCode:    int(ticketvote.ErrorStatusAuthorizationInvalid),
			ErrorContext: []string{"prev action was revoke"},
		}
	}

	// Prepare authorize vote
	receipt := p.identity.SignMessage([]byte(a.Signature))
	auth := ticketvote.AuthDetails{
		Token:     a.Token,
		Version:   a.Version,
		Action:    string(a.Action),
		PublicKey: a.PublicKey,
		Signature: a.Signature,
		Timestamp: time.Now().Unix(),
		Receipt:   hex.EncodeToString(receipt[:]),
	}

	// Save authorize vote
	err = p.authorizeSave(auth)
	if err != nil {
		return "", err
	}

	// Update inventory
	switch a.Action {
	case ticketvote.AuthActionAuthorize:
		p.inventorySetToAuthorized(a.Token)
	case ticketvote.AuthActionRevoke:
		p.inventorySetToUnauthorized(a.Token)
	default:
		// Should not happen
		e := fmt.Sprintf("invalid authorize action: %v", a.Action)
		panic(e)
	}

	// Prepare reply
	ar := ticketvote.AuthorizeReply{
		Timestamp: auth.Timestamp,
		Receipt:   auth.Receipt,
	}
	reply, err := ticketvote.EncodeAuthorizeReply(ar)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

func voteBitVerify(options []ticketvote.VoteOption, mask, bit uint64) error {
	if len(options) == 0 {
		return fmt.Errorf("no vote options found")
	}
	if bit == 0 {
		return fmt.Errorf("invalid bit 0x%x", bit)
	}

	// Verify bit is included in mask
	if mask&bit != bit {
		return fmt.Errorf("invalid mask 0x%x bit 0x%x", mask, bit)
	}

	// Verify bit is included in vote options
	for _, v := range options {
		if v.Bit == bit {
			// Bit matches one of the options. We're done.
			return nil
		}
	}

	return fmt.Errorf("bit 0x%x not found in vote options", bit)
}

// TODO test this function
func voteParamsVerify(vote ticketvote.VoteParams, voteDurationMin, voteDurationMax uint32) error {
	// Verify vote type
	switch vote.Type {
	case ticketvote.VoteTypeStandard:
		// This is allowed
	case ticketvote.VoteTypeRunoff:
		// This is allowed
	default:
		e := fmt.Sprintf("invalid type %v", vote.Type)
		return backend.PluginUserError{
			PluginID:     ticketvote.ID,
			ErrorCode:    int(ticketvote.ErrorStatusVoteParamsInvalid),
			ErrorContext: []string{e},
		}
	}

	// Verify vote params
	switch {
	case vote.Duration > voteDurationMax:
		e := fmt.Sprintf("duration %v exceeds max duration %v",
			vote.Duration, voteDurationMax)
		return backend.PluginUserError{
			PluginID:     ticketvote.ID,
			ErrorCode:    int(ticketvote.ErrorStatusVoteParamsInvalid),
			ErrorContext: []string{e},
		}
	case vote.Duration < voteDurationMin:
		e := fmt.Sprintf("duration %v under min duration %v",
			vote.Duration, voteDurationMin)
		return backend.PluginUserError{
			PluginID:     ticketvote.ID,
			ErrorCode:    int(ticketvote.ErrorStatusVoteParamsInvalid),
			ErrorContext: []string{e},
		}
	case vote.QuorumPercentage > 100:
		e := fmt.Sprintf("quorum percent %v exceeds 100 percent",
			vote.QuorumPercentage)
		return backend.PluginUserError{
			PluginID:     ticketvote.ID,
			ErrorCode:    int(ticketvote.ErrorStatusVoteParamsInvalid),
			ErrorContext: []string{e},
		}
	case vote.PassPercentage > 100:
		e := fmt.Sprintf("pass percent %v exceeds 100 percent",
			vote.PassPercentage)
		return backend.PluginUserError{
			PluginID:     ticketvote.ID,
			ErrorCode:    int(ticketvote.ErrorStatusVoteParamsInvalid),
			ErrorContext: []string{e},
		}
	}

	// Verify vote options. Different vote types have different
	// requirements.
	if len(vote.Options) == 0 {
		return backend.PluginUserError{
			PluginID:     ticketvote.ID,
			ErrorCode:    int(ticketvote.ErrorStatusVoteParamsInvalid),
			ErrorContext: []string{"no vote options found"},
		}
	}
	switch vote.Type {
	case ticketvote.VoteTypeStandard, ticketvote.VoteTypeRunoff:
		// These vote types only allow for approve/reject votes. Ensure
		// that the only options present are approve/reject and that they
		// use the vote option IDs specified by the ticketvote API.
		if len(vote.Options) != 2 {
			e := fmt.Sprintf("vote options count got %v, want 2",
				len(vote.Options))
			return backend.PluginUserError{
				PluginID:     ticketvote.ID,
				ErrorCode:    int(ticketvote.ErrorStatusVoteParamsInvalid),
				ErrorContext: []string{e},
			}
		}
		// map[optionID]found
		options := map[string]bool{
			ticketvote.VoteOptionIDApprove: false,
			ticketvote.VoteOptionIDReject:  false,
		}
		for _, v := range vote.Options {
			switch v.ID {
			case ticketvote.VoteOptionIDApprove:
				options[v.ID] = true
			case ticketvote.VoteOptionIDReject:
				options[v.ID] = true
			}
		}
		missing := make([]string, 0, 2)
		for k, v := range options {
			if !v {
				// Option ID was not found
				missing = append(missing, k)
			}
		}
		if len(missing) > 0 {
			e := fmt.Sprintf("vote option IDs not found: %v",
				strings.Join(missing, ","))
			return backend.PluginUserError{
				PluginID:     ticketvote.ID,
				ErrorCode:    int(ticketvote.ErrorStatusVoteParamsInvalid),
				ErrorContext: []string{e},
			}
		}
	}

	// Verify vote bits are somewhat sane
	for _, v := range vote.Options {
		err := voteBitVerify(vote.Options, vote.Mask, v.Bit)
		if err != nil {
			return backend.PluginUserError{
				PluginID:     ticketvote.ID,
				ErrorCode:    int(ticketvote.ErrorStatusVoteParamsInvalid),
				ErrorContext: []string{err.Error()},
			}
		}
	}

	// Verify parent token
	switch {
	case vote.Type == ticketvote.VoteTypeStandard && vote.Parent != "":
		e := "parent token should not be provided for a standard vote"
		return backend.PluginUserError{
			PluginID:     ticketvote.ID,
			ErrorCode:    int(ticketvote.ErrorStatusVoteParamsInvalid),
			ErrorContext: []string{e},
		}
	case vote.Type == ticketvote.VoteTypeRunoff:
		_, err := tokenDecode(vote.Parent)
		if err != nil {
			e := fmt.Sprintf("invalid parent %v", vote.Parent)
			return backend.PluginUserError{
				PluginID:     ticketvote.ID,
				ErrorCode:    int(ticketvote.ErrorStatusVoteParamsInvalid),
				ErrorContext: []string{e},
			}
		}
	}

	return nil
}

// startStandard starts a standard vote.
func (p *ticketVotePlugin) startStandard(s ticketvote.Start) (*ticketvote.StartReply, error) {
	// Verify there is only one start details
	if len(s.Starts) != 1 {
		return nil, backend.PluginUserError{
			PluginID:     ticketvote.ID,
			ErrorCode:    int(ticketvote.ErrorStatusStartDetailsInvalid),
			ErrorContext: []string{"more than one start details found"},
		}
	}
	sd := s.Starts[0]

	// Verify token
	token, err := tokenDecode(sd.Params.Token)
	if err != nil {
		return nil, backend.PluginUserError{
			PluginID:  ticketvote.ID,
			ErrorCode: int(ticketvote.ErrorStatusTokenInvalid),
		}
	}

	// Verify signature
	vb, err := json.Marshal(sd.Params)
	if err != nil {
		return nil, err
	}
	msg := hex.EncodeToString(util.Digest(vb))
	err = util.VerifySignature(sd.Signature, sd.PublicKey, msg)
	if err != nil {
		return nil, convertTicketVoteErrFromSignatureErr(err)
	}

	// Verify vote options and params
	err = voteParamsVerify(sd.Params, p.voteDurationMin, p.voteDurationMax)
	if err != nil {
		return nil, err
	}

	// Get vote blockchain data
	sr, err := p.startReply(sd.Params.Duration)
	if err != nil {
		return nil, err
	}

	// Validate existing record state. The lock for this record must be
	// held for the remainder of this function.
	m := p.mutex(sd.Params.Token)
	m.Lock()
	defer m.Unlock()

	// Verify record version
	r, err := p.backend.GetVetted(token, "")
	if err != nil {
		if errors.Is(err, backend.ErrRecordNotFound) {
			return nil, backend.PluginUserError{
				PluginID:  ticketvote.ID,
				ErrorCode: int(ticketvote.ErrorStatusRecordNotFound),
			}
		}
		return nil, fmt.Errorf("GetVetted: %v", err)
	}
	version := strconv.FormatUint(uint64(sd.Params.Version), 10)
	if r.Version != version {
		e := fmt.Sprintf("version is not latest: got %v, want %v",
			sd.Params.Version, r.Version)
		return nil, backend.PluginUserError{
			PluginID:     ticketvote.ID,
			ErrorCode:    int(ticketvote.ErrorStatusRecordVersionInvalid),
			ErrorContext: []string{e},
		}
	}

	// Verify vote authorization
	auths, err := p.authorizes(token)
	if err != nil {
		return nil, err
	}
	if len(auths) == 0 {
		return nil, backend.PluginUserError{
			PluginID:     ticketvote.ID,
			ErrorCode:    int(ticketvote.ErrorStatusAuthorizationInvalid),
			ErrorContext: []string{"authorization not found"},
		}
	}
	action := ticketvote.AuthActionT(auths[len(auths)-1].Action)
	if action != ticketvote.AuthActionAuthorize {
		return nil, backend.PluginUserError{
			PluginID:     ticketvote.ID,
			ErrorCode:    int(ticketvote.ErrorStatusAuthorizationInvalid),
			ErrorContext: []string{"not authorized"},
		}
	}

	// Verify vote has not already been started
	svp, err := p.voteDetails(token)
	if err != nil {
		return nil, err
	}
	if svp != nil {
		// Vote has already been started
		return nil, backend.PluginUserError{
			PluginID:     ticketvote.ID,
			ErrorCode:    int(ticketvote.ErrorStatusVoteStatusInvalid),
			ErrorContext: []string{"vote already started"},
		}
	}

	// Prepare vote details
	vd := ticketvote.VoteDetails{
		Params:           sd.Params,
		PublicKey:        sd.PublicKey,
		Signature:        sd.Signature,
		StartBlockHeight: sr.StartBlockHeight,
		StartBlockHash:   sr.StartBlockHash,
		EndBlockHeight:   sr.EndBlockHeight,
		EligibleTickets:  sr.EligibleTickets,
	}

	// Save vote details
	err = p.voteDetailsSave(vd)
	if err != nil {
		return nil, fmt.Errorf("voteDetailsSave: %v", err)
	}

	// Update inventory
	p.inventorySetToStarted(vd.Params.Token, ticketvote.VoteTypeStandard,
		vd.EndBlockHeight)

	return &ticketvote.StartReply{
		StartBlockHeight: sr.StartBlockHeight,
		StartBlockHash:   sr.StartBlockHash,
		EndBlockHeight:   sr.EndBlockHeight,
		EligibleTickets:  sr.EligibleTickets,
	}, nil
}

// startRunoff starts a runoff vote.
func (p *ticketVotePlugin) startRunoff(s ticketvote.Start) (*ticketvote.StartReply, error) {
	// Sanity check
	if len(s.Starts) == 0 {
		return nil, fmt.Errorf("no start details found")
	}

	// Perform validation that can be done without fetching any records
	// from the backend.
	var (
		mask     = s.Starts[0].Params.Mask
		duration = s.Starts[0].Params.Duration
		quorum   = s.Starts[0].Params.QuorumPercentage
		pass     = s.Starts[0].Params.PassPercentage
		parent   = s.Starts[0].Params.Parent
	)
	for _, v := range s.Starts {
		// Verify vote params are the same for all submissions
		switch {
		case v.Params.Type != ticketvote.VoteTypeRunoff:
			e := fmt.Sprintf("%v vote type invalid: got %v, want %v",
				v.Params.Token, v.Params.Type, ticketvote.VoteTypeRunoff)
			return nil, backend.PluginUserError{
				PluginID:     ticketvote.ID,
				ErrorCode:    int(ticketvote.ErrorStatusVoteParamsInvalid),
				ErrorContext: []string{e},
			}
		case v.Params.Mask != mask:
			e := fmt.Sprintf("%v mask invalid: all must be the same",
				v.Params.Token)
			return nil, backend.PluginUserError{
				PluginID:     ticketvote.ID,
				ErrorCode:    int(ticketvote.ErrorStatusVoteParamsInvalid),
				ErrorContext: []string{e},
			}
		case v.Params.Duration != duration:
			e := fmt.Sprintf("%v duration invalid: all must be the same",
				v.Params.Token)
			return nil, backend.PluginUserError{
				PluginID:     ticketvote.ID,
				ErrorCode:    int(ticketvote.ErrorStatusVoteParamsInvalid),
				ErrorContext: []string{e},
			}
		case v.Params.QuorumPercentage != quorum:
			e := fmt.Sprintf("%v quorum invalid: must be the same",
				v.Params.Token)
			return nil, backend.PluginUserError{
				PluginID:     ticketvote.ID,
				ErrorCode:    int(ticketvote.ErrorStatusVoteParamsInvalid),
				ErrorContext: []string{e},
			}
		case v.Params.PassPercentage != pass:
			e := fmt.Sprintf("%v pass rate invalid: all must be the same",
				v.Params.Token)
			return nil, backend.PluginUserError{
				PluginID:     ticketvote.ID,
				ErrorCode:    int(ticketvote.ErrorStatusVoteParamsInvalid),
				ErrorContext: []string{e},
			}
		case v.Params.Parent != parent:
			e := fmt.Sprintf("%v parent invalid: all must be the same",
				v.Params.Token)
			return nil, backend.PluginUserError{
				PluginID:     ticketvote.ID,
				ErrorCode:    int(ticketvote.ErrorStatusVoteParamsInvalid),
				ErrorContext: []string{e},
			}
		}

		// Verify token
		_, err := tokenDecode(v.Params.Token)
		if err != nil {
			return nil, backend.PluginUserError{
				PluginID:     ticketvote.ID,
				ErrorCode:    int(ticketvote.ErrorStatusTokenInvalid),
				ErrorContext: []string{v.Params.Token},
			}
		}

		// Verify signature
		vb, err := json.Marshal(v.Params)
		if err != nil {
			return nil, err
		}
		msg := hex.EncodeToString(util.Digest(vb))
		err = util.VerifySignature(v.Signature, v.PublicKey, msg)
		if err != nil {
			return nil, convertTicketVoteErrFromSignatureErr(err)
		}

		// Verify vote options and params. Vote optoins are required to
		// be approve and reject.
		err = voteParamsVerify(v.Params, p.voteDurationMin, p.voteDurationMax)
		if err != nil {
			return nil, err
		}
	}

	// Get vote blockchain data
	sr, err := p.startReply(duration)
	if err != nil {
		return nil, err
	}

	// Verify parent exists
	parentb, err := tokenDecode(parent)
	if err != nil {
		return nil, err
	}
	if !p.backend.VettedExists(parentb) {
		e := fmt.Sprintf("parent record not found %v", parent)
		return nil, backend.PluginUserError{
			PluginID:     ticketvote.ID,
			ErrorCode:    int(ticketvote.ErrorStatusVoteParamsInvalid),
			ErrorContext: []string{e},
		}
	}

	// TODO handle the case where part of the votes are started but
	// not all.

	// Validate existing record state. The lock for each record must
	// be held for the remainder of this function.
	for _, v := range s.Starts {
		m := p.mutex(v.Params.Token)
		m.Lock()
		defer m.Unlock()

		token, err := tokenDecode(v.Params.Token)
		if err != nil {
			return nil, err
		}

		// Verify record version
		r, err := p.backend.GetVetted(token, "")
		if err != nil {
			if errors.Is(err, backend.ErrRecordNotFound) {
				return nil, backend.PluginUserError{
					PluginID:     ticketvote.ID,
					ErrorCode:    int(ticketvote.ErrorStatusRecordNotFound),
					ErrorContext: []string{v.Params.Token},
				}
			}
			return nil, fmt.Errorf("GetVetted: %v", err)
		}
		version := strconv.FormatUint(uint64(v.Params.Version), 10)
		if r.Version != version {
			e := fmt.Sprintf("version is not latest %v: got %v, want %v",
				v.Params.Token, v.Params.Version, r.Version)
			return nil, backend.PluginUserError{
				PluginID:     ticketvote.ID,
				ErrorCode:    int(ticketvote.ErrorStatusRecordVersionInvalid),
				ErrorContext: []string{e},
			}
		}

		// Verify vote has not already been started
		svp, err := p.voteDetails(token)
		if err != nil {
			return nil, err
		}
		if svp != nil {
			// Vote has already been started
			return nil, backend.PluginUserError{
				PluginID:     ticketvote.ID,
				ErrorCode:    int(ticketvote.ErrorStatusVoteStatusInvalid),
				ErrorContext: []string{"vote already started"},
			}
		}
	}

	for _, v := range s.Starts {
		// Prepare vote details
		vd := ticketvote.VoteDetails{
			Params:           v.Params,
			PublicKey:        v.PublicKey,
			Signature:        v.Signature,
			StartBlockHeight: sr.StartBlockHeight,
			StartBlockHash:   sr.StartBlockHash,
			EndBlockHeight:   sr.EndBlockHeight,
			EligibleTickets:  sr.EligibleTickets,
		}

		// Save vote details
		err = p.voteDetailsSave(vd)
		if err != nil {
			return nil, fmt.Errorf("voteDetailsSave: %v", err)
		}

		// Update inventory
		p.inventorySetToStarted(vd.Params.Token, ticketvote.VoteTypeRunoff,
			vd.EndBlockHeight)
	}

	return &ticketvote.StartReply{
		StartBlockHeight: sr.StartBlockHeight,
		StartBlockHash:   sr.StartBlockHash,
		EndBlockHeight:   sr.EndBlockHeight,
		EligibleTickets:  sr.EligibleTickets,
	}, nil
}

func (p *ticketVotePlugin) cmdStart(payload string) (string, error) {
	log.Tracef("ticketvote cmdStart: %v", payload)

	// Decode payload
	s, err := ticketvote.DecodeStart([]byte(payload))
	if err != nil {
		return "", err
	}

	// Parse vote type
	if len(s.Starts) == 0 {
		return "", backend.PluginUserError{
			PluginID:     ticketvote.ID,
			ErrorCode:    int(ticketvote.ErrorStatusStartDetailsInvalid),
			ErrorContext: []string{"no start details found"},
		}
	}
	vtype := s.Starts[0].Params.Type

	// Start vote
	// TODO these vote user errors need to become more granular. Update
	// this when writing tests.
	var sr *ticketvote.StartReply
	switch vtype {
	case ticketvote.VoteTypeStandard:
		sr, err = p.startStandard(*s)
		if err != nil {
			return "", err
		}
	case ticketvote.VoteTypeRunoff:
		sr, err = p.startRunoff(*s)
		if err != nil {
			return "", err
		}
	default:
		e := fmt.Sprintf("invalid vote type %v", vtype)
		return "", backend.PluginUserError{
			PluginID:     ticketvote.ID,
			ErrorCode:    int(ticketvote.ErrorStatusVoteParamsInvalid),
			ErrorContext: []string{e},
		}
	}

	// Prepare reply
	reply, err := ticketvote.EncodeStartReply(*sr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// ballot casts the provided votes concurrently. The vote results are passed
// back through the results channel to the calling function. This function
// waits until all provided votes have been cast before returning.
//
// This function must be called WITH the record lock held.
func (p *ticketVotePlugin) ballot(votes []ticketvote.CastVote, results chan ticketvote.CastVoteReply) {
	// Cast the votes concurrently
	var wg sync.WaitGroup
	for _, v := range votes {
		// Increment the wait group counter
		wg.Add(1)

		go func(v ticketvote.CastVote) {
			// Decrement wait group counter once vote is cast
			defer wg.Done()

			// Setup cast vote details
			receipt := p.identity.SignMessage([]byte(v.Signature))
			cv := ticketvote.CastVoteDetails{
				Token:     v.Token,
				Ticket:    v.Ticket,
				VoteBit:   v.VoteBit,
				Signature: v.Signature,
				Receipt:   hex.EncodeToString(receipt[:]),
			}

			// Save cast vote
			var cvr ticketvote.CastVoteReply
			err := p.castVoteSave(cv)
			if err != nil {
				t := time.Now().Unix()
				log.Errorf("cmdCastBallot: castVoteSave %v: %v", t, err)
				e := ticketvote.VoteErrorInternalError
				cvr.Ticket = v.Ticket
				cvr.ErrorCode = e
				cvr.ErrorContext = fmt.Sprintf("%v: %v",
					ticketvote.VoteError[e], t)
				goto sendResult
			}

			// Update receipt
			cvr.Ticket = v.Ticket
			cvr.Receipt = cv.Receipt

			// Update cast votes cache
			p.cachedVotesSet(v.Token, v.Ticket, v.VoteBit)

		sendResult:
			// Send result back to calling function
			results <- cvr
		}(v)
	}

	// Wait for the full ballot to be cast before returning.
	wg.Wait()
}

// cmdCastBallot casts a ballot of votes. This function will not return a user
// error if one occurs. It will instead return the ballot reply with the error
// included in the invidiual cast vote reply that it applies to.
func (p *ticketVotePlugin) cmdCastBallot(payload string) (string, error) {
	log.Tracef("ticketvote cmdCastBallot: %v", payload)

	// Decode payload
	cb, err := ticketvote.DecodeCastBallot([]byte(payload))
	if err != nil {
		return "", err
	}
	votes := cb.Ballot

	// Verify there is work to do
	if len(votes) == 0 {
		// Nothing to do
		cbr := ticketvote.CastBallotReply{
			Receipts: []ticketvote.CastVoteReply{},
		}
		reply, err := ticketvote.EncodeCastBallotReply(cbr)
		if err != nil {
			return "", err
		}
		return string(reply), nil
	}

	// Verify that all tokens in the ballot are valid, full length
	// tokens and that they are all voting for the same record.
	var (
		token    []byte
		receipts = make([]ticketvote.CastVoteReply, len(votes))
	)
	for k, v := range votes {
		// Verify token
		t, err := tokenDecode(v.Token)
		if err != nil {
			e := ticketvote.VoteErrorTokenInvalid
			receipts[k].Ticket = v.Ticket
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = fmt.Sprintf("%v: not hex",
				ticketvote.VoteError[e])
			continue
		}
		if token == nil {
			// Set token to the first valid one we come across. All votes
			// in the ballot with a valid token are required to be the same
			// as this token.
			token = t
		}

		// Verify token is the same
		if !bytes.Equal(t, token) {
			e := ticketvote.VoteErrorMultipleRecordVotes
			receipts[k].Ticket = v.Ticket
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = ticketvote.VoteError[e]
			continue
		}
	}

	// From this point forward, it can be assumed that all votes that
	// have not had their error set are voting for the same record. Get
	// the record and vote data that we need to perform the remaining
	// inexpensive validation before we have to hold the lock.
	voteDetails, err := p.voteDetails(token)
	if err != nil {
		return "", err
	}
	bestBlock, err := p.bestBlock()
	if err != nil {
		return "", err
	}

	// eligible contains the ticket hashes of all eligble tickets. They
	// are put into a map for O(n) lookups.
	eligible := make(map[string]struct{}, len(voteDetails.EligibleTickets))
	for _, v := range voteDetails.EligibleTickets {
		eligible[v] = struct{}{}
	}

	// addrs contains the largest commitment addresses for each ticket.
	// The vote must be signed using the largest commitment address.
	tickets := make([]string, 0, len(cb.Ballot))
	for _, v := range cb.Ballot {
		tickets = append(tickets, v.Ticket)
	}
	addrs, err := p.largestCommitmentAddrs(tickets)
	if err != nil {
		return "", fmt.Errorf("largestCommitmentAddrs: %v", err)
	}

	// Perform validation that doesn't require holding the record lock.
	for k, v := range votes {
		if receipts[k].ErrorCode != ticketvote.VoteErrorInvalid {
			// Vote has an error. Skip it.
			continue
		}

		// Verify record vote status
		if voteDetails == nil {
			// Vote has not been started yet
			e := ticketvote.VoteErrorVoteStatusInvalid
			receipts[k].Ticket = v.Ticket
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = fmt.Sprintf("%v: vote not started",
				ticketvote.VoteError[e])
			continue
		}
		if bestBlock >= voteDetails.EndBlockHeight {
			// Vote has ended
			e := ticketvote.VoteErrorVoteStatusInvalid
			receipts[k].Ticket = v.Ticket
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = fmt.Sprintf("%v: vote has ended",
				ticketvote.VoteError[e])
			continue
		}

		// Verify vote bit
		bit, err := strconv.ParseUint(v.VoteBit, 16, 64)
		if err != nil {
			e := ticketvote.VoteErrorVoteBitInvalid
			receipts[k].Ticket = v.Ticket
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = ticketvote.VoteError[e]
			continue
		}
		err = voteBitVerify(voteDetails.Params.Options,
			voteDetails.Params.Mask, bit)
		if err != nil {
			e := ticketvote.VoteErrorVoteBitInvalid
			receipts[k].Ticket = v.Ticket
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = fmt.Sprintf("%v: %v",
				ticketvote.VoteError[e], err)
			continue
		}

		// Verify vote signature
		commitmentAddr := addrs[k]
		if commitmentAddr.ticket != v.Ticket {
			t := time.Now().Unix()
			log.Errorf("cmdCastBallot: commitment addr mismatch %v: %v %v",
				t, commitmentAddr.ticket, v.Ticket)
			e := ticketvote.VoteErrorInternalError
			receipts[k].Ticket = v.Ticket
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = fmt.Sprintf("%v: %v",
				ticketvote.VoteError[e], t)
			continue
		}
		if commitmentAddr.err != nil {
			t := time.Now().Unix()
			log.Errorf("cmdCastBallot: commitment addr error %v: %v %v",
				t, commitmentAddr.ticket, commitmentAddr.err)
			e := ticketvote.VoteErrorInternalError
			receipts[k].Ticket = v.Ticket
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = fmt.Sprintf("%v: %v",
				ticketvote.VoteError[e], t)
			continue
		}
		err = p.castVoteSignatureVerify(v, commitmentAddr.addr)
		if err != nil {
			e := ticketvote.VoteErrorSignatureInvalid
			receipts[k].Ticket = v.Ticket
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = fmt.Sprintf("%v: %v",
				ticketvote.VoteError[e], err)
			continue
		}

		// Verify ticket is eligible to vote
		_, ok := eligible[v.Ticket]
		if !ok {
			e := ticketvote.VoteErrorTicketNotEligible
			receipts[k].Ticket = v.Ticket
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = ticketvote.VoteError[e]
			continue
		}
	}

	// The record lock must be held for the remainder of the function to
	// ensure duplicate votes cannot be cast.
	m := p.mutex(hex.EncodeToString(token))
	m.Lock()
	defer m.Unlock()

	// cachedVotes contains the tickets that have alread voted
	cachedVotes := p.cachedVotes(token)
	for k, v := range votes {
		if receipts[k].ErrorCode != ticketvote.VoteErrorInvalid {
			// Vote has an error. Skip it.
			continue
		}

		// Verify ticket has not already vote
		_, ok := cachedVotes[v.Ticket]
		if ok {
			e := ticketvote.VoteErrorTicketAlreadyVoted
			receipts[k].Ticket = v.Ticket
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = ticketvote.VoteError[e]
			continue
		}
	}

	// The votes that have passed validation will be cast in batches of
	// size batchSize. Each batch of votes is cast concurrently in order
	// to accommodate the trillian log signer bottleneck. The log signer
	// picks up queued leaves and appends them onto the trillian tree
	// every xxx ms, where xxx is a configurable value on the log signer,
	// but is typically a few hundred milliseconds. Lets use 200ms as an
	// example. If we don't cast the votes in batches then every vote in
	// the ballot will take 200 milliseconds since we wait for the leaf
	// to be fully appended before considering the trillian call
	// successful. A person casting hundreds of votes in a single ballot
	// would cause UX issues for the all voting clients since the lock is
	// held during these calls.
	//
	// The second variable that we must watch out for is the max trillian
	// queued leaf batch size. This is also a configurable trillian value
	// that represents the maximum number of leaves that can be waiting
	// in the queue for all trees in the trillian instance. This value is
	// typically around the order of magnitude of 1000 queued leaves.
	//
	// This is why a vote batch size of 5 was chosen. It is large enough
	// to alleviate performance bottlenecks from the log signer interval,
	// but small enough to still allow multiple records votes be held
	// concurrently without running into the queued leaf batch size limit.

	// Prepare work
	var (
		batchSize = 5
		batch     = make([]ticketvote.CastVote, 0, batchSize)
		queue     = make([][]ticketvote.CastVote, 0, len(votes)/batchSize)

		// ballotCount is the number of votes that have passed validation
		// and are being cast in this ballot.
		ballotCount int
	)
	for k, v := range votes {
		if receipts[k].ErrorCode != ticketvote.VoteErrorInvalid {
			// Vote has an error. Skip it.
			continue
		}

		// Add vote to the current batch
		batch = append(batch, v)
		ballotCount++

		if len(batch) == batchSize {
			// This batch is full. Add the batch to the queue and start
			// a new batch.
			queue = append(queue, batch)
			batch = make([]ticketvote.CastVote, 0, batchSize)
		}
	}
	if len(batch) != 0 {
		// Add leftover batch to the queue
		queue = append(queue, batch)
	}

	log.Debugf("Casting %v votes in %v batches of size %v",
		ballotCount, len(queue), batchSize)

	// Cast ballot in batches
	results := make(chan ticketvote.CastVoteReply, ballotCount)
	for i, batch := range queue {
		log.Debugf("Casting %v votes in batch %v/%v", len(batch), i+1, len(queue))

		p.ballot(batch, results)
	}

	// Empty out the results channel
	r := make(map[string]ticketvote.CastVoteReply, ballotCount)
	close(results)
	for v := range results {
		r[v.Ticket] = v
	}

	if len(r) != ballotCount {
		log.Errorf("Missing results: got %v, want %v", len(r), ballotCount)
	}

	// Fill in the receipts
	for k, v := range votes {
		if receipts[k].ErrorCode != ticketvote.VoteErrorInvalid {
			// Vote has an error. Skip it.
			continue
		}
		cvr, ok := r[v.Ticket]
		if !ok {
			t := time.Now().Unix()
			log.Errorf("cmdCastBallot: vote result not found %v: %v", t, v.Ticket)
			e := ticketvote.VoteErrorInternalError
			receipts[k].Ticket = v.Ticket
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = fmt.Sprintf("%v: %v",
				ticketvote.VoteError[e], t)
			continue
		}

		// Fill in receipt
		receipts[k] = cvr
	}

	// Prepare reply
	cbr := ticketvote.CastBallotReply{
		Receipts: receipts,
	}
	reply, err := ticketvote.EncodeCastBallotReply(cbr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

func (p *ticketVotePlugin) cmdDetails(payload string) (string, error) {
	log.Tracef("ticketvote cmdDetails: %v", payload)

	d, err := ticketvote.DecodeDetails([]byte(payload))
	if err != nil {
		return "", err
	}

	votes := make(map[string]ticketvote.RecordVote, len(d.Tokens))
	for _, v := range d.Tokens {
		// Verify token
		token, err := tokenDecodeAnyLength(v)
		if err != nil {
			continue
		}

		// Get authorize votes
		auths, err := p.authorizes(token)
		if err != nil {
			if errors.Is(err, errRecordNotFound) {
				return "", backend.PluginUserError{
					PluginID:  ticketvote.ID,
					ErrorCode: int(ticketvote.ErrorStatusRecordNotFound),
				}
			}
			return "", fmt.Errorf("authorizes: %v", err)
		}

		// Get vote details
		vd, err := p.voteDetails(token)
		if err != nil {
			return "", fmt.Errorf("startDetails: %v", err)
		}

		// Add record vote
		votes[v] = ticketvote.RecordVote{
			Auths: auths,
			Vote:  vd,
		}
	}

	// Prepare rely
	dr := ticketvote.DetailsReply{
		Votes: votes,
	}
	reply, err := ticketvote.EncodeDetailsReply(dr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

func (p *ticketVotePlugin) cmdResults(payload string) (string, error) {
	log.Tracef("ticketvote cmdResults: %v", payload)

	// Decode payload
	r, err := ticketvote.DecodeResults([]byte(payload))
	if err != nil {
		return "", err
	}

	// Verify token
	token, err := tokenDecodeAnyLength(r.Token)
	if err != nil {
		return "", backend.PluginUserError{
			PluginID:  ticketvote.ID,
			ErrorCode: int(ticketvote.ErrorStatusTokenInvalid),
		}
	}

	// Get cast votes
	votes, err := p.castVotes(token)
	if err != nil {
		if errors.Is(err, errRecordNotFound) {
			return "", backend.PluginUserError{
				PluginID:  ticketvote.ID,
				ErrorCode: int(ticketvote.ErrorStatusRecordNotFound),
			}
		}
		return "", err
	}

	// Prepare reply
	rr := ticketvote.ResultsReply{
		Votes: votes,
	}
	reply, err := ticketvote.EncodeResultsReply(rr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// voteIsApproved returns whether the provided vote option results met the
// provided quorum and pass percentage requirements. This function can only be
// called on votes that use VoteOptionIDApprove and VoteOptionIDReject. Any
// other vote option IDs will cause this function to panic.
func voteIsApproved(vd ticketvote.VoteDetails, results []ticketvote.VoteOptionResult) bool {
	// Tally the total votes
	var total uint64
	for _, v := range results {
		total += v.Votes
	}

	// Calculate required thresholds
	var (
		eligible   = float64(len(vd.EligibleTickets))
		quorumPerc = float64(vd.Params.QuorumPercentage)
		passPerc   = float64(vd.Params.PassPercentage)
		quorum     = uint64(quorumPerc / 100 * eligible)
		pass       = uint64(passPerc / 100 * float64(total))

		approvedVotes uint64
	)

	// Tally approve votes
	for _, v := range results {
		switch v.ID {
		case ticketvote.VoteOptionIDApprove:
			// Valid vote option
			approvedVotes++
		case ticketvote.VoteOptionIDReject:
			// Valid vote option
		default:
			// Invalid vote option
			e := fmt.Sprintf("invalid vote option id found: %v", v.ID)
			panic(e)
		}
	}

	// Check tally against thresholds
	var approved bool
	switch {
	case total < quorum:
		// Quorum not met
		approved = false
	case approvedVotes < pass:
		// Pass percentage not met
		approved = false
	default:
		// Vote was approved
		approved = true
	}

	return approved
}

func (p *ticketVotePlugin) summary(token []byte, bestBlock uint32) (*ticketvote.Summary, error) {
	// Check if the summary has been cached
	s, err := p.cachedSummary(hex.EncodeToString(token))
	switch {
	case errors.Is(err, errRecordNotFound):
		// Cached summary not found. Continue.
	case err != nil:
		// Some other error
		return nil, fmt.Errorf("cachedSummary: %v", err)
	default:
		// Caches summary was found. Return it.
		return s, nil
	}

	// Summary has not been cached. Get it manually.

	// Assume vote is unauthorized. Only update the status when the
	// appropriate record has been found that proves otherwise.
	status := ticketvote.VoteStatusUnauthorized

	// Check if the vote has been authorized
	auths, err := p.authorizes(token)
	if err != nil {
		if errors.Is(err, errRecordNotFound) {
			return nil, err
		}
		return nil, fmt.Errorf("authorizes: %v", err)
	}
	if len(auths) > 0 {
		lastAuth := auths[len(auths)-1]
		switch ticketvote.AuthActionT(lastAuth.Action) {
		case ticketvote.AuthActionAuthorize:
			// Vote has been authorized; continue
			status = ticketvote.VoteStatusAuthorized
		case ticketvote.AuthActionRevoke:
			// Vote authorization has been revoked. Its not possible for
			// the vote to have been started. We can stop looking.
			return &ticketvote.Summary{
				Status:  status,
				Results: []ticketvote.VoteOptionResult{},
			}, nil
		}
	}

	// Check if the vote has been started
	vd, err := p.voteDetails(token)
	if err != nil {
		return nil, fmt.Errorf("startDetails: %v", err)
	}
	if vd == nil {
		// Vote has not been started yet
		return &ticketvote.Summary{
			Status:  status,
			Results: []ticketvote.VoteOptionResult{},
		}, nil
	}

	// Vote has been started. Check if it is still in progress or has
	// already ended.
	if bestBlock < vd.EndBlockHeight {
		status = ticketvote.VoteStatusStarted
	} else {
		status = ticketvote.VoteStatusFinished
	}

	// Pull the cast votes from the cache and tally the results
	votes := p.cachedVotes(token)
	tally := make(map[string]int, len(vd.Params.Options))
	for _, voteBit := range votes {
		tally[voteBit]++
	}
	results := make([]ticketvote.VoteOptionResult, 0, len(vd.Params.Options))
	for _, v := range vd.Params.Options {
		bit := strconv.FormatUint(v.Bit, 16)
		results = append(results, ticketvote.VoteOptionResult{
			ID:          v.ID,
			Description: v.Description,
			VoteBit:     v.Bit,
			Votes:       uint64(tally[bit]),
		})
	}

	// Prepare summary
	summary := ticketvote.Summary{
		Type:             vd.Params.Type,
		Status:           status,
		Duration:         vd.Params.Duration,
		StartBlockHeight: vd.StartBlockHeight,
		StartBlockHash:   vd.StartBlockHash,
		EndBlockHeight:   vd.EndBlockHeight,
		EligibleTickets:  uint32(len(vd.EligibleTickets)),
		QuorumPercentage: vd.Params.QuorumPercentage,
		PassPercentage:   vd.Params.PassPercentage,
		Results:          results,
	}

	// If the vote has not finished yet then we are done for now.
	if status == ticketvote.VoteStatusStarted {
		return &summary, nil
	}

	// The vote has finished. We can calculate if the vote was approved
	// for certain vote types and cache the results.
	switch vd.Params.Type {
	case ticketvote.VoteTypeStandard, ticketvote.VoteTypeRunoff:
		// These vote types are strictly approve/reject votes so we can
		// calculate the vote approval. Continue.
	default:
		// Nothing else to do for all other vote types
		return &summary, nil
	}

	// Calculate vote approval
	approved := voteIsApproved(*vd, results)

	// If this is a standard vote then we can take the results as is. A
	// runoff vote requires that we pull all other runoff vote
	// submissions to determine if the vote actually passed.
	// TODO
	summary.Approved = approved

	// Cache the summary
	err = p.cachedSummarySave(vd.Params.Token, summary)
	if err != nil {
		return nil, fmt.Errorf("cachedSummarySave %v: %v %v",
			vd.Params.Token, err, summary)
	}

	// Remove record from the votes cache now that a summary has been
	// saved for it.
	p.cachedVotesDel(vd.Params.Token)

	return &summary, nil
}

func (p *ticketVotePlugin) cmdSummaries(payload string) (string, error) {
	log.Tracef("ticketvote cmdSummaries: %v", payload)

	// Decode payload
	s, err := ticketvote.DecodeSummaries([]byte(payload))
	if err != nil {
		return "", err
	}

	// Get best block. This cmd does not write any data so we do not
	// have to use the safe best block.
	bb, err := p.bestBlockUnsafe()
	if err != nil {
		return "", fmt.Errorf("bestBlockUnsafe: %v", err)
	}

	// Get summaries
	summaries := make(map[string]ticketvote.Summary, len(s.Tokens))
	for _, v := range s.Tokens {
		token, err := tokenDecodeAnyLength(v)
		if err != nil {
			return "", err
		}
		s, err := p.summary(token, bb)
		if err != nil {
			if errors.Is(err, errRecordNotFound) {
				// Record does not exist for token. Do not include this token
				// in the reply.
				continue
			}
			return "", fmt.Errorf("summary %v: %v", v, err)
		}
		summaries[v] = *s
	}

	// Prepare reply
	sr := ticketvote.SummariesReply{
		Summaries: summaries,
		BestBlock: bb,
	}
	reply, err := ticketvote.EncodeSummariesReply(sr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

func convertInventoryReply(v voteInventory) ticketvote.InventoryReply {
	// Started needs to be converted from a map to a slice where the
	// slice is sorted by end block height from smallest to largest.
	tokensByHeight := make(map[uint32][]string, len(v.started))
	for token, height := range v.started {
		tokens, ok := tokensByHeight[height]
		if !ok {
			tokens = make([]string, 0, len(v.started))
		}
		tokens = append(tokens, token)
		tokensByHeight[height] = tokens
	}
	sortedHeights := make([]uint32, 0, len(tokensByHeight))
	for k := range tokensByHeight {
		sortedHeights = append(sortedHeights, k)
	}
	// Sort smallest to largest block height
	sort.SliceStable(sortedHeights, func(i, j int) bool {
		return sortedHeights[i] < sortedHeights[j]
	})
	started := make([]string, 0, len(v.started))
	for _, height := range sortedHeights {
		tokens := tokensByHeight[height]
		started = append(started, tokens...)
	}
	return ticketvote.InventoryReply{
		Unauthorized: v.unauthorized,
		Authorized:   v.authorized,
		Started:      started,
		Finished:     v.finished,
		BestBlock:    v.bestBlock,
	}
}

func (p *ticketVotePlugin) cmdInventory(payload string) (string, error) {
	log.Tracef("ticketvote cmdInventory: %v", payload)

	// Payload is empty. Nothing to decode.

	// Get best block. This command does not write any data so we can
	// use the unsafe best block.
	bb, err := p.bestBlockUnsafe()
	if err != nil {
		return "", fmt.Errorf("bestBlockUnsafe: %v", err)
	}

	// Get the inventory
	inv, err := p.inventory(bb)
	if err != nil {
		return "", fmt.Errorf("inventory: %v", err)
	}
	ir := convertInventoryReply(*inv)

	// Prepare reply
	reply, err := ticketvote.EncodeInventoryReply(ir)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// setup performs any plugin setup work that needs to be done.
//
// This function satisfies the pluginClient interface.
func (p *ticketVotePlugin) setup() error {
	log.Tracef("ticketvote setup")

	// Verify plugin dependencies
	plugins, err := p.backend.GetPlugins()
	if err != nil {
		return fmt.Errorf("Plugins: %v", err)
	}
	var dcrdataFound bool
	for _, v := range plugins {
		if v.ID == dcrdata.ID {
			dcrdataFound = true
		}
	}
	if !dcrdataFound {
		return fmt.Errorf("plugin dependency not registered: %v", dcrdata.ID)
	}

	// Build inventory cache
	log.Infof("ticketvote: building inventory cache")

	ibs, err := p.backend.InventoryByStatus()
	if err != nil {
		return fmt.Errorf("InventoryByStatus: %v", err)
	}

	bestBlock, err := p.bestBlock()
	if err != nil {
		return fmt.Errorf("bestBlock: %v", err)
	}

	var (
		unauthorized = make([]string, 0, 256)
		authorized   = make([]string, 0, 256)
		started      = make(map[string]uint32, 256) // [token]endHeight
		finished     = make([]string, 0, 256)
	)
	for _, tokens := range ibs.Vetted {
		for _, v := range tokens {
			token, err := tokenDecode(v)
			if err != nil {
				return err
			}
			s, err := p.summary(token, bestBlock)
			if err != nil {
				return fmt.Errorf("summary %v: %v", v, err)
			}
			switch s.Status {
			case ticketvote.VoteStatusUnauthorized:
				unauthorized = append(unauthorized, v)
			case ticketvote.VoteStatusAuthorized:
				authorized = append(authorized, v)
			case ticketvote.VoteStatusStarted:
				started[v] = s.EndBlockHeight
			case ticketvote.VoteStatusFinished:
				finished = append(finished, v)
			default:
				return fmt.Errorf("invalid vote status %v %v", v, s.Status)
			}
		}
	}

	p.Lock()
	p.inv = voteInventory{
		unauthorized: unauthorized,
		authorized:   authorized,
		started:      started,
		finished:     finished,
		bestBlock:    bestBlock,
	}
	p.Unlock()

	// Build votes cace
	log.Infof("ticketvote: building votes cache")

	for k := range started {
		token, err := tokenDecode(k)
		if err != nil {
			return err
		}
		votes, err := p.castVotes(token)
		if err != nil {
			return fmt.Errorf("castVotes %v: %v", token, err)
		}
		for _, v := range votes {
			p.cachedVotesSet(v.Token, v.Ticket, v.VoteBit)
		}
	}

	return nil
}

// cmd executes a plugin command.
//
// This function satisfies the pluginClient interface.
func (p *ticketVotePlugin) cmd(cmd, payload string) (string, error) {
	log.Tracef("ticketvote cmd: %v %v", cmd, payload)

	switch cmd {
	case ticketvote.CmdAuthorize:
		return p.cmdAuthorize(payload)
	case ticketvote.CmdStart:
		return p.cmdStart(payload)
	case ticketvote.CmdCastBallot:
		return p.cmdCastBallot(payload)
	case ticketvote.CmdDetails:
		return p.cmdDetails(payload)
	case ticketvote.CmdResults:
		return p.cmdResults(payload)
	case ticketvote.CmdSummaries:
		return p.cmdSummaries(payload)
	case ticketvote.CmdInventory:
		return p.cmdInventory(payload)
	}

	return "", backend.ErrPluginCmdInvalid
}

// hook executes a plugin hook.
//
// This function satisfies the pluginClient interface.
func (p *ticketVotePlugin) hook(h hookT, payload string) error {
	log.Tracef("ticketvote hook: %v %v", hooks[h], payload)

	return nil
}

// Fsck performs a plugin filesystem check.
//
// This function satisfies the pluginClient interface.
func (p *ticketVotePlugin) fsck() error {
	log.Tracef("ticketvote fsck")

	return nil
}

func newTicketVotePlugin(backend backend.Backend, tlog tlogClient, settings []backend.PluginSetting, id *identity.FullIdentity, activeNetParams *chaincfg.Params) (*ticketVotePlugin, error) {
	// Plugin settings
	var (
		dataDir         string
		voteDurationMin uint32
		voteDurationMax uint32
	)

	// Set plugin settings to defaults. These will be overwritten if
	// the setting was specified by the user.
	switch activeNetParams.Name {
	case chaincfg.MainNetParams().Name:
		voteDurationMin = ticketvote.DefaultMainNetVoteDurationMin
		voteDurationMax = ticketvote.DefaultMainNetVoteDurationMax
	case chaincfg.TestNet3Params().Name:
		voteDurationMin = ticketvote.DefaultTestNetVoteDurationMin
		voteDurationMax = ticketvote.DefaultTestNetVoteDurationMax
	case chaincfg.SimNetParams().Name:
		voteDurationMin = ticketvote.DefaultSimNetVoteDurationMin
		voteDurationMax = ticketvote.DefaultSimNetVoteDurationMax
	default:
		return nil, fmt.Errorf("unknown active net: %v", activeNetParams.Name)
	}

	// Parse user provided plugin settings
	for _, v := range settings {
		switch v.Key {
		case pluginSettingDataDir:
			dataDir = v.Value
		case pluginSettingVoteDurationMin:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("plugin setting '%v': ParseUint(%v): %v",
					v.Key, v.Value, err)
			}
			voteDurationMin = uint32(u)
		case pluginSettingVoteDurationMax:
			u, err := strconv.ParseUint(v.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("plugin setting '%v': ParseUint(%v): %v",
					v.Key, v.Value, err)
			}
			voteDurationMax = uint32(u)
		default:
			return nil, fmt.Errorf("invalid plugin setting '%v'", v.Key)
		}
	}

	// Verify required plugin settings
	switch {
	case dataDir == "":
		return nil, fmt.Errorf("plugin setting not found: %v",
			pluginSettingDataDir)
	}

	// Create the plugin data directory
	dataDir = filepath.Join(dataDir, ticketvote.ID)
	err := os.MkdirAll(dataDir, 0700)
	if err != nil {
		return nil, err
	}

	return &ticketVotePlugin{
		activeNetParams: activeNetParams,
		backend:         backend,
		tlog:            tlog,
		voteDurationMin: voteDurationMin,
		voteDurationMax: voteDurationMax,
		dataDir:         dataDir,
		identity:        id,
		inv: voteInventory{
			unauthorized: make([]string, 0, 1024),
			authorized:   make([]string, 0, 1024),
			started:      make(map[string]uint32, 1024),
			finished:     make([]string, 0, 1024),
			bestBlock:    0,
		},
		votes:   make(map[string]map[string]string),
		mutexes: make(map[string]*sync.Mutex),
	}, nil
}
