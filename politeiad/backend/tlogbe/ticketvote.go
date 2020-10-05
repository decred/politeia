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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/dcrec/secp256k1/v3/ecdsa"
	"github.com/decred/dcrd/dcrutil/v3"
	"github.com/decred/dcrd/wire"
	"github.com/decred/politeia/plugins/dcrdata"
	"github.com/decred/politeia/plugins/ticketvote"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe/store"
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
	dataDescriptorAuthorizeDetails = "authorizedetails"
	dataDescriptorVoteDetails      = "votedetails"
	dataDescriptorCastVoteDetails  = "castvotedetails"

	// Prefixes that are appended to key-value store keys before
	// storing them in the log leaf ExtraData field.
	keyPrefixAuthorizeDetails = "authorizedetails:"
	keyPrefixVoteDetails      = "votedetails:"
	keyPrefixCastVoteDetails  = "castvotedetails:"
)

var (
	_ pluginClient = (*ticketVotePlugin)(nil)
)

// TODO holding the lock before verifying the token can allow the mutexes to
// be spammed. Create an infinite amount of them with invalid tokens. The fix
// is to add an exists() method onto the tlogClient and have the mutexes
// function ensure a token is valid before holding the lock on it.

// ticketVotePlugin satisfies the pluginClient interface.
type ticketVotePlugin struct {
	sync.Mutex
	backend backend.Backend
	tlog    tlogClient

	// Plugin settings
	activeNetParams *chaincfg.Params
	voteDurationMin uint32 // In blocks
	voteDurationMax uint32 // In blocks

	// identity contains the full identity that the plugin uses to
	// create receipts, i.e. signatures of user provided data that
	// prove the backend received and processed a plugin command.
	identity *identity.FullIdentity

	// dataDir is the ticket vote plugin data directory. The only data
	// that is stored here is cached data that can be re-created at any
	// time by walking the trillian trees. Ex, the vote summary once a
	// record vote has ended.
	dataDir string

	// inv contains the record inventory categorized by vote status.
	// The inventory will only contain public, non-abandoned records.
	// This cache is built on startup.
	inv inventory

	// votes contains the cast votes of ongoing record votes. This
	// cache is built on startup and record entries are removed once
	// the vote has ended and the vote summary has been saved.
	votes map[string]map[string]string // [token][ticket]voteBit

	// Mutexes contains a mutex for each record. The mutexes are lazy
	// loaded.
	mutexes map[string]*sync.Mutex // [string]mutex
}

type inventory struct {
	unauthorized []string          // Unauthorized tokens
	authorized   []string          // Authorized tokens
	started      map[string]uint32 // [token]endHeight
	finished     []string          // Finished tokens
	bestBlock    uint32            // Height of last inventory update
}

func (p *ticketVotePlugin) cachedInventory() inventory {
	p.Lock()
	defer p.Unlock()

	// Return a copy of the inventory
	var (
		unauthorized = make([]string, len(p.inv.unauthorized))
		authorized   = make([]string, len(p.inv.authorized))
		started      = make(map[string]uint32, len(p.inv.started))
		finished     = make([]string, len(p.inv.finished))
	)
	for k, v := range p.inv.unauthorized {
		unauthorized[k] = v
	}
	for k, v := range p.inv.authorized {
		authorized[k] = v
	}
	for k, v := range p.inv.started {
		started[k] = v
	}
	for k, v := range p.inv.finished {
		finished[k] = v
	}

	return inventory{
		unauthorized: unauthorized,
		authorized:   authorized,
		started:      started,
		finished:     finished,
	}
}

func (p *ticketVotePlugin) cachedInventorySet(inv inventory) {
	p.Lock()
	defer p.Unlock()

	p.inv = inv
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

	log.Debugf("Votes add: %v %v %v", token, ticket, voteBit)
}

func (p *ticketVotePlugin) cachedVotesDel(token string) {
	p.Lock()
	defer p.Unlock()

	delete(p.votes, token)

	log.Debugf("Votes del: %v", token)
}

func (p *ticketVotePlugin) cachedSummaryPath(token string) string {
	fn := strings.Replace(filenameSummary, "{token}", token, 1)
	return filepath.Join(p.dataDir, fn)
}

func (p *ticketVotePlugin) cachedSummary(token string) (*ticketvote.Summary, error) {
	p.Lock()
	defer p.Unlock()

	fp := p.cachedSummaryPath(token)
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

	fp := p.cachedSummaryPath(token)
	err = ioutil.WriteFile(fp, b, 0664)
	if err != nil {
		return err
	}

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

func convertAuthorizeDetailsFromBlobEntry(be store.BlobEntry) (*ticketvote.AuthorizeDetails, error) {
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
	if dd.Descriptor != dataDescriptorAuthorizeDetails {
		return nil, fmt.Errorf("unexpected data descriptor: got %v, want %v",
			dd.Descriptor, dataDescriptorAuthorizeDetails)
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
	var ad ticketvote.AuthorizeDetails
	err = json.Unmarshal(b, &ad)
	if err != nil {
		return nil, fmt.Errorf("unmarshal AuthorizeDetails: %v", err)
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

func convertBlobEntryFromAuthorizeDetails(ad ticketvote.AuthorizeDetails) (*store.BlobEntry, error) {
	data, err := json.Marshal(ad)
	if err != nil {
		return nil, err
	}
	hint, err := json.Marshal(
		store.DataDescriptor{
			Type:       store.DataTypeStructure,
			Descriptor: dataDescriptorAuthorizeDetails,
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

func (p *ticketVotePlugin) authorizeSave(ad ticketvote.AuthorizeDetails) error {
	token, err := hex.DecodeString(ad.Token)
	if err != nil {
		return err
	}

	// Prepare blob
	be, err := convertBlobEntryFromAuthorizeDetails(ad)
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
	merkles, err := p.tlog.save(tlogIDVetted, token, keyPrefixAuthorizeDetails,
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

func (p *ticketVotePlugin) authorizes(token []byte) ([]ticketvote.AuthorizeDetails, error) {
	// Retrieve blobs
	blobs, err := p.tlog.blobsByKeyPrefix(tlogIDVetted, token,
		keyPrefixAuthorizeDetails)
	if err != nil {
		return nil, err
	}

	// Decode blobs
	auths := make([]ticketvote.AuthorizeDetails, 0, len(blobs))
	for _, v := range blobs {
		be, err := store.Deblob(v)
		if err != nil {
			return nil, err
		}
		a, err := convertAuthorizeDetailsFromBlobEntry(*be)
		if err != nil {
			return nil, err
		}
		auths = append(auths, *a)
	}

	return auths, nil
}

func (p *ticketVotePlugin) voteSave(vd ticketvote.VoteDetails) error {
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

	return &ticketvote.StartReply{
		StartBlockHeight: snapshotHeight,
		StartBlockHash:   snapshotHash,
		EndBlockHeight:   snapshotHeight + duration,
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
	// expects bas64.
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
	token, err := hex.DecodeString(a.Token)
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
	case ticketvote.ActionAuthorize:
		// This is allowed
	case ticketvote.ActionRevoke:
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
		if a.Action != ticketvote.ActionAuthorize {
			return "", backend.PluginUserError{
				PluginID:     ticketvote.ID,
				ErrorCode:    int(ticketvote.ErrorStatusAuthorizationInvalid),
				ErrorContext: []string{"no prev action; action must be authorize"},
			}
		}
	case prevAction == ticketvote.ActionAuthorize:
		// Previous action was a authorize. This action must be revoke.
		return "", backend.PluginUserError{
			ErrorCode:    int(ticketvote.ErrorStatusAuthorizationInvalid),
			ErrorContext: []string{"prev action was authorize"},
		}
	case prevAction == ticketvote.ActionRevoke:
		// Previous action was a revoke. This action must be authorize.
		return "", backend.PluginUserError{
			PluginID:     ticketvote.ID,
			ErrorCode:    int(ticketvote.ErrorStatusAuthorizationInvalid),
			ErrorContext: []string{"prev action was revoke"},
		}
	}

	// Prepare authorize vote
	receipt := p.identity.SignMessage([]byte(a.Signature))
	auth := ticketvote.AuthorizeDetails{
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

	return nil
}

func (p *ticketVotePlugin) cmdStart(payload string) (string, error) {
	log.Tracef("ticketvote cmdStart: %v", payload)

	// Decode payload
	s, err := ticketvote.DecodeStart([]byte(payload))
	if err != nil {
		return "", err
	}

	// Verify token
	token, err := hex.DecodeString(s.Params.Token)
	if err != nil {
		return "", backend.PluginUserError{
			PluginID:  ticketvote.ID,
			ErrorCode: int(ticketvote.ErrorStatusTokenInvalid),
		}
	}

	// Verify signature
	vb, err := json.Marshal(s.Params)
	if err != nil {
		return "", err
	}
	msg := hex.EncodeToString(util.Digest(vb))
	err = util.VerifySignature(s.Signature, s.PublicKey, msg)
	if err != nil {
		return "", convertTicketVoteErrFromSignatureErr(err)
	}

	// Verify vote options and params
	err = voteParamsVerify(s.Params, p.voteDurationMin, p.voteDurationMax)
	if err != nil {
		return "", err
	}

	// Verify record version
	version := strconv.FormatUint(uint64(s.Params.Version), 10)
	_, err = p.backend.GetVetted(token, version)
	if err != nil {
		if err == backend.ErrRecordNotFound {
			e := fmt.Sprintf("version %v not found", version)
			return "", backend.PluginUserError{
				PluginID:     ticketvote.ID,
				ErrorCode:    int(ticketvote.ErrorStatusRecordNotFound),
				ErrorContext: []string{e},
			}
		}
	}

	// Verify vote authorization
	auths, err := p.authorizes(token)
	if err != nil {
		return "", err
	}
	if len(auths) == 0 {
		return "", backend.PluginUserError{
			PluginID:     ticketvote.ID,
			ErrorCode:    int(ticketvote.ErrorStatusAuthorizationInvalid),
			ErrorContext: []string{"authorization not found"},
		}
	}
	action := ticketvote.AuthActionT(auths[len(auths)-1].Action)
	if action != ticketvote.ActionAuthorize {
		return "", backend.PluginUserError{
			PluginID:     ticketvote.ID,
			ErrorCode:    int(ticketvote.ErrorStatusAuthorizationInvalid),
			ErrorContext: []string{"not authorized"},
		}
	}

	// Get vote blockchain data
	sr, err := p.startReply(s.Params.Duration)
	if err != nil {
		return "", err
	}

	// Any previous vote details must be retrieved to verify that a vote
	// has not already been started. The lock must be held for the
	// remainder of this function.
	m := p.mutex(s.Params.Token)
	m.Lock()
	defer m.Unlock()

	// Verify vote has not already been started
	svp, err := p.voteDetails(token)
	if err != nil {
		return "", err
	}
	if svp != nil {
		// Vote has already been started
		return "", backend.PluginUserError{
			PluginID:     ticketvote.ID,
			ErrorCode:    int(ticketvote.ErrorStatusVoteStatusInvalid),
			ErrorContext: []string{"vote already started"},
		}
	}

	// Prepare vote details
	vd := ticketvote.VoteDetails{
		Params:           s.Params,
		PublicKey:        s.PublicKey,
		Signature:        s.Signature,
		StartBlockHeight: sr.StartBlockHeight,
		StartBlockHash:   sr.StartBlockHash,
		EndBlockHeight:   sr.EndBlockHeight,
		EligibleTickets:  sr.EligibleTickets,
	}

	// Save vote details
	err = p.voteSave(vd)
	if err != nil {
		return "", fmt.Errorf("startSave: %v", err)
	}

	// Prepare reply
	reply, err := ticketvote.EncodeStartReply(*sr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

func (p *ticketVotePlugin) cmdStartRunoff(payload string) (string, error) {
	log.Tracef("ticketvote cmdStartRunoff: %v", payload)

	return "", nil
}

// ballotExitWithErr applies the provided vote error to each of the cast vote
// replies then returns the encoded ballot reply.
func ballotExitWithErr(votes []ticketvote.CastVote, errCode ticketvote.VoteErrorT, errContext string) (string, error) {
	token := votes[0].Token
	receipts := make([]ticketvote.CastVoteReply, len(votes))
	for k, v := range votes {
		// Its possible that cast votes were provided for different
		// records. This is not allowed. Verify the token is the same
		// before applying the provided error.
		if v.Token != token {
			// Token is not the same. Use multiple record vote error.
			e := ticketvote.VoteErrorMultipleRecordVotes
			receipts[k].Ticket = v.Ticket
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = ticketvote.VoteError[e]
			continue
		}

		// Use the provided vote error
		receipts[k].Ticket = v.Ticket
		receipts[k].ErrorCode = errCode
		receipts[k].ErrorContext = errContext
	}

	// Prepare reply
	br := ticketvote.BallotReply{
		Receipts: receipts,
	}
	reply, err := ticketvote.EncodeBallotReply(br)
	if err != nil {
		return "", err
	}
	return string(reply), nil
}

// TODO test this when casting large blocks of votes
// cmdBallot casts a ballot of votes. This function will not return a user
// error if one occurs. It will instead return the ballot reply with the error
// included in the invidiual cast vote reply that it applies to.
func (p *ticketVotePlugin) cmdBallot(payload string) (string, error) {
	log.Tracef("ticketvote cmdBallot: %v", payload)

	// Decode payload
	ballot, err := ticketvote.DecodeBallot([]byte(payload))
	if err != nil {
		return "", err
	}
	votes := ballot.Votes

	// Verify there is work to do
	if len(votes) == 0 {
		// Nothing to do
		br := ticketvote.BallotReply{
			Receipts: []ticketvote.CastVoteReply{},
		}
		reply, err := ticketvote.EncodeBallotReply(br)
		if err != nil {
			return "", err
		}
		return string(reply), nil
	}

	// Verify token
	token, err := hex.DecodeString(votes[0].Token)
	if err != nil {
		e := ticketvote.VoteErrorTokenInvalid
		c := fmt.Sprintf("%v: not hex", ticketvote.VoteError[e])
		return ballotExitWithErr(votes, e, c)
	}

	// Verify record vote status
	vd, err := p.voteDetails(token)
	if err != nil {
		return "", err
	}
	if vd == nil {
		// Vote has not been started yet
		e := ticketvote.VoteErrorVoteStatusInvalid
		c := fmt.Sprintf("%v: vote not started", ticketvote.VoteError[e])
		return ballotExitWithErr(votes, e, c)
	}
	bb, err := p.bestBlock()
	if err != nil {
		return "", err
	}
	if bb >= vd.EndBlockHeight {
		// Vote has ended
		e := ticketvote.VoteErrorVoteStatusInvalid
		c := fmt.Sprintf("%v: vote has ended", ticketvote.VoteError[e])
		return ballotExitWithErr(votes, e, c)
	}

	// Put eligible tickets in a map for easy lookups
	eligible := make(map[string]struct{}, len(vd.EligibleTickets))
	for _, v := range vd.EligibleTickets {
		eligible[v] = struct{}{}
	}

	// Obtain largest commitment addresses for each ticket. The vote
	// must be signed using the largest commitment address.
	tickets := make([]string, 0, len(ballot.Votes))
	for _, v := range ballot.Votes {
		tickets = append(tickets, v.Ticket)
	}
	addrs, err := p.largestCommitmentAddrs(tickets)
	if err != nil {
		return "", fmt.Errorf("largestCommitmentAddrs: %v", err)
	}

	// The lock must be held for the remainder of the function to
	// ensure duplicate votes cannot be cast.
	m := p.mutex(hex.EncodeToString(token))
	m.Lock()
	defer m.Unlock()

	// castVotes contains the tickets that have alread voted
	castVotes := p.cachedVotes(token)

	// Verify and save votes
	receipts := make([]ticketvote.CastVoteReply, len(votes))
	for k, v := range votes {
		// Set receipt ticket
		receipts[k].Ticket = v.Ticket

		// Verify token is the same
		if v.Token != hex.EncodeToString(token) {
			e := ticketvote.VoteErrorMultipleRecordVotes
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = ticketvote.VoteError[e]
			continue
		}

		// Verify vote bit
		bit, err := strconv.ParseUint(v.VoteBit, 16, 64)
		if err != nil {
			e := ticketvote.VoteErrorVoteBitInvalid
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = ticketvote.VoteError[e]
			continue
		}
		err = voteBitVerify(vd.Params.Options, vd.Params.Mask, bit)
		if err != nil {
			e := ticketvote.VoteErrorVoteBitInvalid
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = fmt.Sprintf("%v: %v",
				ticketvote.VoteError[e], err)
			continue
		}

		// Verify vote signature
		ca := addrs[k]
		if ca.ticket != v.Ticket {
			t := time.Now().Unix()
			log.Errorf("cmdBallot: commitment addr mismatch %v: %v %v",
				t, ca.ticket, v.Ticket)
			e := ticketvote.VoteErrorInternalError
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = fmt.Sprintf("%v: %v",
				ticketvote.VoteError[e], t)
			continue
		}
		if ca.err != nil {
			t := time.Now().Unix()
			log.Errorf("cmdBallot: commitment addr error %v: %v %v",
				t, ca.ticket, ca.err)
			e := ticketvote.VoteErrorInternalError
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = fmt.Sprintf("%v: %v",
				ticketvote.VoteError[e], t)
			continue
		}
		err = p.castVoteSignatureVerify(v, ca.addr)
		if err != nil {
			e := ticketvote.VoteErrorSignatureInvalid
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = fmt.Sprintf("%v: %v",
				ticketvote.VoteError[e], err)
			continue
		}

		// Verify ticket is eligible to vote
		_, ok := eligible[v.Ticket]
		if !ok {
			e := ticketvote.VoteErrorTicketNotEligible
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = ticketvote.VoteError[e]
			continue
		}

		// Verify ticket has not already vote
		_, ok = castVotes[v.Ticket]
		if ok {
			e := ticketvote.VoteErrorTicketAlreadyVoted
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = ticketvote.VoteError[e]
			continue
		}

		// Save cast vote
		receipt := p.identity.SignMessage([]byte(v.Signature))
		cv := ticketvote.CastVoteDetails{
			Token:     v.Token,
			Ticket:    v.Ticket,
			VoteBit:   v.VoteBit,
			Signature: v.Signature,
			Receipt:   hex.EncodeToString(receipt[:]),
		}
		err = p.castVoteSave(cv)
		if err != nil {
			t := time.Now().Unix()
			log.Errorf("cmdBallot: castVoteSave %v: %v", t, err)
			e := ticketvote.VoteErrorInternalError
			receipts[k].ErrorCode = e
			receipts[k].ErrorContext = fmt.Sprintf("%v: %v",
				ticketvote.VoteError[e], t)
			continue
		}

		// Update receipt
		receipts[k].Ticket = cv.Ticket
		receipts[k].Receipt = cv.Receipt

		// Update cast votes cache
		p.cachedVotesSet(v.Token, v.Ticket, v.VoteBit)
	}

	// Prepare reply
	br := ticketvote.BallotReply{
		Receipts: receipts,
	}
	reply, err := ticketvote.EncodeBallotReply(br)
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
		token, err := hex.DecodeString(v)
		if err != nil {
			continue
		}

		// Get authorize votes
		auths, err := p.authorizes(token)
		if err != nil {
			if err == errRecordNotFound {
				continue
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

func (p *ticketVotePlugin) cmdCastVotes(payload string) (string, error) {
	log.Tracef("ticketvote cmdCastVotes: %v", payload)

	// Decode payload
	cv, err := ticketvote.DecodeCastVotes([]byte(payload))
	if err != nil {
		return "", err
	}

	// Verify token
	token, err := hex.DecodeString(cv.Token)
	if err != nil {
		return "", backend.PluginUserError{
			PluginID:  ticketvote.ID,
			ErrorCode: int(ticketvote.ErrorStatusTokenInvalid),
		}
	}

	// Get cast votes
	votes, err := p.castVotes(token)
	if err != nil {
		return "", err
	}

	// Prepare reply
	cvr := ticketvote.CastVotesReply{
		Votes: votes,
	}
	reply, err := ticketvote.EncodeCastVotesReply(cvr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

func (p *ticketVotePlugin) summary(token []byte, bestBlock uint32) (*ticketvote.Summary, error) {
	// Check if the summary has been cached
	s, err := p.cachedSummary(hex.EncodeToString(token))
	switch {
	case err == errRecordNotFound:
		// Cached summary not found
	case err != nil:
		// Some other error
		return nil, fmt.Errorf("cachedSummary: %v", err)
	default:
		// Caches summary was found. Return it.
		return s, nil
	}

	// Summary has not been cached. Get it manually.

	// Check if the vote has been authorized
	auths, err := p.authorizes(token)
	if err != nil {
		return nil, fmt.Errorf("authorizes: %v", err)
	}
	if len(auths) == 0 {
		// Vote has not been authorized yet
		return &ticketvote.Summary{
			Status:  ticketvote.VoteStatusUnauthorized,
			Results: []ticketvote.Result{},
		}, nil
	}
	lastAuth := auths[len(auths)-1]
	switch ticketvote.AuthActionT(lastAuth.Action) {
	case ticketvote.ActionAuthorize:
		// Vote has been authorized; continue
	case ticketvote.ActionRevoke:
		// Vote authorization has been revoked
		return &ticketvote.Summary{
			Status:  ticketvote.VoteStatusUnauthorized,
			Results: []ticketvote.Result{},
		}, nil
	}

	// Vote has been authorized. Check if it has been started yet.
	vd, err := p.voteDetails(token)
	if err != nil {
		return nil, fmt.Errorf("startDetails: %v", err)
	}
	if vd == nil {
		// Vote has not been started yet
		return &ticketvote.Summary{
			Status:  ticketvote.VoteStatusAuthorized,
			Results: []ticketvote.Result{},
		}, nil
	}

	// Vote has been started. Check if it is still in progress or has
	// already ended.
	var status ticketvote.VoteStatusT
	if bestBlock < vd.EndBlockHeight {
		status = ticketvote.VoteStatusStarted
	} else {
		status = ticketvote.VoteStatusFinished
	}

	// Pull the cast votes from the cache and calculate the results
	// manually.
	votes := p.cachedVotes(token)
	tally := make(map[string]int, len(vd.Params.Options))
	for _, voteBit := range votes {
		tally[voteBit]++
	}
	results := make([]ticketvote.Result, len(vd.Params.Options))
	for _, v := range vd.Params.Options {
		bit := strconv.FormatUint(v.Bit, 16)
		results = append(results, ticketvote.Result{
			ID:          v.ID,
			Description: v.Description,
			VoteBit:     v.Bit,
			Votes:       uint64(tally[bit]),
		})
	}

	// Approved can only be calculated on certain types of votes
	var approved bool
	switch vd.Params.Type {
	case ticketvote.VoteTypeStandard, ticketvote.VoteTypeRunoff:
		// Calculate results for a simple approve/reject vote
		var total uint64
		for _, v := range results {
			total += v.Votes
		}

		var (
			eligible   = float64(len(vd.EligibleTickets))
			quorumPerc = float64(vd.Params.QuorumPercentage)
			passPerc   = float64(vd.Params.PassPercentage)
			quorum     = uint64(quorumPerc / 100 * eligible)
			pass       = uint64(passPerc / 100 * float64(total))

			approvedVotes uint64
		)
		for _, v := range results {
			if v.ID == ticketvote.VoteOptionIDApprove {
				approvedVotes++
			}
		}

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
		Approved:         approved,
	}

	// Cache the summary if the vote has finished so we don't have to
	// calculate these results again.
	if status == ticketvote.VoteStatusFinished {
		// Save summary
		err = p.cachedSummarySave(vd.Params.Token, summary)
		if err != nil {
			return nil, fmt.Errorf("cachedSummarySave %v: %v %v",
				vd.Params.Token, err, summary)
		}

		// Remove record from the votes cache now that a summary has
		// been saved for it.
		p.cachedVotesDel(vd.Params.Token)
	}

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
		return "", fmt.Errorf("bestBlock: %v", err)
	}

	// Get summaries
	summaries := make(map[string]ticketvote.Summary, len(s.Tokens))
	for _, v := range s.Tokens {
		token, err := hex.DecodeString(v)
		if err != nil {
			return "", err
		}
		s, err := p.summary(token, bb)
		if err != nil {
			if err == errRecordNotFound {
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
	}
	reply, err := ticketvote.EncodeSummariesReply(sr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

func (p *ticketVotePlugin) inventory(bestBlock uint32) (*ticketvote.InventoryReply, error) {
	// Get existing inventory
	inv := p.cachedInventory()

	// Get backend inventory to see if there are any new unauthorized
	// records.
	invBackend, err := p.backend.InventoryByStatus()
	if err != nil {
		return nil, err
	}
	l := len(inv.unauthorized) + len(inv.authorized) +
		len(inv.started) + len(inv.finished)
	if l != len(invBackend.Vetted) {
		// There are new unauthorized records. Put all ticket vote
		// inventory records into a map so we can easily find what
		// backend records are missing.
		all := make(map[string]struct{}, l)
		for _, v := range inv.unauthorized {
			all[v] = struct{}{}
		}
		for _, v := range inv.authorized {
			all[v] = struct{}{}
		}
		for k := range inv.started {
			all[k] = struct{}{}
		}
		for _, v := range inv.finished {
			all[v] = struct{}{}
		}

		// Add any missing records to the inventory
		for _, v := range invBackend.Vetted {
			if _, ok := all[v]; !ok {
				inv.unauthorized = append(inv.unauthorized, v)
			}
		}

		// Update cache
		p.cachedInventorySet(inv)
	}

	// Check if inventory has already been updated for this block
	// height.
	if inv.bestBlock == bestBlock {
		// Inventory already updated. Nothing else to do.
		started := make([]string, 0, len(inv.started))
		for k := range inv.started {
			started = append(started, k)
		}
		return &ticketvote.InventoryReply{
			Unauthorized: inv.unauthorized,
			Authorized:   inv.authorized,
			Started:      started,
			Finished:     inv.finished,
			BestBlock:    bestBlock,
		}, nil
	}

	// Inventory has not been updated for this block height. Check if
	// any proposal votes have finished.
	started := make([]string, 0, len(inv.started))
	for token, endHeight := range inv.started {
		if bestBlock >= endHeight {
			// Vote has finished
			inv.finished = append(inv.finished, token)
		} else {
			// Vote is still ongoing
			started = append(started, token)
		}
	}

	// Update cache
	p.cachedInventorySet(inv)

	return &ticketvote.InventoryReply{
		Unauthorized: inv.unauthorized,
		Authorized:   inv.authorized,
		Started:      started,
		Finished:     inv.finished,
		BestBlock:    bestBlock,
	}, nil
}

func (p *ticketVotePlugin) cmdInventory(payload string) (string, error) {
	log.Tracef("ticketvote cmdInventory: %v", payload)

	// Payload is empty. Nothing to decode.

	// Get best block. This command does not write any data so we can
	// use the unsafe best block.
	bb, err := p.bestBlockUnsafe()
	if err != nil {
		return "", err
	}

	// Get the inventory
	ir, err := p.inventory(bb)
	if err != nil {
		return "", fmt.Errorf("inventory: %v", err)
	}

	// Prepare reply
	reply, err := ticketvote.EncodeInventoryReply(*ir)
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

	// TODO
	// Ensure dcrdata plugin has been registered
	// Build votes cache
	// Build inventory cache

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
	case ticketvote.CmdStartRunoff:
		return p.cmdStartRunoff(payload)
	case ticketvote.CmdBallot:
		return p.cmdBallot(payload)
	case ticketvote.CmdDetails:
		return p.cmdDetails(payload)
	case ticketvote.CmdCastVotes:
		return p.cmdCastVotes(payload)
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
	// Unpack plugin settings
	var (
		dataDir         string
		voteDurationMin uint32
		voteDurationMax uint32
	)
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

	// Set optional plugin settings to default values if a value was
	// not specified.
	if voteDurationMin == 0 {
		switch activeNetParams.Name {
		case chaincfg.MainNetParams().Name:
			voteDurationMin = ticketvote.DefaultMainNetVoteDurationMin
		case chaincfg.TestNet3Params().Name:
			voteDurationMin = ticketvote.DefaultTestNetVoteDurationMin
		case chaincfg.SimNetParams().Name:
			voteDurationMin = ticketvote.DefaultSimNetVoteDurationMin
		}
	}
	if voteDurationMax == 0 {
		switch activeNetParams.Name {
		case chaincfg.MainNetParams().Name:
			voteDurationMax = ticketvote.DefaultMainNetVoteDurationMax
		case chaincfg.TestNet3Params().Name:
			voteDurationMax = ticketvote.DefaultTestNetVoteDurationMax
		case chaincfg.SimNetParams().Name:
			voteDurationMax = ticketvote.DefaultSimNetVoteDurationMax
		}
	}

	// Create the plugin data directory
	dataDir = filepath.Join(dataDir, ticketvote.ID)
	err := os.MkdirAll(dataDir, 0700)
	if err != nil {
		return nil, err
	}

	return &ticketVotePlugin{
		dataDir:         dataDir,
		backend:         backend,
		tlog:            tlog,
		identity:        id,
		activeNetParams: activeNetParams,
		voteDurationMin: voteDurationMin,
		voteDurationMax: voteDurationMax,
	}, nil
}
