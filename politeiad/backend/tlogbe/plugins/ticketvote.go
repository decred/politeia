// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package plugins

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

	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1"
	"github.com/decred/dcrd/dcrutil"
	"github.com/decred/dcrd/wire"
	"github.com/decred/politeia/plugins/dcrdata"
	"github.com/decred/politeia/plugins/ticketvote"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe"
	"github.com/decred/politeia/politeiad/backend/tlogbe/store"
	"github.com/decred/politeia/util"
)

// TODO don't save data to the file system. Save it to the kv store and save
// the key to the file system. This will allow the data to be backed up.

const (
	// ticketVoteDirname is the ticket vote data directory name.
	ticketVoteDirname = "ticketvote"

	// Filenames of memoized data saved to the data dir.
	filenameSummary = "{token}-summary.json"

	// Blob entry data descriptors
	dataDescriptorAuthorizeVote = "authorizevote"
	dataDescriptorStartVote     = "startvote"
	dataDescriptorCastVote      = "castvote"

	// Prefixes that are appended to key-value store keys before
	// storing them in the log leaf ExtraData field.
	keyPrefixAuthorizeVote = "authorizevote:"
	keyPrefixStartVote     = "startvote:"
	keyPrefixCastVote      = "castvote:"
)

var (
	_ tlogbe.Plugin = (*ticketVotePlugin)(nil)

	// Local errors
	errRecordNotFound = errors.New("record not found")
)

// ticketVotePlugin satisfies the Plugin interface.
type ticketVotePlugin struct {
	sync.Mutex
	backend *tlogbe.TlogBackend

	// Plugin settings
	id              *identity.FullIdentity
	activeNetParams *chaincfg.Params
	voteDurationMin uint32 // In blocks
	voteDurationMax uint32 // In blocks

	// dataDir is the ticket vote plugin data directory. The only data
	// that is stored here is cached data that can be re-created at any
	// time by walking the trillian trees. Ex, the vote summary once a
	// record vote has ended.
	dataDir string

	// inv contains the record inventory catagorized by vote status.
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

func (p *ticketVotePlugin) cachedVotes(token string) map[string]string {
	p.Lock()
	defer p.Unlock()

	// Return a copy of the map
	cv, ok := p.votes[token]
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

func convertTicketVoteErrFromSignatureErr(err error) ticketvote.UserErrorReply {
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
	return ticketvote.UserErrorReply{
		ErrorCode:    s,
		ErrorContext: e.ErrorContext,
	}
}

func convertAuthorizeVoteFromBlobEntry(be store.BlobEntry) (*ticketvote.AuthorizeVote, error) {
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
	if dd.Descriptor != dataDescriptorAuthorizeVote {
		return nil, fmt.Errorf("unexpected data descriptor: got %v, want %v",
			dd.Descriptor, dataDescriptorAuthorizeVote)
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
	var av ticketvote.AuthorizeVote
	err = json.Unmarshal(b, &av)
	if err != nil {
		return nil, fmt.Errorf("unmarshal AuthorizeVote: %v", err)
	}

	return &av, nil
}

func convertStartVoteFromBlobEntry(be store.BlobEntry) (*ticketvote.StartVote, error) {
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
	if dd.Descriptor != dataDescriptorStartVote {
		return nil, fmt.Errorf("unexpected data descriptor: got %v, want %v",
			dd.Descriptor, dataDescriptorStartVote)
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
	var sv ticketvote.StartVote
	err = json.Unmarshal(b, &sv)
	if err != nil {
		return nil, fmt.Errorf("unmarshal StartVote: %v", err)
	}

	return &sv, nil
}

func convertCastVoteFromBlobEntry(be store.BlobEntry) (*ticketvote.CastVote, error) {
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
	if dd.Descriptor != dataDescriptorCastVote {
		return nil, fmt.Errorf("unexpected data descriptor: got %v, want %v",
			dd.Descriptor, dataDescriptorCastVote)
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
	var cv ticketvote.CastVote
	err = json.Unmarshal(b, &cv)
	if err != nil {
		return nil, fmt.Errorf("unmarshal CastVote: %v", err)
	}

	return &cv, nil
}

func convertBlobEntryFromAuthorizeVote(av ticketvote.AuthorizeVote) (*store.BlobEntry, error) {
	data, err := json.Marshal(av)
	if err != nil {
		return nil, err
	}
	hint, err := json.Marshal(
		store.DataDescriptor{
			Type:       store.DataTypeStructure,
			Descriptor: dataDescriptorAuthorizeVote,
		})
	if err != nil {
		return nil, err
	}
	be := store.BlobEntryNew(hint, data)
	return &be, nil
}

func convertBlobEntryFromStartVote(sv ticketvote.StartVote) (*store.BlobEntry, error) {
	data, err := json.Marshal(sv)
	if err != nil {
		return nil, err
	}
	hint, err := json.Marshal(
		store.DataDescriptor{
			Type:       store.DataTypeStructure,
			Descriptor: dataDescriptorStartVote,
		})
	if err != nil {
		return nil, err
	}
	be := store.BlobEntryNew(hint, data)
	return &be, nil
}

func convertBlobEntryFromCastVote(cv ticketvote.CastVote) (*store.BlobEntry, error) {
	data, err := json.Marshal(cv)
	if err != nil {
		return nil, err
	}
	hint, err := json.Marshal(
		store.DataDescriptor{
			Type:       store.DataTypeStructure,
			Descriptor: dataDescriptorCastVote,
		})
	if err != nil {
		return nil, err
	}
	be := store.BlobEntryNew(hint, data)
	return &be, nil
}

func authorizeVoteSave(client *tlogbe.RecordClient, av ticketvote.AuthorizeVote) error {
	// Prepare blob
	be, err := convertBlobEntryFromAuthorizeVote(av)
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
	merkles, err := client.Save(keyPrefixAuthorizeVote,
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

func authorizeVotes(client *tlogbe.RecordClient) ([]ticketvote.AuthorizeVote, error) {
	// Retrieve blobs
	blobs, err := client.BlobsByKeyPrefix(keyPrefixAuthorizeVote)
	if err != nil {
		return nil, err
	}

	// Decode blobs
	auths := make([]ticketvote.AuthorizeVote, 0, len(blobs))
	for _, v := range blobs {
		be, err := store.Deblob(v)
		if err != nil {
			return nil, err
		}
		a, err := convertAuthorizeVoteFromBlobEntry(*be)
		if err != nil {
			return nil, err
		}
		auths = append(auths, *a)
	}

	return auths, nil
}

func startVoteSave(client *tlogbe.RecordClient, sv ticketvote.StartVote) error {
	// Prepare blob
	be, err := convertBlobEntryFromStartVote(sv)
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
	merkles, err := client.Save(keyPrefixStartVote,
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

// startVote returns the StartVote for the provided record if one exists.
func startVote(client *tlogbe.RecordClient) (*ticketvote.StartVote, error) {
	// Retrieve blobs
	blobs, err := client.BlobsByKeyPrefix(keyPrefixStartVote)
	if err != nil {
		return nil, err
	}
	switch len(blobs) {
	case 0:
		// A start vote does not exist
		return nil, nil
	case 1:
		// A start vote exists; continue
	default:
		// This should not happen. There should only ever be a max of
		// one start vote.
		return nil, fmt.Errorf("multiple start votes found (%v) for record %x",
			len(blobs), client.Token)
	}

	// Decode blob
	be, err := store.Deblob(blobs[0])
	if err != nil {
		return nil, err
	}
	sv, err := convertStartVoteFromBlobEntry(*be)
	if err != nil {
		return nil, err
	}

	return sv, nil
}

func castVotes(client *tlogbe.RecordClient) ([]ticketvote.CastVote, error) {
	// Retrieve blobs
	blobs, err := client.BlobsByKeyPrefix(keyPrefixCastVote)
	if err != nil {
		return nil, err
	}

	// Decode blobs
	votes := make([]ticketvote.CastVote, 0, len(blobs))
	for _, v := range blobs {
		be, err := store.Deblob(v)
		if err != nil {
			return nil, err
		}
		cv, err := convertCastVoteFromBlobEntry(*be)
		if err != nil {
			return nil, err
		}
		votes = append(votes, *cv)
	}

	return votes, nil
}

func castVoteSave(client *tlogbe.RecordClient, cv ticketvote.CastVote) error {
	// Prepare blob
	be, err := convertBlobEntryFromCastVote(cv)
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
	merkles, err := client.Save(keyPrefixCastVote,
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
	err    error  // Error if one occured
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
	addr, err := dcrutil.DecodeAddress(address)
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
	pk, wasCompressed, err := secp256k1.RecoverCompact(sig,
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
	return a.EncodeAddress() == address, nil
}

func (p *ticketVotePlugin) voteSignatureVerify(v ticketvote.Vote, addr string) error {
	msg := v.Token + v.Ticket + v.VoteBit

	// Convert hex signature to base64. The voteMessageVerify function
	// expects bas64.
	b, err := hex.DecodeString(v.Signature)
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

	// Verify signature
	version := strconv.FormatUint(uint64(a.Version), 10)
	msg := a.Token + version + string(a.Action)
	err = util.VerifySignature(a.Signature, a.PublicKey, msg)
	if err != nil {
		return "", convertTicketVoteErrFromSignatureErr(err)
	}

	// Get record client
	tokenb, err := hex.DecodeString(a.Token)
	if err != nil {
		return "", ticketvote.UserErrorReply{
			ErrorCode: ticketvote.ErrorStatusTokenInvalid,
		}
	}
	client, err := p.backend.RecordClient(tokenb)
	if err != nil {
		if err == backend.ErrRecordNotFound {
			return "", ticketvote.UserErrorReply{
				ErrorCode: ticketvote.ErrorStatusRecordNotFound,
			}
		}
		return "", err
	}
	if client.State != tlogbe.RecordStateVetted {
		return "", ticketvote.UserErrorReply{
			ErrorCode:    ticketvote.ErrorStatusRecordStatusInvalid,
			ErrorContext: []string{"record not vetted"},
		}
	}

	// Verify record version
	_, err = p.backend.GetVetted(tokenb, version)
	if err != nil {
		if err == backend.ErrRecordNotFound {
			e := fmt.Sprintf("version %v not found", version)
			return "", ticketvote.UserErrorReply{
				ErrorCode:    ticketvote.ErrorStatusRecordNotFound,
				ErrorContext: []string{e},
			}
		}
	}

	// Verify action
	switch a.Action {
	case ticketvote.ActionAuthorize:
		// This is allowed
	case ticketvote.ActionRevoke:
		// This is allowed
	default:
		e := fmt.Sprintf("%v not a valid action", a.Action)
		return "", ticketvote.UserErrorReply{
			ErrorCode:    ticketvote.ErrorStatusAuthorizationInvalid,
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
	auths, err := authorizeVotes(client)
	if err != nil {
		return "", err
	}
	var prevAction ticketvote.ActionT
	if len(auths) > 0 {
		prevAction = ticketvote.ActionT(auths[len(auths)-1].Action)
	}
	switch {
	case len(auths) == 0:
		// No previous actions. New action must be an authorize.
		if a.Action != ticketvote.ActionAuthorize {
			return "", ticketvote.UserErrorReply{
				ErrorCode:    ticketvote.ErrorStatusAuthorizationInvalid,
				ErrorContext: []string{"no prev action; action must be authorize"},
			}
		}
	case prevAction == ticketvote.ActionAuthorize:
		// Previous action was a authorize. This action must be revoke.
		return "", ticketvote.UserErrorReply{
			ErrorCode:    ticketvote.ErrorStatusAuthorizationInvalid,
			ErrorContext: []string{"prev action was authorize"},
		}
	case prevAction == ticketvote.ActionRevoke:
		// Previous action was a revoke. This action must be authorize.
		return "", ticketvote.UserErrorReply{
			ErrorCode:    ticketvote.ErrorStatusAuthorizationInvalid,
			ErrorContext: []string{"prev action was revoke"},
		}
	}

	// Prepare authorize vote
	receipt := p.id.SignMessage([]byte(a.Signature))
	auth := ticketvote.AuthorizeVote{
		Token:     a.Token,
		Version:   a.Version,
		Action:    string(a.Action),
		PublicKey: a.PublicKey,
		Signature: a.Signature,
		Timestamp: time.Now().Unix(),
		Receipt:   hex.EncodeToString(receipt[:]),
	}

	// Save authorize vote
	err = authorizeVoteSave(client, auth)
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

	// Verify bit is inlcuded in vote options
	for _, v := range options {
		if v.Bit == bit {
			// Bit matches one of the options. We're done.
			return nil
		}
	}

	return fmt.Errorf("bit 0x%x not found in vote options")
}

// TODO test this function
func voteDetailsVerify(vote ticketvote.VoteDetails, voteDurationMin, voteDurationMax uint32) error {
	// Verify vote type
	switch vote.Type {
	case ticketvote.VoteTypeStandard:
		// This is allowed
	case ticketvote.VoteTypeRunoff:
		// This is allowed
	default:
		e := fmt.Sprintf("invalid type %v", vote.Type)
		return ticketvote.UserErrorReply{
			ErrorCode:    ticketvote.ErrorStatusVoteDetailsInvalid,
			ErrorContext: []string{e},
		}
	}

	// Verify vote params
	switch {
	case vote.Duration > voteDurationMax:
		e := fmt.Sprintf("duration %v exceeds max duration %v",
			vote.Duration, voteDurationMax)
		return ticketvote.UserErrorReply{
			ErrorCode:    ticketvote.ErrorStatusVoteDetailsInvalid,
			ErrorContext: []string{e},
		}
	case vote.Duration < voteDurationMin:
		e := fmt.Sprintf("duration %v under min duration %v",
			vote.Duration, voteDurationMin)
		return ticketvote.UserErrorReply{
			ErrorCode:    ticketvote.ErrorStatusVoteDetailsInvalid,
			ErrorContext: []string{e},
		}
	case vote.QuorumPercentage > 100:
		e := fmt.Sprintf("quorum percent %v exceeds 100 percent",
			vote.QuorumPercentage)
		return ticketvote.UserErrorReply{
			ErrorCode:    ticketvote.ErrorStatusVoteDetailsInvalid,
			ErrorContext: []string{e},
		}
	case vote.PassPercentage > 100:
		e := fmt.Sprintf("pass percent %v exceeds 100 percent",
			vote.PassPercentage)
		return ticketvote.UserErrorReply{
			ErrorCode:    ticketvote.ErrorStatusVoteDetailsInvalid,
			ErrorContext: []string{e},
		}
	}

	// Verify vote options. Different vote types have different
	// requirements.
	if len(vote.Options) == 0 {
		return ticketvote.UserErrorReply{
			ErrorCode:    ticketvote.ErrorStatusVoteDetailsInvalid,
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
			return ticketvote.UserErrorReply{
				ErrorCode:    ticketvote.ErrorStatusVoteDetailsInvalid,
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
			return ticketvote.UserErrorReply{
				ErrorCode:    ticketvote.ErrorStatusVoteDetailsInvalid,
				ErrorContext: []string{e},
			}
		}
	}

	// Verify vote bits are somewhat sane
	for _, v := range vote.Options {
		err := voteBitVerify(vote.Options, vote.Mask, v.Bit)
		if err != nil {
			return ticketvote.UserErrorReply{
				ErrorCode:    ticketvote.ErrorStatusVoteDetailsInvalid,
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

	// Verify signature
	vb, err := json.Marshal(s.Vote)
	if err != nil {
		return "", err
	}
	msg := hex.EncodeToString(util.Digest(vb))
	err = util.VerifySignature(s.Signature, s.PublicKey, msg)
	if err != nil {
		return "", convertTicketVoteErrFromSignatureErr(err)
	}

	// Verify vote options and params
	err = voteDetailsVerify(s.Vote, p.voteDurationMin, p.voteDurationMax)
	if err != nil {
		return "", err
	}

	// Get record client
	tokenb, err := hex.DecodeString(s.Vote.Token)
	if err != nil {
		return "", ticketvote.UserErrorReply{
			ErrorCode: ticketvote.ErrorStatusTokenInvalid,
		}
	}
	client, err := p.backend.RecordClient(tokenb)
	if err != nil {
		if err == backend.ErrRecordNotFound {
			return "", ticketvote.UserErrorReply{
				ErrorCode: ticketvote.ErrorStatusRecordNotFound,
			}
		}
		return "", err
	}
	if client.State != tlogbe.RecordStateVetted {
		return "", ticketvote.UserErrorReply{
			ErrorCode:    ticketvote.ErrorStatusRecordStatusInvalid,
			ErrorContext: []string{"record not vetted"},
		}
	}

	// Verify record version
	version := strconv.FormatUint(uint64(s.Vote.Version), 10)
	_, err = p.backend.GetVetted(tokenb, version)
	if err != nil {
		if err == backend.ErrRecordNotFound {
			e := fmt.Sprintf("version %v not found", version)
			return "", ticketvote.UserErrorReply{
				ErrorCode:    ticketvote.ErrorStatusRecordNotFound,
				ErrorContext: []string{e},
			}
		}
	}

	// Verify vote authorization
	auths, err := authorizeVotes(client)
	if err != nil {
		return "", err
	}
	if len(auths) == 0 {
		return "", ticketvote.UserErrorReply{
			ErrorCode:    ticketvote.ErrorStatusAuthorizationInvalid,
			ErrorContext: []string{"authorization not found"},
		}
	}
	action := ticketvote.ActionT(auths[len(auths)-1].Action)
	if action != ticketvote.ActionAuthorize {
		return "", ticketvote.UserErrorReply{
			ErrorCode:    ticketvote.ErrorStatusAuthorizationInvalid,
			ErrorContext: []string{"not authorized"},
		}
	}

	// Get vote blockchain data
	sr, err := p.startReply(s.Vote.Duration)
	if err != nil {
		return "", err
	}

	// Any previous start vote must be retrieved to verify that a vote
	// has not already been started. The lock must be held for the
	// remainder of this function.
	m := p.mutex(s.Vote.Token)
	m.Lock()
	defer m.Unlock()

	// Verify vote has not already been started
	svp, err := startVote(client)
	if err != nil {
		return "", err
	}
	if svp != nil {
		// Vote has already been started
		return "", ticketvote.UserErrorReply{
			ErrorCode:    ticketvote.ErrorStatusVoteStatusInvalid,
			ErrorContext: []string{"vote already started"},
		}
	}

	// Prepare start vote
	sv := ticketvote.StartVote{
		Vote:             s.Vote,
		PublicKey:        s.PublicKey,
		Signature:        s.Signature,
		StartBlockHeight: sr.StartBlockHeight,
		StartBlockHash:   sr.StartBlockHash,
		EndBlockHeight:   sr.EndBlockHeight,
		EligibleTickets:  sr.EligibleTickets,
	}

	// Save start vote
	err = startVoteSave(client, sv)
	if err != nil {
		return "", fmt.Errorf("startVoteSave: %v", err)
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
func ballotExitWithErr(votes []ticketvote.Vote, errCode ticketvote.VoteErrorT, errContext string) (string, error) {
	token := votes[0].Token
	receipts := make([]ticketvote.VoteReply, len(votes))
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

	// Verify there is work to do
	if len(ballot.Votes) == 0 {
		// Nothing to do
		br := ticketvote.BallotReply{
			Receipts: []ticketvote.VoteReply{},
		}
		reply, err := ticketvote.EncodeBallotReply(br)
		if err != nil {
			return "", err
		}
		return string(reply), nil
	}

	// Get record client
	var (
		votes = ballot.Votes
		token = votes[0].Token
	)
	tokenb, err := hex.DecodeString(token)
	if err != nil {
		e := ticketvote.VoteErrorTokenInvalid
		c := fmt.Sprintf("%v: not hex", ticketvote.VoteError[e])
		return ballotExitWithErr(votes, e, c)
	}
	client, err := p.backend.RecordClient(tokenb)
	if err != nil {
		if err == backend.ErrRecordNotFound {
			e := ticketvote.VoteErrorRecordNotFound
			c := fmt.Sprintf("%v: %v", ticketvote.VoteError[e], token)
			return ballotExitWithErr(votes, e, c)
		}
		return "", err
	}
	if client.State != tlogbe.RecordStateVetted {
		e := ticketvote.VoteErrorVoteStatusInvalid
		c := fmt.Sprintf("%v: record is unvetted", ticketvote.VoteError[e])
		return ballotExitWithErr(votes, e, c)
	}

	// Verify record vote status
	sv, err := startVote(client)
	if err != nil {
		return "", err
	}
	if sv == nil {
		// Vote has not been started yet
		e := ticketvote.VoteErrorVoteStatusInvalid
		c := fmt.Sprintf("%v: vote not started", ticketvote.VoteError[e])
		return ballotExitWithErr(votes, e, c)
	}
	bb, err := p.bestBlock()
	if err != nil {
		return "", err
	}
	if bb >= sv.EndBlockHeight {
		// Vote has ended
		e := ticketvote.VoteErrorVoteStatusInvalid
		c := fmt.Sprintf("%v: vote has ended", ticketvote.VoteError[e])
		return ballotExitWithErr(votes, e, c)
	}

	// Put eligible tickets in a map for easy lookups
	eligible := make(map[string]struct{}, len(sv.EligibleTickets))
	for _, v := range sv.EligibleTickets {
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
	m := p.mutex(token)
	m.Lock()
	defer m.Unlock()

	// castVotes contains the tickets that have alread voted
	castVotes := p.cachedVotes(token)

	// Verify and save votes
	receipts := make([]ticketvote.VoteReply, len(votes))
	for k, v := range votes {
		// Set receipt ticket
		receipts[k].Ticket = v.Ticket

		// Verify token is the same
		if v.Token != token {
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
		err = voteBitVerify(sv.Vote.Options, sv.Vote.Mask, bit)
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
		err = p.voteSignatureVerify(v, ca.addr)
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
		receipt := p.id.SignMessage([]byte(v.Signature))
		cv := ticketvote.CastVote{
			Token:     v.Token,
			Ticket:    v.Ticket,
			VoteBit:   v.VoteBit,
			Signature: v.Signature,
			Receipt:   hex.EncodeToString(receipt[:]),
		}
		err = castVoteSave(client, cv)
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

	// Get record client
	tokenb, err := hex.DecodeString(d.Token)
	if err != nil {
		return "", ticketvote.UserErrorReply{
			ErrorCode: ticketvote.ErrorStatusTokenInvalid,
		}
	}
	client, err := p.backend.RecordClient(tokenb)
	if err != nil {
		if err == backend.ErrRecordNotFound {
			return "", ticketvote.UserErrorReply{
				ErrorCode: ticketvote.ErrorStatusRecordNotFound,
			}
		}
		return "", err
	}

	// Get authorize votes
	auths, err := authorizeVotes(client)
	if err != nil {
		return "", fmt.Errorf("authorizeVotes: %v", err)
	}

	// Get start vote
	sv, err := startVote(client)
	if err != nil {
		return "", fmt.Errorf("startVote: %v", err)
	}

	// Prepare rely
	dr := ticketvote.DetailsReply{
		Auths: auths,
		Vote:  sv,
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

	// Get record client
	tokenb, err := hex.DecodeString(cv.Token)
	if err != nil {
		return "", ticketvote.UserErrorReply{
			ErrorCode: ticketvote.ErrorStatusTokenInvalid,
		}
	}
	client, err := p.backend.RecordClient(tokenb)
	if err != nil {
		if err == backend.ErrRecordNotFound {
			return "", ticketvote.UserErrorReply{
				ErrorCode: ticketvote.ErrorStatusRecordNotFound,
			}
		}
		return "", err
	}

	// Get cast votes
	votes, err := castVotes(client)
	if err != nil {
		return "", fmt.Errorf("castVotes: %v", err)
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

func (p *ticketVotePlugin) summary(token string, bestBlock uint32) (*ticketvote.Summary, error) {
	// Check if the summary has been cached
	s, err := p.cachedSummary(token)
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

	// Cached summary not found. Get the record client so we can create
	// a summary manually.
	tokenb, err := hex.DecodeString(token)
	if err != nil {
		return nil, errRecordNotFound
	}
	client, err := p.backend.RecordClient(tokenb)
	if err != nil {
		return nil, errRecordNotFound
	}
	if client.State != tlogbe.RecordStateVetted {
		// Record exists but is unvetted so a vote can not have been
		// authorized yet.
		return &ticketvote.Summary{
			Status:  ticketvote.VoteStatusUnauthorized,
			Results: []ticketvote.Result{},
		}, nil
	}

	// Check if the vote has been authorized
	auths, err := authorizeVotes(client)
	if err != nil {
		return nil, fmt.Errorf("authorizeVotes: %v", err)
	}
	if len(auths) == 0 {
		// Vote has not been authorized yet
		return &ticketvote.Summary{
			Status:  ticketvote.VoteStatusUnauthorized,
			Results: []ticketvote.Result{},
		}, nil
	}
	lastAuth := auths[len(auths)-1]
	switch ticketvote.ActionT(lastAuth.Action) {
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
	sv, err := startVote(client)
	if err != nil {
		return nil, fmt.Errorf("startVote: %v", err)
	}
	if sv == nil {
		// Vote has not been started yet
		return &ticketvote.Summary{
			Status:  ticketvote.VoteStatusAuthorized,
			Results: []ticketvote.Result{},
		}, nil
	}

	// Vote has been started. Check if it is still in progress or has
	// already ended.
	var status ticketvote.VoteStatusT
	if bestBlock < sv.EndBlockHeight {
		status = ticketvote.VoteStatusStarted
	} else {
		status = ticketvote.VoteStatusFinished
	}

	// Pull the cast votes from the cache and calculate the results
	// manually.
	votes := p.cachedVotes(token)
	tally := make(map[string]int, len(sv.Vote.Options))
	for _, voteBit := range votes {
		tally[voteBit]++
	}
	results := make([]ticketvote.Result, len(sv.Vote.Options))
	for _, v := range sv.Vote.Options {
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
	switch sv.Vote.Type {
	case ticketvote.VoteTypeStandard, ticketvote.VoteTypeRunoff:
		// Calculate results for a simple approve/reject vote
		var total uint64
		for _, v := range results {
			total += v.Votes
		}

		var (
			eligible   = float64(len(sv.EligibleTickets))
			quorumPerc = float64(sv.Vote.QuorumPercentage)
			passPerc   = float64(sv.Vote.PassPercentage)
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
		Type:             sv.Vote.Type,
		Status:           status,
		Duration:         sv.Vote.Duration,
		StartBlockHeight: sv.StartBlockHeight,
		StartBlockHash:   sv.StartBlockHash,
		EndBlockHeight:   sv.EndBlockHeight,
		EligibleTickets:  uint32(len(sv.EligibleTickets)),
		QuorumPercentage: sv.Vote.QuorumPercentage,
		PassPercentage:   sv.Vote.PassPercentage,
		Results:          results,
		Approved:         approved,
	}

	// Cache the summary if the vote has finished so we don't have to
	// calculate these results again.
	if status == ticketvote.VoteStatusFinished {
		// Save summary
		err = p.cachedSummarySave(sv.Vote.Token, summary)
		if err != nil {
			return nil, fmt.Errorf("cachedSummarySave %v: %v %v",
				sv.Vote.Token, err, summary)
		}

		// Remove record from the votes cache now that a summary has
		// been saved for it.
		p.cachedVotesDel(sv.Vote.Token)
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
		s, err := p.summary(v, bb)
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

// Cmd executes a plugin command.
//
// This function satisfies the Plugin interface.
func (p *ticketVotePlugin) Cmd(cmd, payload string) (string, error) {
	log.Tracef("ticketvote Cmd: %v", cmd)

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

// Hook executes a plugin hook.
//
// This function satisfies the Plugin interface.
func (p *ticketVotePlugin) Hook(h tlogbe.HookT, payload string) error {
	log.Tracef("ticketvote Hook: %v %v", tlogbe.Hooks[h], payload)

	return nil
}

// Fsck performs a plugin filesystem check.
//
// This function satisfies the Plugin interface.
func (p *ticketVotePlugin) Fsck() error {
	log.Tracef("ticketvote Fsck")

	return nil
}

// Setup performs any plugin setup work that needs to be done.
//
// This function satisfies the Plugin interface.
func (p *ticketVotePlugin) Setup() error {
	log.Tracef("ticketvote Setup")

	// TODO
	// Ensure dcrdata plugin has been registered
	// Build votes cache
	// Build inventory cache

	return nil
}

func TicketVotePluginNew(backend *tlogbe.TlogBackend, settings []backend.PluginSetting) (*ticketVotePlugin, error) {
	var (
		// TODO these should be passed in as plugin settings
		dataDir         string
		id              = &identity.FullIdentity{}
		activeNetParams = &chaincfg.Params{}
		voteDurationMin uint32
		voteDurationMax uint32
	)

	/*
		switch activeNetParams.Name {
		case chaincfg.MainNetParams.Name:
		case chaincfg.TestNet3Params.Name:
		}
	*/

	return &ticketVotePlugin{
		dataDir:         filepath.Join(dataDir, ticketVoteDirname),
		backend:         backend,
		id:              id,
		activeNetParams: activeNetParams,
		voteDurationMin: voteDurationMin,
		voteDurationMax: voteDurationMax,
	}, nil
}
