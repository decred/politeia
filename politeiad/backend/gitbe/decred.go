package gitbe

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/decred/dcrd/chaincfg/chainec"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrutil"
	"github.com/decred/dcrd/wire"
	"github.com/decred/dcrdata/dcrdataapi"
	"github.com/decred/politeia/decredplugin"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/util"
)

// XXX plugins really need to become an interface. Run with this for now.

const (
	decredPluginIdentity = "fullidentity"
)

var (
	decredPluginSettings map[string]string // [key]setting

	// cached values, requires lock
	decredPluginVoteCache = make(map[string]*decredplugin.Vote) // [token]vote
)

func getDecredPlugin(testnet bool) backend.Plugin {
	decredPlugin := backend.Plugin{
		ID:       decredplugin.ID,
		Version:  decredplugin.Version,
		Settings: []backend.PluginSetting{},
	}

	if testnet {
		decredPlugin.Settings = append(decredPlugin.Settings,
			backend.PluginSetting{
				Key:   "dcrdata",
				Value: "https://testnet.dcrdata.org:443/",
			},
		)
	} else {
		decredPlugin.Settings = append(decredPlugin.Settings,
			backend.PluginSetting{
				Key:   "dcrdata",
				Value: "https://dcrdata.org:443/",
			})
	}

	// Initialize settings map
	decredPluginSettings = make(map[string]string)
	for _, v := range decredPlugin.Settings {
		decredPluginSettings[v.Key] = v.Value
	}

	return decredPlugin
}

//SetDecredPluginSetting removes a setting if the value is "" and adds a setting otherwise.
func setDecredPluginSetting(key, value string) {
	if value == "" {
		delete(decredPluginSettings, key)
		return
	}
	decredPluginSettings[key] = value
}

// verifyMessage verifies a message is properly signed.
// Copied from https://github.com/decred/dcrd/blob/0fc55252f912756c23e641839b1001c21442c38a/rpcserver.go#L5605
func (g *gitBackEnd) verifyMessage(address, message, signature string) (bool, error) {
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
	pk, wasCompressed, err := chainec.Secp256k1.RecoverCompact(sig,
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
	a, err := dcrutil.NewAddressSecpPubKey(serializedPK, g.activeNetParams)
	if err != nil {
		// Again mirror Bitcoin Core behavior, which treats error in
		// public key reconstruction as invalid signature.
		return false, nil
	}

	// Return boolean if addresses match.
	return a.EncodeAddress() == address, nil
}

func bestBlock() (*dcrdataapi.BlockDataBasic, error) {
	url := decredPluginSettings["dcrdata"] + "api/block/best"
	log.Debugf("connecting to %v", url)
	r, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	var bdb dcrdataapi.BlockDataBasic
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&bdb); err != nil {
		return nil, err
	}

	return &bdb, nil
}

func block(block uint32) (*dcrdataapi.BlockDataBasic, error) {
	h := strconv.FormatUint(uint64(block), 10)
	url := decredPluginSettings["dcrdata"] + "api/block/" + h
	log.Debugf("connecting to %v", url)
	r, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	var bdb dcrdataapi.BlockDataBasic
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&bdb); err != nil {
		return nil, err
	}

	return &bdb, nil
}

func snapshot(hash string) ([]string, error) {
	url := decredPluginSettings["dcrdata"] + "api/stake/pool/b/" + hash +
		"/full?sort=true"
	log.Debugf("connecting to %v", url)
	r, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	var tickets []string
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&tickets); err != nil {
		return nil, err
	}

	return tickets, nil
}

func largestCommitmentAddress(hash string) (string, error) {
	url := decredPluginSettings["dcrdata"] + "api/tx/" + hash
	log.Debugf("connecting to %v", url)
	r, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer r.Body.Close()

	var ttx dcrdataapi.TrimmedTx
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&ttx); err != nil {
		return "", err
	}

	// Find largest commitment address
	var (
		bestAddr   string
		bestAmount float64
	)
	for _, v := range ttx.Vout {
		if v.ScriptPubKeyDecoded.CommitAmt == nil {
			continue
		}
		if *v.ScriptPubKeyDecoded.CommitAmt > bestAmount {
			if len(v.ScriptPubKeyDecoded.Addresses) == 0 {
				log.Errorf("unexpected addresses length: %v",
					ttx.TxID)
				continue
			}
			bestAddr = v.ScriptPubKeyDecoded.Addresses[0]
			bestAmount = *v.ScriptPubKeyDecoded.CommitAmt
		}
	}

	if bestAddr == "" || bestAmount == 0.0 {
		return "", fmt.Errorf("no best commitment address found: %v",
			ttx.TxID)
	}

	return bestAddr, nil
}

func (g *gitBackEnd) pluginBestBlock() (string, error) {
	bb, err := bestBlock()
	if err != nil {
		return "", err
	}
	return strconv.FormatUint(uint64(bb.Height), 10), nil
}

func (g *gitBackEnd) pluginStartVote(payload string) (string, error) {
	vote, err := decredplugin.DecodeVote([]byte(payload))
	if err != nil {
		return "", fmt.Errorf("DecodeVote %v", err)
	}

	// XXX verify vote bits are sane

	// XXX verify proposal exists

	// XXX verify proposal is in the right state

	token, err := util.ConvertStringToken(vote.Token)
	if err != nil {
		return "", fmt.Errorf("ConvertStringToken %v", err)
	}

	// 1. Get best block
	bb, err := bestBlock()
	if err != nil {
		return "", fmt.Errorf("bestBlock %v", err)
	}
	if bb.Height < uint32(g.activeNetParams.TicketMaturity) {
		return "", fmt.Errorf("invalid height")
	}
	// 2. Subtract TicketMaturity from block height to get into
	// unforkable teritory
	snapshotBlock, err := block(bb.Height -
		uint32(g.activeNetParams.TicketMaturity))
	if err != nil {
		return "", fmt.Errorf("bestBlock %v", err)
	}
	// 3. Get ticket pool snapshot
	snapshot, err := snapshot(snapshotBlock.Hash)
	if err != nil {
		return "", fmt.Errorf("snapshot %v", err)
	}

	duration := uint32(2016) // XXX 1 week on mainnet
	svr := decredplugin.StartVoteReply{
		StartBlockHeight: strconv.FormatUint(uint64(snapshotBlock.Height), 10),
		StartBlockHash:   snapshotBlock.Hash,
		EndHeight:        strconv.FormatUint(uint64(snapshotBlock.Height+duration), 10),
		EligibleTickets:  snapshot,
	}
	svrb, err := decredplugin.EncodeStartVoteReply(svr)
	if err != nil {
		return "", fmt.Errorf("EncodeStartVoteReply: %v", err)
	}

	// XXX store snapshot in metadata
	err = g.UpdateVettedMetadata(token, nil, []backend.MetadataStream{
		{
			ID:      decredplugin.MDStreamVoteBits,
			Payload: payload, // Contains incoming vote request
		},
		{
			ID:      decredplugin.MDStreamVoteSnapshot,
			Payload: string(svrb),
		}})
	if err != nil {
		return "", fmt.Errorf("UpdateVettedMetadata: %v", err)
	}

	log.Infof("Vote started for: %v snapshot %v start %v end %v",
		vote.Token, svr.StartBlockHash, svr.StartBlockHeight,
		svr.EndHeight)

	// return success and encoded answer
	return string(svrb), nil
}

// validateVote validates that vote is signed correctly.
func (g *gitBackEnd) validateVote(token, ticket, votebit, signature string) error {
	// Figure out addresses
	addr, err := largestCommitmentAddress(ticket)
	if err != nil {
		return err
	}

	// Recreate message
	msg := token + ticket + votebit

	// verifyMessage expects base64 encoded sig
	sig, err := hex.DecodeString(signature)
	if err != nil {
		return err
	}

	// Verify message
	validated, err := g.verifyMessage(addr, msg,
		base64.StdEncoding.EncodeToString(sig))
	if err != nil {
		return err
	}

	if !validated {
		return fmt.Errorf("could not verify message")
	}

	return nil
}

type invalidVoteBitError struct {
	err error
}

func (i invalidVoteBitError) Error() string {
	return i.err.Error()
}

// _validateVoteBit iterates over all vote bits and ensure the sent in vote bit
// exists.
func _validateVoteBit(vote decredplugin.Vote, bit uint64) error {
	if len(vote.Options) == 0 {
		return fmt.Errorf("_validateVoteBit vote corrupt")
	}
	if bit == 0 {
		return invalidVoteBitError{
			err: fmt.Errorf("invalid bit 0x%x", bit),
		}
	}
	for _, v := range vote.Options {
		if v.Bits == bit {
			return nil
		}
	}
	return invalidVoteBitError{
		err: fmt.Errorf("bit not found 0x%x", bit),
	}
}

// validateVoteBits ensures that the passed in bit is a valid vote option.
// This function is expensive due to it's filesystem touches and therefore is
// lazily cached. This could stand a rewrite.
func (g *gitBackEnd) validateVoteBit(token, bit string) error {
	b, err := strconv.ParseUint(bit, 16, 64)
	if err != nil {
		return err
	}

	err = g.lock.Lock(LockDuration)
	if err != nil {
		return err
	}
	defer func() {
		err := g.lock.Unlock()
		if err != nil {
			log.Errorf("validateVoteBits unlock error: %v", err)
		}
	}()
	if g.shutdown {
		return backend.ErrShutdown
	}

	vote, ok := decredPluginVoteCache[token]
	if ok {
		return _validateVoteBit(*vote, b)
	}

	// git checkout master
	err = g.gitCheckout(g.unvetted, "master")
	if err != nil {
		return err
	}

	// git pull --ff-only --rebase
	err = g.gitPull(g.unvetted, true)
	if err != nil {
		return err
	}

	// Load md stream
	f, err := os.Open(mdFilename(g.vetted, token,
		decredplugin.MDStreamVoteBits))
	if err != nil {
		return err
	}
	defer f.Close()

	d := json.NewDecoder(f)
	err = d.Decode(&vote)
	if err != nil {
		return err
	}

	decredPluginVoteCache[token] = vote

	return _validateVoteBit(*vote, b)
}

func (g *gitBackEnd) pluginCastVotes(payload string) (string, error) {
	log.Tracef("pluginCastVotes: %v", payload)
	votes, err := decredplugin.DecodeCastVotes([]byte(payload))
	if err != nil {
		return "", fmt.Errorf("DecodeVote %v", err)
	}

	// XXX this should become part of some sort of context
	fiJSON, ok := decredPluginSettings[decredPluginIdentity]
	if !ok {
		return "", fmt.Errorf("full identity not set")
	}
	fi, err := identity.UnmarshalFullIdentity([]byte(fiJSON))
	if err != nil {
		return "", err
	}

	// Go over all votes and verify signature
	type dedupVote struct {
		vote  *decredplugin.CastVote
		index int
	}
	cbr := make([]decredplugin.CastVoteReply, len(votes))
	dedupVotes := make(map[string]dedupVote)
	for k, v := range votes {
		// Check if this is a duplicate vote
		key := v.Token + v.Ticket
		if _, ok := dedupVotes[key]; ok {
			cbr[k].Error = fmt.Sprintf("duplicate vote token %v "+
				"ticket %v", v.Token, v.Ticket)
			continue
		}

		// Ensure that the votebits are correct
		err = g.validateVoteBit(v.Token, v.VoteBit)
		if err != nil {
			if e, ok := err.(invalidVoteBitError); ok {
				cbr[k].Error = e.err.Error()
				continue
			}
			t := time.Now().Unix()
			log.Errorf("pluginCastVotes: validateVoteBit %v %v %v",
				v.Token, t, err)
			cbr[k].Error = fmt.Sprintf("internal error %v", t)
			continue
		}

		cbr[k].ClientSignature = v.Signature
		// Verify that vote is signed correctly
		err = g.validateVote(v.Token, v.Ticket, v.VoteBit, v.Signature)
		if err != nil {
			t := time.Now().Unix()
			log.Errorf("pluginCastVotes: validateVote %v %v %v",
				v.Token, t, err)
			cbr[k].Error = fmt.Sprintf("internal error %v", t)
			continue
		}

		// Sign ClientSignature
		signature := fi.SignMessage([]byte(v.Signature))
		cbr[k].Signature = hex.EncodeToString(signature[:])
		dedupVotes[key] = dedupVote{
			vote:  &votes[k],
			index: k,
		}
	}

	// See if we can short circuit the lock magic
	if len(dedupVotes) == 0 {
		reply, err := decredplugin.EncodeCastVoteReplies(cbr)
		if err != nil {
			return "", fmt.Errorf("Could not encode CastVoteReply"+
				" %v", err)
		}
		return string(reply), nil
	}

	// Store votes
	err = g.lock.Lock(LockDuration)
	if err != nil {
		return "", fmt.Errorf("pluginCastVotes: lock error try again "+
			"later: %v", err)
	}
	defer func() {
		err := g.lock.Unlock()
		if err != nil {
			log.Errorf("pluginCastVotes unlock error: %v", err)
		}
	}()
	if g.shutdown {
		return "", backend.ErrShutdown
	}

	// XXX split out git commands so we can do a stash + stash drop if the operation fails

	// XXX remove panics

	// git checkout master
	err = g.gitCheckout(g.unvetted, "master")
	if err != nil {
		return "", err
	}

	// git pull --ff-only --rebase
	err = g.gitPull(g.unvetted, true)
	if err != nil {
		return "", err
	}

	// Create random temporary branch
	random, err := util.Random(64)
	if err != nil {
		return "", err
	}
	id := hex.EncodeToString(random)
	idTmp := id + "_tmp"
	err = g.gitNewBranch(g.unvetted, idTmp)
	if err != nil {
		return "", err
	}

	// Check for dups
	type file struct {
		fileHandle *os.File
		token      string
		mdFilename string
		content    map[string]struct{} // [token+ticket]
	}
	files := make(map[string]*file)
	for _, v := range dedupVotes {
		var f *file
		if f, ok = files[v.vote.Token]; !ok {
			// Lazily open files and recreate content
			filename := mdFilename(g.unvetted, v.vote.Token,
				decredplugin.MDStreamVotes)
			fh, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE,
				0666)
			if err != nil {
				// XXX find right cbr entry to report error
				panic("x " + err.Error())
				continue
			}
			f = &file{
				fileHandle: fh,
				token:      v.vote.Token,
				mdFilename: strconv.FormatUint(uint64(decredplugin.MDStreamVotes),
					10) + defaultMDFilenameSuffix,
				content: make(map[string]struct{}),
			}

			// Decode file content
			cvs := make([]decredplugin.CastVote, 0, len(dedupVotes))
			d := json.NewDecoder(fh)
			for {
				var cv decredplugin.CastVote
				err = d.Decode(&cv)
				if err != nil {
					if err == io.EOF {
						break
					}

					// XXX find right cbr entry to report error
					panic("zzz " + err.Error())
					continue
				}
				cvs = append(cvs, cv)
			}

			// Recreate keys
			for _, vv := range cvs {
				key := vv.Token + vv.Ticket
				// Sanity
				if _, ok := f.content[key]; ok {
					panic("yy")
					continue
				}
				f.content[key] = struct{}{}
			}

			files[v.vote.Token] = f
		}

		// Check for dups in file content
		key := v.vote.Token + v.vote.Ticket
		if _, ok := f.content[key]; ok {
			index := dedupVotes[key].index
			cbr[index].Error = "ticket already voted on proposal"
			log.Debugf("duplicate vote token %v ticket %v",
				v.vote.Token, v.vote.Ticket)
			continue
		}

		// Append vote
		_, err = f.fileHandle.Seek(0, 2)
		if err != nil {
			// XXX find right cbr entry to report error
			panic("y " + err.Error())
			continue
		}
		e := json.NewEncoder(f.fileHandle)
		err = e.Encode(*v.vote)
		if err != nil {
			// XXX find right cbr entry to report error
			panic("z " + err.Error())
			continue
		}
	}

	// Unwind all opens
	for _, v := range files {
		if v.fileHandle == nil {
			continue
		}
		v.fileHandle.Close()

		// Add file to repo
		err = g.gitAdd(g.unvetted, filepath.Join(v.token, v.mdFilename))
		if err != nil {
			// XXX find right cbr entry to report error
			panic("zzz " + err.Error())
			continue
		}
	}

	// If there are no changes DO NOT update the record and reply with no
	// changes.
	if g.gitHasChanges(g.unvetted) {
		// Commit change
		err = g.gitCommit(g.unvetted, "Update record metadata via plugin")
		if err != nil {
			panic("111 " + err.Error())
			//return err
		}

		// create and rebase PR
		err = g.rebasePR(idTmp)
		if err != nil {
			panic("222 " + err.Error())
			//return "", fmt.Errorf("Could not rebase %v", err)
		}
	}

	reply, err := decredplugin.EncodeCastVoteReplies(cbr)
	if err != nil {
		return "", fmt.Errorf("Could not encode CastVoteReply %v", err)
	}

	return string(reply), nil
}
