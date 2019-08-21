// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package gitbe

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/decred/politeia/cmsplugin"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/util"
)

// XXX plugins really need to become an interface. Run with this for now.

const (
	cmsPluginIdentity  = "fullidentity"
	cmsPluginJournals  = "journals"
	cmsPluginInventory = "inventory"
)

// FlushRecord is a structure that is stored on disk when a journal has been
// flushed.
type FlushRecord struct {
	Version   string `json:"version"`   // Version
	Timestamp string `json:"timestamp"` // Timestamp
}

type CastVoteJournal struct {
	CastVote cmsplugin.CastVote `json:"castvote"` // Client side vote
	Receipt  string             `json:"receipt"`  // Signature of CastVote.Signature
}

func encodeCastVoteJournal(cvj CastVoteJournal) ([]byte, error) {
	b, err := json.Marshal(cvj)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func decodeCastVoteJournal(payload []byte) (*CastVoteJournal, error) {
	var cvj CastVoteJournal

	err := json.Unmarshal(payload, &cvj)
	if err != nil {
		return nil, err
	}

	return &cvj, nil
}

var (
	cmsPluginSettings map[string]string             // [key]setting
	cmsPluginHooks    map[string]func(string) error // [key]func(token) error

	// Cached values, requires lock. These caches are lazy loaded.
	// XXX why is this a pointer? Convert if possible after investigating
	cmsPluginVoteCache         = make(map[string]*cmsplugin.StartVote)     // [token]startvote
	cmsPluginVoteSnapshotCache = make(map[string]cmsplugin.StartVoteReply) // [token]StartVoteReply

	// Plugin specific data that CANNOT be treated as metadata
	pluginDataDir = filepath.Join("plugins", "cms")

	// Cached values, requires lock. These caches are built on startup.
	cmsPluginVotesCache = make(map[string]map[string]struct{}) // [token][ticket]struct{}
)

// init is used to pregenerate the JSON journal actions.
func init() {
	var err error

	journalAdd, err = json.Marshal(JournalAction{
		Version: journalVersion,
		Action:  journalActionAdd,
	})
	if err != nil {
		panic(err.Error())
	}
	journalDel, err = json.Marshal(JournalAction{
		Version: journalVersion,
		Action:  journalActionDel,
	})
	if err != nil {
		panic(err.Error())
	}
	journalAddLike, err = json.Marshal(JournalAction{
		Version: journalVersion,
		Action:  journalActionAddLike,
	})
	if err != nil {
		panic(err.Error())
	}
}

func getCMSPlugin(testnet bool) backend.Plugin {
	cmsPlugin := backend.Plugin{
		ID:       cmsplugin.ID,
		Version:  cmsplugin.Version,
		Settings: []backend.PluginSetting{},
	}

	if testnet {
		cmsPlugin.Settings = append(cmsPlugin.Settings,
			backend.PluginSetting{
				Key:   "dcrdata",
				Value: "https://testnet.dcrdata.org:443/",
			},
		)
	} else {
		cmsPlugin.Settings = append(cmsPlugin.Settings,
			backend.PluginSetting{
				Key:   "dcrdata",
				Value: "https://explorer.dcrdata.org:443/",
			})
	}

	// This setting is used to tell politeiad how to retrieve the
	// decred plugin data that is required to build the external
	// politeiad cache.
	cmsPlugin.Settings = append(cmsPlugin.Settings,
		backend.PluginSetting{
			Key:   cmsPluginInventory,
			Value: cmsplugin.CmdInventory,
		})

	// Initialize hooks
	cmsPluginHooks = make(map[string]func(string) error)

	// Initialize settings map
	cmsPluginSettings = make(map[string]string)
	for _, v := range cmsPlugin.Settings {
		cmsPluginSettings[v.Key] = v.Value
	}
	return cmsPlugin
}

// initCmsPluginJournals is called externally to run initial procedures
// such as replaying journals
func (g *gitBackEnd) initCmsPluginJournals() error {
	log.Infof("initCmsPluginJournals")

	// check if backend journal is initialized
	if g.journal == nil {
		return fmt.Errorf("initCmsPlugin backend journal isn't initialized")
	}

	err := g.replayAllJournals()
	if err != nil {
		log.Infof("initDecredPlugin replay all journals %v", err)
	}
	return nil
}

//SetCmsPluginSetting removes a setting if the value is "" and adds a setting otherwise.
func setCmsPluginSetting(key, value string) {
	if value == "" {
		delete(cmsPluginSettings, key)
		return
	}

	cmsPluginSettings[key] = value
}

func setCmsPluginHook(name string, f func(string) error) {
	cmsPluginHooks[name] = f
}

func (g *gitBackEnd) propExists(repo, token string) bool {
	_, err := os.Stat(pijoin(repo, token))
	return err == nil
}

func dccSnapshot(hash string) ([]string, error) {
	/*
		REMOVE TICKET SNAPSHOT AND REPLACE WITH USER WEIGHT SNAPSHOT

		url := cmsPluginSettings["dcrdata"] + "api/stake/pool/b/" + hash +
			"/full?sort=true"
		log.Debugf("connecting to %v", url)
		r, err := http.Get(url)
		if err != nil {
			return nil, err
		}
		defer r.Body.Close()

		if r.StatusCode != http.StatusOK {
			body, err := ioutil.ReadAll(r.Body)
			if err != nil {
				return nil, fmt.Errorf("dcrdata error: %v %v %v",
					r.StatusCode, url, err)
			}
			return nil, fmt.Errorf("dcrdata error: %v %v %s",
				r.StatusCode, url, body)
		}
	*/
	var tickets []string
	return tickets, nil
}

// pluginAuthorizeVote updates the vetted repo with vote authorization
// metadata from the proposal author.
func (g *gitBackEnd) pluginAuthorizeVote(payload string) (string, error) {
	log.Tracef("pluginAuthorizeVote")

	// Decode authorize vote
	authorize, err := cmsplugin.DecodeAuthorizeVote([]byte(payload))
	if err != nil {
		return "", fmt.Errorf("DecodeAuthorizeVote %v", err)
	}
	token := authorize.Token

	// Verify proposal exists
	if !g.propExists(g.vetted, token) {
		return "", fmt.Errorf("unknown proposal: %v", token)
	}

	// Get identity
	// XXX this should become part of some sort of context
	fiJSON, ok := decredPluginSettings[decredPluginIdentity]
	if !ok {
		return "", fmt.Errorf("full identity not set")
	}
	fi, err := identity.UnmarshalFullIdentity([]byte(fiJSON))
	if err != nil {
		return "", fmt.Errorf("UnmarshalFullIdentity: %v", err)
	}

	// Sign signature
	r := fi.SignMessage([]byte(authorize.Signature))
	receipt := hex.EncodeToString(r[:])

	// Create on disk structure
	t := time.Now().Unix()
	av := cmsplugin.AuthorizeVote{
		Version:   cmsplugin.VersionAuthorizeVote,
		Receipt:   receipt,
		Timestamp: t,
		Action:    authorize.Action,
		Token:     token,
		Signature: authorize.Signature,
		PublicKey: authorize.PublicKey,
	}
	avb, err := cmsplugin.EncodeAuthorizeVote(av)
	if err != nil {
		return "", fmt.Errorf("EncodeAuthorizeVote: %v", err)
	}
	tokenb, err := util.ConvertStringToken(token)
	if err != nil {
		return "", fmt.Errorf("ConvertStringToken %v", err)
	}

	// Verify proposal state
	g.Lock()
	defer g.Unlock()
	if g.shutdown {
		return "", backend.ErrShutdown
	}

	_, err = os.Stat(pijoin(joinLatest(g.vetted, token),
		fmt.Sprintf("%02v%v", cmsplugin.MDStreamVoteBits,
			defaultMDFilenameSuffix)))
	if err == nil {
		// Vote has already started. This should not happen.
		return "", fmt.Errorf("proposal vote already started: %v",
			token)
	}

	// Update metadata
	err = g._updateVettedMetadata(tokenb, nil, []backend.MetadataStream{
		{
			ID:      cmsplugin.MDStreamAuthorizeVote,
			Payload: string(avb),
		},
	})
	if err != nil {
		return "", fmt.Errorf("_updateVettedMetadata: %v", err)
	}

	// Prepare reply
	version, err := getLatest(pijoin(g.vetted, token))
	if err != nil {
		return "", fmt.Errorf("getLatest: %v", err)
	}
	avr := cmsplugin.AuthorizeVoteReply{
		Action:        av.Action,
		RecordVersion: version,
		Receipt:       av.Receipt,
		Timestamp:     av.Timestamp,
	}
	avrb, err := cmsplugin.EncodeAuthorizeVoteReply(avr)
	if err != nil {
		return "", err
	}

	log.Infof("Vote authorized for %v", token)

	return string(avrb), nil
}

func (g *gitBackEnd) pluginStartVote(payload string) (string, error) {
	vote, err := cmsplugin.DecodeStartVote([]byte(payload))
	if err != nil {
		return "", fmt.Errorf("DecodeStartVote %v", err)
	}

	// Verify vote bits are somewhat sane
	for _, v := range vote.Vote.Options {
		err = _validateVoteBit(vote.Vote, v.Bits)
		if err != nil {
			return "", fmt.Errorf("invalid vote bits: %v", err)
		}
	}

	// Verify proposal exists
	tokenB, err := util.ConvertStringToken(vote.Vote.Token)
	if err != nil {
		return "", fmt.Errorf("ConvertStringToken %v", err)
	}
	token := vote.Vote.Token

	if !g.propExists(g.vetted, token) {
		return "", fmt.Errorf("unknown proposal: %v", token)
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
	if len(snapshot) == 0 {
		return "", fmt.Errorf("no eligible voters for %v", token)
	}

	// Make sure vote duration is within min/max range
	// XXX calculate this value for testnet instead of using hard coded values.
	if vote.Vote.Duration < cmsplugin.VoteDurationMin ||
		vote.Vote.Duration > cmsplugin.VoteDurationMax {
		// XXX return a user error instead of an internal error
		return "", fmt.Errorf("invalid duration: %v (%v - %v)",
			vote.Vote.Duration, cmsplugin.VoteDurationMin,
			cmsplugin.VoteDurationMax)
	}

	svr := cmsplugin.StartVoteReply{
		Version: cmsplugin.VersionStartVoteReply,
		StartBlockHeight: strconv.FormatUint(uint64(snapshotBlock.Height),
			10),
		StartBlockHash: snapshotBlock.Hash,
		// On EndHeight: we start in the past, add maturity to correct
		EndHeight: strconv.FormatUint(uint64(snapshotBlock.Height+
			vote.Vote.Duration+
			uint32(g.activeNetParams.TicketMaturity)), 10),
		EligibleTickets: snapshot,
	}
	svrb, err := cmsplugin.EncodeStartVoteReply(svr)
	if err != nil {
		return "", fmt.Errorf("EncodeStartVoteReply: %v", err)
	}

	// Add version to on disk structure
	vote.Version = cmsplugin.VersionStartVote
	voteb, err := cmsplugin.EncodeStartVote(*vote)
	if err != nil {
		return "", fmt.Errorf("EncodeStartVote: %v", err)
	}

	// Verify proposal state
	g.Lock()
	defer g.Unlock()
	if g.shutdown {
		// Make sure we are not shutting down
		return "", backend.ErrShutdown
	}

	_, err1 := os.Stat(pijoin(joinLatest(g.vetted, token),
		fmt.Sprintf("%02v%v", cmsplugin.MDStreamAuthorizeVote,
			defaultMDFilenameSuffix)))
	_, err2 := os.Stat(pijoin(joinLatest(g.vetted, token),
		fmt.Sprintf("%02v%v", cmsplugin.MDStreamVoteBits,
			defaultMDFilenameSuffix)))
	_, err3 := os.Stat(pijoin(joinLatest(g.vetted, token),
		fmt.Sprintf("%02v%v", cmsplugin.MDStreamVoteSnapshot,
			defaultMDFilenameSuffix)))

	if err1 != nil {
		// Authorize vote md is not present
		return "", fmt.Errorf("no authorize vote metadata: %v",
			token)
	} else if err2 != nil && err3 != nil {
		// Vote has not started, continue
	} else if err2 == nil && err3 == nil {
		// Vote has started
		return "", fmt.Errorf("proposal vote already started: %v",
			token)
	} else {
		// This is bad, both files should exist or not exist
		return "", fmt.Errorf("proposal is unknown vote state: %v",
			token)
	}

	// Ensure vote authorization has not been revoked
	b, err := ioutil.ReadFile(pijoin(joinLatest(g.vetted, token),
		fmt.Sprintf("%02v%v", cmsplugin.MDStreamAuthorizeVote,
			defaultMDFilenameSuffix)))
	if err != nil {
		return "", fmt.Errorf("readfile authorizevote: %v", err)
	}
	av, err := cmsplugin.DecodeAuthorizeVote(b)
	if err != nil {
		return "", fmt.Errorf("DecodeAuthorizeVote: %v", err)
	}
	if av.Action == cmsplugin.AuthVoteActionRevoke {
		return "", fmt.Errorf("vote authorization revoked")
	}

	// Store snapshot in metadata
	err = g._updateVettedMetadata(tokenB, nil, []backend.MetadataStream{
		{
			ID:      cmsplugin.MDStreamVoteBits,
			Payload: string(voteb),
		},
		{
			ID:      cmsplugin.MDStreamVoteSnapshot,
			Payload: string(svrb),
		}})
	if err != nil {
		return "", fmt.Errorf("_updateVettedMetadata: %v", err)
	}

	// Add vote snapshot to in-memory cache
	cmsPluginVoteSnapshotCache[token] = svr

	log.Infof("Vote started for: %v snapshot %v start %v end %v",
		token, svr.StartBlockHash, svr.StartBlockHeight,
		svr.EndHeight)

	// return success and encoded answer
	return string(svrb), nil
}

// validateVoteByAddress validates that vote, as specified by the commitment
// address with largest amount, is signed correctly.
func (g *gitBackEnd) validateVoteByAddress(token, ticket, addr, votebit, signature string) error {
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

// validateVoteBits ensures that the passed in bit is a valid vote option.
// This function is expensive due to it's filesystem touches and therefore is
// lazily cached. This could stand a rewrite.
func (g *gitBackEnd) validateVoteBit(token, bit string) error {
	b, err := strconv.ParseUint(bit, 16, 64)
	if err != nil {
		return err
	}

	g.Lock()
	defer g.Unlock()
	if g.shutdown {
		return backend.ErrShutdown
	}

	sv, ok := decredPluginVoteCache[token]
	if ok {
		return _validateVoteBit(sv.Vote, b)
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
		cmsplugin.MDStreamVoteBits))
	if err != nil {
		return err
	}
	defer f.Close()

	d := json.NewDecoder(f)
	err = d.Decode(&sv)
	if err != nil {
		return err
	}

	decredPluginVoteCache[token] = sv

	return _validateVoteBit(sv.Vote, b)
}

// replayBallot replays voting journalfor given proposal.
//
// Functions must be called WITH the lock held.
func (g *gitBackEnd) replayBallot(token string) error {
	// Verify proposal exists, we can run this lockless
	if !g.propExists(g.vetted, token) {
		return nil
	}

	// Do some cheap things before expensive calls
	bfilename := pijoin(g.journals, token,
		defaultBallotFilename)

	// Replay journal
	err := g.journal.Open(bfilename)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("journal.Open: %v", err)
		}
		return nil
	}
	defer func() {
		err = g.journal.Close(bfilename)
		if err != nil {
			log.Errorf("journal.Close: %v", err)
		}
	}()

	for {
		err = g.journal.Replay(bfilename, func(s string) error {
			ss := bytes.NewReader([]byte(s))
			d := json.NewDecoder(ss)

			// Decode action
			var action JournalAction
			err = d.Decode(&action)
			if err != nil {
				return fmt.Errorf("journal action: %v", err)
			}

			switch action.Action {
			case journalActionAdd:
				var cvj CastVoteJournal
				err = d.Decode(&cvj)
				if err != nil {
					return fmt.Errorf("journal add: %v",
						err)
				}

				token := cvj.CastVote.Token
				ticket := cvj.CastVote.Ticket
				// See if the prop already exists
				if _, ok := decredPluginVotesCache[token]; !ok {
					// Create map to track tickets
					decredPluginVotesCache[token] = make(map[string]struct{})
				}
				// See if we have a duplicate vote
				if _, ok := decredPluginVotesCache[token][ticket]; ok {
					log.Errorf("duplicate cast vote %v %v",
						token, ticket)
				}
				// All good, record vote in cache
				decredPluginVotesCache[token][ticket] = struct{}{}

			default:
				return fmt.Errorf("invalid action: %v",
					action.Action)
			}
			return nil
		})
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}
	}

	return nil
}

// loadVoteSnapshotCache loads the StartVoteReply from disk for the provided
// token and adds it to the decredPluginVoteSnapshotCache.
//
// This function must be called WITH the lock held.
func (g *gitBackEnd) loadVoteSnapshotCache(token string) (*cmsplugin.StartVoteReply, error) {
	// git checkout master
	err := g.gitCheckout(g.unvetted, "master")
	if err != nil {
		return nil, err
	}

	// git pull --ff-only --rebase
	err = g.gitPull(g.unvetted, true)
	if err != nil {
		return nil, err
	}

	// Load the vote snapshot from disk
	f, err := os.Open(mdFilename(g.vetted, token,
		cmsplugin.MDStreamVoteSnapshot))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var svr cmsplugin.StartVoteReply
	d := json.NewDecoder(f)
	err = d.Decode(&svr)
	if err != nil {
		return nil, err
	}

	decredPluginVoteSnapshotCache[token] = svr

	return &svr, nil
}

// voteEndHeight returns the voting period end height for the provided token.
func (g *gitBackEnd) voteEndHeight(token string) (uint32, error) {
	g.Lock()
	defer g.Unlock()
	if g.shutdown {
		return 0, backend.ErrShutdown
	}

	svr, ok := decredPluginVoteSnapshotCache[token]
	if !ok {
		s, err := g.loadVoteSnapshotCache(token)
		if err != nil {
			return 0, err
		}
		svr = *s
	}

	endHeight, err := strconv.ParseUint(svr.EndHeight, 10, 64)
	if err != nil {
		return 0, err
	}

	return uint32(endHeight), nil
}

// writeVote writes the provided vote to the provided journal file path, if the
// vote does not already exist. Once successfully written to the journal, the
// vote is added to the cast vote memory cache.
//
// This function must be called WITHOUT the lock held.
func (g *gitBackEnd) writeVote(v cmsplugin.CastVote, receipt, journalPath string) error {
	g.Lock()
	defer g.Unlock()

	// Ensure ticket is eligible to vote.
	// This cache should have already been loaded when the
	// vote end height was validated, but lets be sure.
	svr, ok := decredPluginVoteSnapshotCache[v.Token]
	if !ok {
		s, err := g.loadVoteSnapshotCache(v.Token)
		if err != nil {
			return fmt.Errorf("loadVoteSnapshotCache: %v",
				err)
		}
		svr = *s
	}
	var found bool
	for _, t := range svr.EligibleTickets {
		if t == v.Ticket {
			found = true
			break
		}
	}
	if !found {
		return errIneligibleTicket
	}

	// Ensure vote is not a duplicate
	_, ok = decredPluginVotesCache[v.Token]
	if !ok {
		decredPluginVotesCache[v.Token] = make(map[string]struct{})
	}

	_, ok = decredPluginVotesCache[v.Token][v.Ticket]
	if ok {
		return errDuplicateVote
	}

	// Create journal entry
	cvj := CastVoteJournal{
		CastVote: v,
		Receipt:  receipt,
	}
	blob, err := encodeCastVoteJournal(cvj)
	if err != nil {
		return fmt.Errorf("encodeCastVoteJournal: %v",
			err)
	}

	// Write vote to journal
	err = g.journal.Journal(journalPath, string(journalAdd)+
		string(blob))
	if err != nil {
		return fmt.Errorf("could not journal vote %v: %v %v",
			v.Token, v.Ticket, err)
	}

	// Add vote to memory cache
	decredPluginVotesCache[v.Token][v.Ticket] = struct{}{}

	return nil
}

func (g *gitBackEnd) pluginBallot(payload string) (string, error) {
	log.Tracef("pluginBallot")

	// Check if journals were replayed
	if !journalsReplayed {
		return "", backend.ErrJournalsNotReplayed
	}

	// Decode ballot
	ballot, err := cmsplugin.DecodeBallot([]byte(payload))
	if err != nil {
		return "", fmt.Errorf("DecodeBallot: %v", err)
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

	// Get best block
	bb, err := bestBlock()
	if err != nil {
		return "", fmt.Errorf("bestBlock %v", err)
	}

	// Obtain all largest commitment addresses. Assume everything was sent
	// in correct.
	tickets := make([]string, 0, len(ballot.Votes))
	for _, v := range ballot.Votes {
		tickets = append(tickets, v.Ticket)
	}
	ticketAddresses, err := largestCommitmentAddresses(tickets)
	if err != nil {
		return "", err
	}

	br := cmsplugin.BallotReply{
		Receipts: make([]cmsplugin.CastVoteReply, len(ballot.Votes)),
	}
	for k, v := range ballot.Votes {
		// Verify proposal exists, we can run this lockless
		if !g.propExists(g.vetted, v.Token) {
			log.Errorf("pluginBallot: proposal not found: %v",
				v.Token)
			br.Receipts[k].Error = "proposal not found: " + v.Token
			continue
		}

		// Ensure that the votebits are correct
		err = g.validateVoteBit(v.Token, v.VoteBit)
		if err != nil {
			if e, ok := err.(invalidVoteBitError); ok {
				br.Receipts[k].Error = e.err.Error()
				continue
			}
			t := time.Now().Unix()
			log.Errorf("pluginBallot: validateVoteBit %v %v %v %v",
				v.Ticket, v.Token, t, err)
			br.Receipts[k].Error = fmt.Sprintf("internal error %v",
				t)
			continue
		}

		// Verify voting period has not ended
		endHeight, err := g.voteEndHeight(v.Token)
		if err != nil {
			t := time.Now().Unix()
			log.Errorf("pluginBallot: voteEndHeight %v %v %v %v",
				v.Ticket, v.Token, t, err)
			br.Receipts[k].Error = fmt.Sprintf("internal error %v",
				t)
			continue
		}
		if bb.Height >= endHeight {
			br.Receipts[k].Error = "vote has ended: " + v.Token
			continue
		}

		// See if there was an error for this address
		if ticketAddresses[k].err != nil {
			t := time.Now().Unix()
			log.Errorf("pluginBallot: ticketAddresses %v %v %v %v",
				v.Ticket, v.Token, t, err)
			br.Receipts[k].Error = fmt.Sprintf("internal error %v",
				t)
			continue

		}

		// Verify that vote is signed correctly
		err = g.validateVoteByAddress(v.Token, v.Ticket,
			ticketAddresses[k].bestAddr, v.VoteBit, v.Signature)
		if err != nil {
			t := time.Now().Unix()
			log.Errorf("pluginBallot: validateVote %v %v %v %v",
				v.Ticket, v.Token, t, err)
			br.Receipts[k].Error = fmt.Sprintf("internal error %v",
				t)
			continue
		}

		// Ensure journal directory exists
		dir := pijoin(g.journals, v.Token)
		bfilename := pijoin(dir, defaultBallotFilename)
		err = os.MkdirAll(dir, 0774)
		if err != nil {
			// Should not fail, so return failure to alert people
			return "", fmt.Errorf("make journal dir: %v", err)
		}

		// Sign signature
		r := fi.SignMessage([]byte(v.Signature))
		receipt := hex.EncodeToString(r[:])

		// Write vote to journal
		err = g.writeVote(v, receipt, bfilename)
		if err != nil {
			switch err {
			case errDuplicateVote:
				br.Receipts[k].Error = "duplicate vote: " + v.Token
				continue
			case errIneligibleTicket:
				br.Receipts[k].Error = "ineligible ticket: " + v.Token
				continue
			default:
				// Should not fail, so return failure to alert people
				return "", fmt.Errorf("write vote: %v", err)
			}
		}

		// Update reply
		br.Receipts[k].ClientSignature = v.Signature
		br.Receipts[k].Signature = receipt

		// Mark comment journal dirty
		flushFilename := pijoin(g.journals, v.Token,
			defaultBallotFlushed)
		_ = os.Remove(flushFilename)
	}

	// Encode reply
	brb, err := cmsplugin.EncodeBallotReply(br)
	if err != nil {
		return "", fmt.Errorf("EncodeBallotReply: %v", err)
	}

	// return success and encoded answer
	return string(brb), nil
}

// tallyVotes replays the ballot journal for a proposal and tallies the votes.
//
// Function must be called WITH the lock held.
func (g *gitBackEnd) tallyVotes(token string) ([]cmsplugin.CastVote, error) {
	// Do some cheap things before expensive calls
	bfilename := pijoin(g.journals, token, defaultBallotFilename)

	// Replay journal
	err := g.journal.Open(bfilename)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("journal.Open: %v", err)
		}
		return []cmsplugin.CastVote{}, nil
	}
	defer func() {
		err = g.journal.Close(bfilename)
		if err != nil {
			log.Errorf("journal.Close: %v", err)
		}
	}()

	cv := make([]cmsplugin.CastVote, 0, 41000)
	for {
		err = g.journal.Replay(bfilename, func(s string) error {
			ss := bytes.NewReader([]byte(s))
			d := json.NewDecoder(ss)

			// Decode action
			var action JournalAction
			err = d.Decode(&action)
			if err != nil {
				return fmt.Errorf("journal action: %v", err)
			}

			switch action.Action {
			case journalActionAdd:
				var cvj CastVoteJournal
				err = d.Decode(&cvj)
				if err != nil {
					return fmt.Errorf("journal add: %v",
						err)
				}
				cv = append(cv, cvj.CastVote)

			default:
				return fmt.Errorf("invalid action: %v",
					action.Action)
			}
			return nil
		})
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
	}

	return cv, nil
}

// pluginProposalVotes tallies all votes for a proposal. We can run the tally
// unlocked and just replay the journal. If the replay becomes an issue we
// could cache it. The Vote that is returned does have to be locked.
func (g *gitBackEnd) pluginProposalVotes(payload string) (string, error) {
	log.Tracef("pluginProposalVotes: %v", payload)

	vote, err := cmsplugin.DecodeVoteResults([]byte(payload))
	if err != nil {
		return "", fmt.Errorf("DecodeVoteResults %v", err)
	}

	// Verify proposal exists, we can run this lockless
	if !g.propExists(g.vetted, vote.Token) {
		return "", fmt.Errorf("proposal not found: %v", vote.Token)
	}

	// This portion is must run locked

	g.Lock()
	defer g.Unlock()

	if g.shutdown {
		return "", backend.ErrShutdown
	}

	// Prepare reply
	var vrr cmsplugin.VoteResultsReply

	// Fill out cast votes
	vrr.CastVotes, err = g.tallyVotes(vote.Token)
	if err != nil {
		return "", fmt.Errorf("Could not tally votes: %v", err)
	}

	// git checkout master
	err = g.gitCheckout(g.vetted, "master")
	if err != nil {
		return "", err
	}

	// Prepare reply
	var (
		dd *json.Decoder
		ff *os.File
	)
	// Fill out vote
	filename := mdFilename(g.vetted, vote.Token,
		cmsplugin.MDStreamVoteBits)
	ff, err = os.Open(filename)
	if err != nil {
		if os.IsNotExist(err) {
			goto nodata
		}
		return "", err
	}
	defer ff.Close()
	dd = json.NewDecoder(ff)

	err = dd.Decode(&vrr.StartVote)
	if err != nil {
		if err == io.EOF {
			goto nodata
		}
		return "", err
	}

nodata:
	reply, err := cmsplugin.EncodeVoteResultsReply(vrr)
	if err != nil {
		return "", fmt.Errorf("Could not encode VoteResultsReply: %v",
			err)
	}

	return string(reply), nil
}

// pluginInventory returns the decred plugin inventory for all proposals.  The
// inventory consists of comments, like comments, vote authorizations, vote
// details, and cast votes.
func (g *gitBackEnd) pluginInventory() (string, error) {
	log.Tracef("pluginInventory")

	g.Lock()
	defer g.Unlock()

	// Ensure journal has been replayed
	if !journalsReplayed {
		return "", backend.ErrJournalsNotReplayed
	}

	// Walk in-memory comments cache and compile all comments
	var count int
	for _, v := range decredPluginCommentsCache {
		count += len(v)
	}
	comments := make([]cmsplugin.Comment, 0, count)
	for _, v := range decredPluginCommentsCache {
		for _, c := range v {
			comments = append(comments, c)
		}
	}

	// Walk in-memory comment likes cache and compile all
	// comment likes
	count = 0
	for _, v := range decredPluginCommentsLikesCache {
		count += len(v)
	}
	likes := make([]cmsplugin.LikeComment, 0, count)
	for _, v := range decredPluginCommentsLikesCache {
		likes = append(likes, v...)
	}

	// Walk vetted repo and compile all file paths
	paths := make([]string, 0, 2048) // PNOOMA
	err := filepath.Walk(g.vetted,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			paths = append(paths, path)
			return nil
		})
	if err != nil {
		return "", fmt.Errorf("walk vetted: %v", err)
	}

	// Filter out the file paths for authorize vote metadata and
	// start vote metadata
	avPaths := make([]string, 0, len(paths))
	svPaths := make([]string, 0, len(paths))
	avFile := fmt.Sprintf("%02v%v", cmsplugin.MDStreamAuthorizeVote,
		defaultMDFilenameSuffix)
	svFile := fmt.Sprintf("%02v%v", cmsplugin.MDStreamVoteBits,
		defaultMDFilenameSuffix)
	for _, v := range paths {
		switch filepath.Base(v) {
		case avFile:
			avPaths = append(avPaths, v)
		case svFile:
			svPaths = append(svPaths, v)
		}
	}

	// Compile all vote authorizations. We return the authorize
	// vote data for all versions of a record, not just the latest
	// version.
	av := make([]cmsplugin.AuthorizeVote, 0, len(avPaths))
	avr := make([]cmsplugin.AuthorizeVoteReply, 0, len(avPaths))
	for _, v := range avPaths {
		// Read in authorize vote file into memory
		b, err := ioutil.ReadFile(v)
		if err != nil {
			return "", fmt.Errorf("ReadFile: %v", err)
		}

		// Decode authorize vote
		a, err := cmsplugin.DecodeAuthorizeVote(b)
		if err != nil {
			return "", fmt.Errorf("DecodeAuthorizeVote: %v", err)
		}
		av = append(av, *a)

		// Parse record version out of file path
		versionDir := filepath.Dir(v)
		version := filepath.Base(versionDir)

		// Create authorize vote reply
		avr = append(avr, cmsplugin.AuthorizeVoteReply{
			Action:        a.Action,
			RecordVersion: version,
			Receipt:       a.Receipt,
			Timestamp:     a.Timestamp,
		})
	}

	// Compile the start vote tuples. The in-memory caches that
	// contain the vote bits and the vote snapshots are lazy
	// loaded so we have to read vote metadata directly from disk.
	svt := make([]cmsplugin.StartVoteTuple, 0, len(decredPluginVoteCache))
	for _, v := range svPaths {
		// Read vote bits file into memory
		b, err := ioutil.ReadFile(v)
		if err != nil {
			return "", fmt.Errorf("ReadFile %v: %v", v, err)
		}

		// Decode vote bits
		sv, err := cmsplugin.DecodeStartVote(b)
		if err != nil {
			return "", fmt.Errorf("DecodeStartVote: %v", err)
		}

		// Read vote snapshot file into memory
		dir := filepath.Dir(v)
		filename := fmt.Sprintf("%02v%v", cmsplugin.MDStreamVoteSnapshot,
			defaultMDFilenameSuffix)
		path := filepath.Join(dir, filename)
		b, err = ioutil.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("ReadFile %v: %v", path, err)
		}

		// Decode vote snapshot
		svr, err := cmsplugin.DecodeStartVoteReply(b)
		if err != nil {
			return "", fmt.Errorf("DecodeStartVoteReply: %v", err)
		}

		// Create start vote tuple
		svt = append(svt, cmsplugin.StartVoteTuple{
			StartVote:      *sv,
			StartVoteReply: *svr,
		})
	}

	// Compile cast votes. The in-memory votes cache does not
	// store the full cast vote struct so we need to replay the
	// vote journals.

	// Walk journals directory and tally votes for all ballot
	// journals that are found.
	cv := make([][]cmsplugin.CastVote, 0, len(svt))
	err = filepath.Walk(g.journals,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if info.Name() == defaultBallotFilename {
				token := filepath.Base(filepath.Dir(path))
				votes, err := g.tallyVotes(token)
				if err != nil {
					return fmt.Errorf("tallyVotes %v: %v", token, err)
				}

				cv = append(cv, votes)
			}

			return nil
		})
	if err != nil {
		return "", fmt.Errorf("walk journals: %v", err)
	}

	// Combine votes into a single slice
	count = 0
	for _, v := range cv {
		count += len(v)
	}
	votes := make([]cmsplugin.CastVote, 0, count)
	for _, v := range cv {
		votes = append(votes, v...)
	}

	// Prepare reply
	ir := cmsplugin.InventoryReply{
		Comments:             comments,
		LikeComments:         likes,
		AuthorizeVotes:       av,
		AuthorizeVoteReplies: avr,
		StartVoteTuples:      svt,
		CastVotes:            votes,
	}

	payload, err := cmsplugin.EncodeInventoryReply(ir)
	if err != nil {
		return "", fmt.Errorf("EncodeInventoryReply: %v", err)
	}

	return string(payload), nil
}

// pluginLoadVoteResults is a pass through function. CmdLoadVoteResults does
// not require any work to be performed in gitBackEnd.
func (g *gitBackEnd) pluginLoadVoteResults() (string, error) {
	r := cmsplugin.LoadVoteResultsReply{}
	reply, err := cmsplugin.EncodeLoadVoteResultsReply(r)
	if err != nil {
		return "", err
	}
	return string(reply), nil
}
