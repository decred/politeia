// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package gitbe

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/decred/politeia/cmsplugin"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/util"
)

const (
	cmsPluginIdentity    = "cmsfullidentity"
	cmsPluginJournals    = "cmssjournals"
	cmsPluginEnableCache = "enablecache"

	defaultCMSBallotFilename = "cms.ballot.journal"
	defaultCMSBallotFlushed  = "cms.ballot.flushed"
)

type CastDCCVoteJournal struct {
	CastVote cmsplugin.CastVote `json:"castvote"` // Client side vote
	Receipt  string             `json:"receipt"`  // Signature of CastVote.Signature
}

func encodeCastDCCVoteJournal(cvj CastDCCVoteJournal) ([]byte, error) {
	b, err := json.Marshal(cvj)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func decodeCastDCCVoteJournal(payload []byte) (*CastDCCVoteJournal, error) {
	var cvj CastDCCVoteJournal

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
	cmsPluginVoteCache         = make(map[string]cmsplugin.StartVote)      // [token]startvote
	cmsPluginVoteSnapshotCache = make(map[string]cmsplugin.StartVoteReply) // [token]StartVoteReply

	// Plugin specific data that CANNOT be treated as metadata
	cmsDataDir = filepath.Join("plugins", "cms")

	// Cached values, requires lock. These caches are built on startup.
	cmsPluginVotesCache = make(map[string]map[string]struct{}) // [token][ticket]struct{}

	// errIneligibleUserID is emitted when a vote is cast using an
	// ineligible userid.
	errIneligibleUserID = errors.New("ineligible userid")
)

func getCMSPlugin(testnet bool) backend.Plugin {
	cmsPlugin := backend.Plugin{
		ID:       cmsplugin.ID,
		Version:  cmsplugin.Version,
		Settings: []backend.PluginSetting{},
	}

	cmsPlugin.Settings = append(cmsPlugin.Settings,
		backend.PluginSetting{
			Key:   cmsPluginEnableCache,
			Value: "",
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

// initDecredPluginJournals is called externally to run initial procedures
// such as replaying journals
func (g *gitBackEnd) initCMSPluginJournals() error {
	log.Infof("initCMSPluginJournals")

	// check if backend journal is initialized
	if g.journal == nil {
		return fmt.Errorf("initCMSPlugin backend journal isn't initialized")
	}

	err := g.replayAllJournals()
	if err != nil {
		log.Infof("initCMSPlugin replay all journals %v", err)
	}
	return nil
}

//SetCMSPluginSetting removes a setting if the value is "" and adds a setting otherwise.
func setCMSPluginSetting(key, value string) {
	if value == "" {
		delete(cmsPluginSettings, key)
		return
	}

	cmsPluginSettings[key] = value
}

func setCMSPluginHook(name string, f func(string) error) {
	cmsPluginHooks[name] = f
}

// flushDCCVotes flushes votes journal to cms plugin directory in git. It
// returns the filename that was coppied into git repo.
//
// Must be called WITH the mutex held.
func (g *gitBackEnd) flushDCCVotes(token string) (string, error) {
	if !g.vettedPropExists(token) {
		return "", fmt.Errorf("unknown dcc: %v", token)
	}

	// Setup source filenames and verify they actually exist
	srcDir := pijoin(g.journals, token)
	srcVotes := pijoin(srcDir, defaultCMSBallotFilename)
	if !util.FileExists(srcVotes) {
		return "", nil
	}

	// Setup destination filenames
	version, err := getLatest(pijoin(g.unvetted, token))
	if err != nil {
		return "", err
	}
	dir := pijoin(g.unvetted, token, version, pluginDataDir)
	votes := pijoin(dir, defaultCMSBallotFilename)

	// Create the destination container dir
	_ = os.MkdirAll(dir, 0764)

	// Move journal into place
	err = g.journal.Copy(srcVotes, votes)
	if err != nil {
		return "", err
	}

	// Return filename that is relative to git dir.
	return pijoin(token, version, pluginDataDir, defaultCMSBallotFilename), nil
}

// _flushDCCVotesJournals walks all votes journal directories and copies
// modified journals into the unvetted repo. It returns an array of filenames
// that need to be added to the git repo and subsequently rebased into the
// vetted repo .
//
// Must be called WITH the mutex held.
func (g *gitBackEnd) _flushDCCVotesJournals() ([]string, error) {
	dirs, err := ioutil.ReadDir(g.journals)
	if err != nil {
		return nil, err
	}

	files := make([]string, 0, len(dirs))
	for _, v := range dirs {
		filename := pijoin(g.journals, v.Name(),
			defaultCMSBallotFlushed)
		log.Tracef("Checking: %v", v.Name())
		if util.FileExists(filename) {
			continue
		}

		log.Infof("Flushing votes: %v", v.Name())

		// We simply copy the journal into git
		destination, err := g.flushDCCVotes(v.Name())
		if err != nil {
			log.Errorf("Could not flush %v: %v", v.Name(), err)
			continue
		}

		// Create flush record
		err = createFlushFile(filename)
		if err != nil {
			log.Errorf("Could not mark flushed %v: %v", v.Name(),
				err)
			continue
		}

		// Add filename to work
		files = append(files, destination)
	}

	return files, nil
}

// flushDCCVoteJournals wraps _flushDCCVoteJournals in git magic to revert
// flush in case of errors.
//
// Must be called WITHOUT the mutex held.
func (g *gitBackEnd) flushDCCVoteJournals() error {
	log.Tracef("flushDCCVoteJournals")

	// We may have to make this more granular
	g.Lock()
	defer g.Unlock()

	// git checkout master
	err := g.gitCheckout(g.unvetted, "master")
	if err != nil {
		return err
	}

	// git pull --ff-only --rebase
	err = g.gitPull(g.unvetted, true)
	if err != nil {
		return err
	}

	// git checkout -b timestamp_flushvotes
	branch := strconv.FormatInt(time.Now().Unix(), 10) + "_flushvotes"
	_ = g.gitBranchDelete(g.unvetted, branch) // Just in case
	err = g.gitNewBranch(g.unvetted, branch)
	if err != nil {
		return err
	}

	// closure to handle unwind if needed
	var errUnwind error
	defer func() {
		if errUnwind == nil {
			return
		}
		err := g.flushJournalsUnwind(branch)
		if err != nil {
			log.Errorf("flushJournalsUnwind: %v", err)
		}
	}()

	// Flush journals
	files, err := g._flushDCCVotesJournals()
	if err != nil {
		errUnwind = err
		return err
	}

	if len(files) == 0 {
		log.Info("flushVotesJournals: nothing to do")
		err = g.flushJournalsUnwind(branch)
		if err != nil {
			log.Errorf("flushJournalsUnwind: %v", err)
		}
		return nil
	}

	// git add journals
	commitMessage := "Flush vote journals.\n\n"
	for _, v := range files {
		err = g.gitAdd(g.unvetted, v)
		if err != nil {
			errUnwind = err
			return err
		}

		s := strings.Split(v, string(os.PathSeparator))
		if len(s) == 0 {
			commitMessage += "ERROR: " + v + "\n"
		} else {
			commitMessage += s[0] + "\n"
		}
	}

	// git commit
	err = g.gitCommit(g.unvetted, commitMessage)
	if err != nil {
		errUnwind = err
		return err
	}

	// git rebase master
	err = g.rebasePR(branch)
	if err != nil {
		errUnwind = err
		return err
	}

	return nil
}
func (g *gitBackEnd) cmsPluginJournalFlusher() {
	// XXX make this a single PR instead of 2 to save some git time
	err := g.flushDCCVoteJournals()
	if err != nil {
		log.Errorf("cmsPluginVoteFlusher: %v", err)
	}
}

func (g *gitBackEnd) pluginStartDCCVote(payload string) (string, error) {
	vote, err := cmsplugin.DecodeStartVote([]byte(payload))
	if err != nil {
		return "", fmt.Errorf("DecodeStartVote %v", err)
	}

	// Verify vote bits are somewhat sane
	for _, v := range vote.Vote.Options {
		err = _validateCMSVoteBit(vote.Vote.Options, vote.Vote.Mask, v.Bits)
		if err != nil {
			return "", fmt.Errorf("invalid vote bits: %v", err)
		}
	}

	// Verify dcc exists
	tokenB, err := util.ConvertStringToken(vote.Vote.Token)
	if err != nil {
		return "", fmt.Errorf("ConvertStringToken %v", err)
	}
	token := vote.Vote.Token

	if !g.vettedPropExists(token) {
		return "", fmt.Errorf("unknown proposal: %v", token)
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
	startVoteBlock, err := block(bb.Height)
	if err != nil {
		return "", fmt.Errorf("bestBlock %v", err)
	}

	svr := cmsplugin.StartVoteReply{
		Version:          cmsplugin.VersionStartVoteReply,
		StartBlockHeight: startVoteBlock.Height,
		StartBlockHash:   startVoteBlock.Hash,
		EndHeight:        startVoteBlock.Height + vote.Vote.Duration,
	}
	svrb, err := cmsplugin.EncodeStartVoteReply(svr)
	if err != nil {
		return "", fmt.Errorf("EncodeStartVoteReply: %v", err)
	}

	// Add version to on disk structure
	vote.Version = cmsplugin.VersionStartVote
	voteb, err := cmsplugin.EncodeStartVote(vote)
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

	// Verify DCC vote state
	vbExists := g.vettedMetadataStreamExists(tokenB,
		cmsplugin.MDStreamVoteBits)
	vsExists := g.vettedMetadataStreamExists(tokenB,
		cmsplugin.MDStreamVoteSnapshot)

	switch {
	case vbExists && vsExists:
		// Vote has started
		return "", fmt.Errorf("dcc vote already started: %v", token)
	case !vbExists && !vsExists:
		// Vote has not started; continue
	default:
		// We're in trouble!
		return "", fmt.Errorf("dcc vote is unknown vote state: %v",
			token)
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

// validateCMSVoteBits ensures that the passed in bit is a valid vote option.
// This function is expensive due to it's filesystem touches and therefore is
// lazily cached. This could stand a rewrite.
func (g *gitBackEnd) validateCMSVoteBit(token, bit string) error {
	b, err := strconv.ParseUint(bit, 16, 64)
	if err != nil {
		return err
	}

	g.Lock()
	defer g.Unlock()
	if g.shutdown {
		return backend.ErrShutdown
	}

	sv, ok := cmsPluginVoteCache[token]
	if !ok {
		// StartVote is not in the cache. Load it from disk.

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
		svb, err := ioutil.ReadFile(mdFilename(g.vetted, token,
			cmsplugin.MDStreamVoteBits))
		if err != nil {
			return err
		}
		svp, err := cmsplugin.DecodeStartVote(svb)
		if err != nil {
			return err
		}
		sv = svp

		// Update cache
		cmsPluginVoteCache[token] = sv
	}

	// Handle StartVote versioning
	var (
		mask    uint64
		options []cmsplugin.VoteOption
	)
	switch sv.Version {
	case cmsplugin.VersionStartVote:
		mask = sv.Vote.Mask
		options = sv.Vote.Options
	default:
		return fmt.Errorf("invalid start vote version %v %v",
			sv.Version, sv.Token)
	}

	return _validateCMSVoteBit(options, mask, b)
}

// _validateVoteBit iterates over all vote bits and ensure the sent in vote bit
// exists.
func _validateCMSVoteBit(options []cmsplugin.VoteOption, mask uint64, bit uint64) error {
	if len(options) == 0 {
		return fmt.Errorf("_validateVoteBit vote corrupt")
	}
	if bit == 0 {
		return invalidVoteBitError{
			err: fmt.Errorf("invalid bit 0x%x", bit),
		}
	}
	if mask&bit != bit {
		return invalidVoteBitError{
			err: fmt.Errorf("invalid mask 0x%x bit 0x%x",
				mask, bit),
		}
	}
	for _, v := range options {
		if v.Bits == bit {
			return nil
		}
		if v.Id != cmsplugin.DCCApprovalString &&
			v.Id != cmsplugin.DCCDisapprovalString {
			return invalidVoteBitError{
				err: fmt.Errorf("bit option not valid found: %s", v.Id),
			}
		}
	}
	return invalidVoteBitError{
		err: fmt.Errorf("bit not found 0x%x", bit),
	}
}

// replayDCCBallot replays voting journal for given dcc.
//
// Functions must be called WITH the lock held.
func (g *gitBackEnd) replayDCCBallot(token string) error {
	// Verify proposal exists, we can run this lockless
	if !g.vettedPropExists(token) {
		return nil
	}

	// Do some cheap things before expensive calls
	bfilename := pijoin(g.journals, token,
		defaultCMSBallotFilename)

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
				var cvj CastDCCVoteJournal
				err = d.Decode(&cvj)
				if err != nil {
					return fmt.Errorf("journal add: %v",
						err)
				}

				token := cvj.CastVote.Token
				userid := cvj.CastVote.UserID
				// See if the prop already exists
				if _, ok := cmsPluginVotesCache[token]; !ok {
					// Create map to track tickets
					cmsPluginVotesCache[token] = make(map[string]struct{})
				}
				// See if we have a duplicate vote
				if _, ok := cmsPluginVotesCache[token][userid]; ok {
					log.Errorf("duplicate cms cast vote %v %v",
						token, userid)
				}
				// All good, record vote in cache
				cmsPluginVotesCache[token][userid] = struct{}{}

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

// loadDCCVoteCache loads the cmsplugin.StartVote from disk for the provided
// token and adds it to the cmsPluginVoteCache.
//
// This function must be called WITH the lock held.
func (g *gitBackEnd) loadDCCVoteCache(token string) (*cmsplugin.StartVote, error) {
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
		cmsplugin.MDStreamVoteBits))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var sv cmsplugin.StartVote
	d := json.NewDecoder(f)
	err = d.Decode(&sv)
	if err != nil {
		return nil, err
	}

	cmsPluginVoteCache[token] = sv

	return &sv, nil
}

// loadDCCVoteSnapshotCache loads the cmsplugin.StartVoteReply from disk for the provided
// token and adds it to the cmsPluginVoteSnapshotCache.
//
// This function must be called WITH the lock held.
func (g *gitBackEnd) loadDCCVoteSnapshotCache(token string) (*cmsplugin.StartVoteReply, error) {
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

	cmsPluginVoteSnapshotCache[token] = svr

	return &svr, nil
}

// dccVoteEndHeight returns the voting period end height for the provided token.
func (g *gitBackEnd) dccVoteEndHeight(token string) (uint32, error) {
	g.Lock()
	defer g.Unlock()
	if g.shutdown {
		return 0, backend.ErrShutdown
	}

	svr, ok := cmsPluginVoteSnapshotCache[token]
	if !ok {
		s, err := g.loadDCCVoteSnapshotCache(token)
		if err != nil {
			return 0, err
		}
		svr = *s
	}

	return svr.EndHeight, nil
}

// writeDCCVote writes the provided vote to the provided journal file path, if the
// vote does not already exist. Once successfully written to the journal, the
// vote is added to the cast vote memory cache.
//
// This function must be called WITHOUT the lock held.
func (g *gitBackEnd) writeDCCVote(v cmsplugin.CastVote, receipt, journalPath string) error {
	g.Lock()
	defer g.Unlock()

	// Ensure ticket is eligible to vote.
	// This cache should have already been loaded when the
	// vote end height was validated, but lets be sure.
	sv, ok := cmsPluginVoteCache[v.Token]
	if !ok {
		s, err := g.loadDCCVoteCache(v.Token)
		if err != nil {
			return fmt.Errorf("loadDCCVoteCache: %v",
				err)
		}
		sv = *s
	}
	var found bool
	for _, t := range sv.UserWeights {
		if t.UserID == v.UserID {
			found = true
			break
		}
	}
	if !found {
		return errIneligibleUserID
	}

	// Ensure vote is not a duplicate
	_, ok = cmsPluginVotesCache[v.Token]
	if !ok {
		cmsPluginVotesCache[v.Token] = make(map[string]struct{})
	}

	_, ok = cmsPluginVotesCache[v.Token][v.UserID]
	if ok {
		return errDuplicateVote
	}

	// Create journal entry
	cvj := CastDCCVoteJournal{
		CastVote: v,
		Receipt:  receipt,
	}
	blob, err := encodeCastDCCVoteJournal(cvj)
	if err != nil {
		return fmt.Errorf("encodeCastVoteJournal: %v",
			err)
	}

	// Write vote to journal
	err = g.journal.Journal(journalPath, string(journalAdd)+
		string(blob))
	if err != nil {
		return fmt.Errorf("could not journal vote %v: %v %v",
			v.Token, v.UserID, err)
	}

	// Add vote to memory cache
	cmsPluginVotesCache[v.Token][v.UserID] = struct{}{}

	return nil
}

func (g *gitBackEnd) pluginCastVote(payload string) (string, error) {
	log.Tracef("pluginCastVote")

	// Check if journals were replayed
	if !journalsReplayed {
		return "", backend.ErrJournalsNotReplayed
	}

	// Decode ballot
	vote, err := cmsplugin.DecodeCastVote([]byte(payload))
	if err != nil {
		return "", fmt.Errorf("DecodeBallot: %v", err)
	}

	// XXX this should become part of some sort of context
	fiJSON, ok := cmsPluginSettings[cmsPluginIdentity]
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

	br := cmsplugin.CastVoteReply{}
	// Verify proposal exists, we can run this lockless
	if !g.vettedPropExists(vote.Token) {
		log.Errorf("pluginCastVote: proposal not found: %v",
			vote.Token)
		e := cmsplugin.ErrorStatusDCCNotFound
		err := fmt.Sprintf("%v: %v",
			cmsplugin.ErrorStatus[e], vote.Token)
		return "", fmt.Errorf("write vote: %v", err)
	}

	// Ensure that the votebits are correct
	err = g.validateCMSVoteBit(vote.Token, vote.VoteBit)
	if err != nil {
		if e, ok := err.(invalidVoteBitError); ok {
			es := cmsplugin.ErrorStatusInvalidVoteBit
			err := fmt.Sprintf("%v: %v",
				cmsplugin.ErrorStatus[es], e.err.Error())
			return "", fmt.Errorf("validateCMSVoteBit: %v", err)

		}
		t := time.Now().Unix()
		log.Errorf("pluginCastVote: validateCMSVoteBit %v %v %v %v",
			vote.UserID, vote.Token, t, err)
		e := cmsplugin.ErrorStatusInternalError
		err := fmt.Sprintf("%v: %v",
			cmsplugin.ErrorStatus[e], t)
		return "", fmt.Errorf("write vote: %v", err)

	}

	// Verify voting period has not ended
	endHeight, err := g.dccVoteEndHeight(vote.Token)
	if err != nil {
		t := time.Now().Unix()
		log.Errorf("pluginCastVote: dccVoteEndHeight %v %v %v %v",
			vote.UserID, vote.Token, t, err)
		e := cmsplugin.ErrorStatusInternalError
		err := fmt.Sprintf("%v: %v",
			cmsplugin.ErrorStatus[e], t)
		return "", fmt.Errorf("write vote: %v", err)

	}
	if bb.Height >= endHeight {
		e := cmsplugin.ErrorStatusVoteHasEnded
		br.ErrorStatus = e
		err := fmt.Sprintf("%v: %v",
			cmsplugin.ErrorStatus[e], vote.Token)
		return "", fmt.Errorf("write vote: %v", err)

	}

	// Ensure journal directory exists
	dir := pijoin(g.journals, vote.Token)
	bfilename := pijoin(dir, defaultCMSBallotFilename)
	err = os.MkdirAll(dir, 0774)
	if err != nil {
		// Should not fail, so return failure to alert people
		return "", fmt.Errorf("make journal dir: %v", err)
	}

	// Sign signature
	r := fi.SignMessage([]byte(vote.Signature))
	receipt := hex.EncodeToString(r[:])

	// Write vote to journal
	err = g.writeDCCVote(*vote, receipt, bfilename)
	if err != nil {
		switch err {
		case errDuplicateVote:
			e := cmsplugin.ErrorStatusDuplicateVote
			err := fmt.Sprintf("%v: %v",
				cmsplugin.ErrorStatus[e], vote.Token)
			return "", fmt.Errorf("write vote: %v", err)
		case errIneligibleUserID:
			e := cmsplugin.ErrorStatusIneligibleUserID
			err := fmt.Sprintf("%v: %v",
				cmsplugin.ErrorStatus[e], vote.Token)
			return "", fmt.Errorf("write vote: %v", err)
		default:
			// Should not fail, so return failure to alert people
			return "", fmt.Errorf("write vote: %v", err)
		}
	}

	// Update reply
	br.ClientSignature = vote.Signature
	br.Signature = receipt

	// Mark comment journal dirty
	flushFilename := pijoin(g.journals, vote.Token,
		defaultCMSBallotFlushed)
	_ = os.Remove(flushFilename)

	// Encode reply
	brb, err := cmsplugin.EncodeCastVoteReply(br)
	if err != nil {
		return "", fmt.Errorf("EncodeCastVoteReply: %v", err)
	}

	// return success and encoded answer
	return string(brb), nil
}

// tallyDCCVotes replays the ballot journal for a proposal and tallies the votes.
//
// Function must be called WITH the lock held.
func (g *gitBackEnd) tallyDCCVotes(token string) ([]cmsplugin.CastVote, error) {
	// Do some cheap things before expensive calls
	bfilename := pijoin(g.journals, token, defaultCMSBallotFilename)

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
				var cvj CastDCCVoteJournal
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

// pluginDCCVoteDetails returns the VoteDetails of a requested DCC vote.
// It uses the caches that should be populated with the StartVotes and
// StartVoteReplies.
func (g *gitBackEnd) pluginDCCVoteDetails(payload string) (string, error) {
	log.Tracef("pluginDCCVoteDetails: %v", payload)

	vd, err := cmsplugin.DecodeVoteDetails([]byte(payload))
	if err != nil {
		return "", fmt.Errorf("DecodeVoteResults %v", err)
	}

	// Verify dcc exists, we can run this lockless
	if !g.vettedPropExists(vd.Token) {
		return "", fmt.Errorf("dcc not found: %v", vd.Token)
	}

	token, err := hex.DecodeString(vd.Token)
	if err != nil {
		return "", err
	}
	// Find the most recent vesion number for this record
	r, err := g.GetVetted(token, "")
	if err != nil {
		return "", fmt.Errorf("GetVetted %v version 0: %v", token, err)
	}

	var vdr cmsplugin.VoteDetailsReply
	// Prepare reply
	for _, v := range r.Metadata {
		switch v.ID {
		case cmsplugin.MDStreamVoteBits:
			// Start vote
			sv, err := cmsplugin.DecodeStartVote([]byte(v.Payload))
			if err != nil {
				return "", err
			}
			vdr.StartVote = sv
		case cmsplugin.MDStreamVoteSnapshot:
			svr, err := cmsplugin.DecodeStartVoteReply([]byte(v.Payload))
			if err != nil {
				return "", err
			}
			vdr.StartVoteReply = svr
		}
	}

	reply, err := cmsplugin.EncodeVoteDetailsReply(vdr)
	if err != nil {
		return "", fmt.Errorf("Could not encode VoteResultsReply: %v",
			err)
	}
	return string(reply), nil
}

// pluginDCCVoteSummary
func (g *gitBackEnd) pluginDCCVoteSummary(payload string) (string, error) {
	log.Tracef("pluginDCCVoteSummary: %v", payload)

	vs, err := cmsplugin.DecodeVoteSummary([]byte(payload))
	if err != nil {
		return "", fmt.Errorf("DecodeVoteResults %v", err)
	}

	// Verify dcc exists, we can run this lockless
	if !g.vettedPropExists(vs.Token) {
		return "", fmt.Errorf("dcc not found: %v", vs.Token)
	}

	token, err := hex.DecodeString(vs.Token)
	if err != nil {
		return "", err
	}
	// Find the most recent vesion number for this record
	r, err := g.GetVetted(token, "")
	if err != nil {
		return "", fmt.Errorf("GetVetted %v version 0: %v", token, err)
	}

	// Prepare reply
	var vrr cmsplugin.VoteResultsReply
	var vsr cmsplugin.VoteSummaryReply
	var svr cmsplugin.StartVoteReply
	vors := make([]cmsplugin.VoteOptionResult, 0,
		len(vrr.StartVote.Vote.Options))

	// Fill out cast votes
	vrr.CastVotes, err = g.tallyDCCVotes(vs.Token)
	if err != nil {
		return "", fmt.Errorf("Could not tally votes: %v", err)
	}

	for _, v := range r.Metadata {
		switch v.ID {
		case cmsplugin.MDStreamVoteBits:
			// Start vote
			sv, err := cmsplugin.DecodeStartVote([]byte(v.Payload))
			if err != nil {
				return "", err
			}
			vrr.StartVote = sv
		case cmsplugin.MDStreamVoteSnapshot:
			svr, err = cmsplugin.DecodeStartVoteReply([]byte(v.Payload))
			if err != nil {
				return "", err
			}
		}
	}

	vsr.EndHeight = svr.EndHeight
	vsr.Duration = vrr.StartVote.Vote.Duration
	vsr.PassPercentage = vrr.StartVote.Vote.PassPercentage

	for _, voteOption := range vrr.StartVote.Vote.Options {
		vors = append(vors, cmsplugin.VoteOptionResult{
			ID:          voteOption.Id,
			Description: voteOption.Description,
			Bits:        voteOption.Bits,
		})
	}

	for _, vote := range vrr.CastVotes {
		b, err := strconv.ParseUint(vote.VoteBit, 16, 64)
		if err != nil {
			log.Errorf("unable to parse vote bits for vote %v %v",
				vote.Signature, err)
			continue
		}
		for i, option := range vors {
			if b == option.Bits {
				vors[i].Votes++
			}
		}
	}
	vsr.Results = vors

	reply, err := cmsplugin.EncodeVoteSummaryReply(vsr)
	if err != nil {
		return "", fmt.Errorf("Could not encode VoteResultsReply: %v",
			err)
	}

	return string(reply), nil
}

// pluginDCCVoteResults tallies all votes for a dcc. We can run the tally
// unlocked and just replay the journal. If the replay becomes an issue we
// could cache it. The Vote that is returned does have to be locked.
func (g *gitBackEnd) pluginDCCVoteResults(payload string) (string, error) {
	log.Tracef("pluginDCCVoteResults: %v", payload)

	vote, err := cmsplugin.DecodeVoteResults([]byte(payload))
	if err != nil {
		return "", fmt.Errorf("DecodeVoteResults %v", err)
	}

	// Verify dcc exists, we can run this lockless
	if !g.vettedPropExists(vote.Token) {
		return "", fmt.Errorf("dcc not found: %v", vote.Token)
	}

	// Prepare reply
	var vrr cmsplugin.VoteResultsReply

	token, err := hex.DecodeString(vote.Token)
	if err != nil {
		return "", err
	}

	// Find the most recent vesion number for this record
	r, err := g.GetVetted(token, "")
	if err != nil {
		return "", fmt.Errorf("GetVetted %v version 0: %v", token, err)
	}

	for _, v := range r.Metadata {
		switch v.ID {
		case cmsplugin.MDStreamVoteBits:
			// Start vote
			sv, err := cmsplugin.DecodeStartVote([]byte(v.Payload))
			if err != nil {
				return "", err
			}
			vrr.StartVote = sv
		}
	}

	// Fill out cast votes
	vrr.CastVotes, err = g.tallyDCCVotes(vote.Token)
	if err != nil {
		return "", fmt.Errorf("Could not tally votes: %v", err)
	}

	reply, err := cmsplugin.EncodeVoteResultsReply(vrr)
	if err != nil {
		return "", fmt.Errorf("Could not encode VoteResultsReply: %v",
			err)
	}

	return string(reply), nil
}

// pluginCMSInventory returns the cms plugin inventory for all dccs.  The
// inventory consists vote details, and cast votes.
func (g *gitBackEnd) pluginCMSInventory() (string, error) {
	log.Tracef("pluginInventory")

	g.Lock()
	defer g.Unlock()

	// Ensure journal has been replayed
	if !journalsReplayed {
		return "", backend.ErrJournalsNotReplayed
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
	svPaths := make([]string, 0, len(paths))
	svFile := fmt.Sprintf("%02v%v", cmsplugin.MDStreamVoteBits,
		defaultMDFilenameSuffix)
	for _, v := range paths {
		switch filepath.Base(v) {
		case svFile:
			svPaths = append(svPaths, v)
		}
	}

	// Compile the start vote tuples. The in-memory caches that
	// contain the vote bits and the vote snapshots are lazy
	// loaded so we have to read vote metadata directly from disk.
	svt := make([]cmsplugin.StartVoteTuple, 0, len(cmsPluginVoteCache))
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
			StartVote:      sv,
			StartVoteReply: svr,
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
				votes, err := g.tallyDCCVotes(token)
				if err != nil {
					return fmt.Errorf("tallyDCCVotes %v: %v", token, err)
				}

				cv = append(cv, votes)
			}

			return nil
		})
	if err != nil {
		return "", fmt.Errorf("walk journals: %v", err)
	}

	var count = 0
	for _, v := range cv {
		count += len(v)
	}
	votes := make([]cmsplugin.CastVote, 0, count)
	for _, v := range cv {
		votes = append(votes, v...)
	}

	// Prepare reply
	ir := cmsplugin.InventoryReply{
		StartVoteTuples: svt,
		CastVotes:       votes,
	}

	payload, err := cmsplugin.EncodeInventoryReply(ir)
	if err != nil {
		return "", fmt.Errorf("EncodeInventoryReply: %v", err)
	}

	return string(payload), nil
}
