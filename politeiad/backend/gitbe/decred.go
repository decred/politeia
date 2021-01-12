// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package gitbe

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1/v3/ecdsa"
	"github.com/decred/dcrd/dcrutil/v3"
	"github.com/decred/dcrd/wire"
	dcrdataapi "github.com/decred/dcrdata/api/types/v4"
	"github.com/decred/politeia/decredplugin"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/util"
)

// XXX plugins really need to become an interface. Run with this for now.

const (
	decredPluginIdentity        = "fullidentity"
	decredPluginJournals        = "journals"
	decredPluginVoteDurationMin = "votedurationmin"
	decredPluginVoteDurationMax = "votedurationmax"

	defaultCommentIDFilename = "commentid.txt"
	defaultCommentFilename   = "comments.journal"
	defaultCommentsFlushed   = "comments.flushed"

	defaultBallotFilename = "ballot.journal"
	defaultBallotFlushed  = "ballot.flushed"

	journalVersion       = "1"       // Version 1 of the comment journal
	journalActionAdd     = "add"     // Add entry
	journalActionDel     = "del"     // Delete entry
	journalActionAddLike = "addlike" // Add comment like

	flushRecordVersion = "1" // Version 1 of the flush journal

	// Following are what should be well-known interface hooks
	PluginPostHookEdit = "postedit" // Hook Post Edit
)

var (
	// errDuplicateVote is emitted when a cast vote is a duplicate.
	errDuplicateVote = errors.New("duplicate vote")

	// errIneligibleTicket is emitted when a vote is cast using an
	// ineligible ticket.
	errIneligibleTicket = errors.New("ineligible ticket")
)

// FlushRecord is a structure that is stored on disk when a journal has been
// flushed.
type FlushRecord struct {
	Version   string `json:"version"`   // Version
	Timestamp string `json:"timestamp"` // Timestamp
}

// JournalAction prefixes and determines what the next structure is in
// the JSON journal.
// Version is used to determine what version of the comment journal structure
// follows.
// journalActionAdd -> Add entry
// journalActionDel -> Delete entry
// journalActionAddLike -> Add comment like structure (comments only)
type JournalAction struct {
	Version string `json:"version"` // Version
	Action  string `json:"action"`  // Add/Del
}

var (
	decredPluginSettings map[string]string             // [key]setting
	decredPluginHooks    map[string]func(string) error // [key]func(token) error

	// Pregenerated journal actions
	journalAdd     []byte
	journalDel     []byte
	journalAddLike []byte

	// Plugin specific data that CANNOT be treated as metadata
	pluginDataDir = filepath.Join("plugins", "decred")

	decredPluginCommentsCache = make(map[string]map[string]decredplugin.Comment) // [token][commentid]comment

	journalsReplayed bool = false
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

func getDecredPlugin(dcrdataHost string) backend.Plugin {
	decredPlugin := backend.Plugin{
		ID:       decredplugin.ID,
		Version:  decredplugin.Version,
		Settings: []backend.PluginSetting{},
	}

	decredPlugin.Settings = append(decredPlugin.Settings,
		backend.PluginSetting{
			Key:   "dcrdata",
			Value: dcrdataHost,
		},
	)

	// Initialize hooks
	decredPluginHooks = make(map[string]func(string) error)

	// Initialize settings map
	decredPluginSettings = make(map[string]string)
	for _, v := range decredPlugin.Settings {
		decredPluginSettings[v.Key] = v.Value
	}
	return decredPlugin
}

// initDecredPlugin is called externally to run initial procedures
// such as replaying journals
func (g *gitBackEnd) initDecredPluginJournals() error {
	log.Infof("initDecredPlugin")

	// check if backend journal is initialized
	if g.journal == nil {
		return fmt.Errorf("initDecredPlugin backend journal isn't initialized")
	}

	err := g.replayAllJournals()
	if err != nil {
		log.Infof("initDecredPlugin replay all journals %v", err)
	}
	return nil
}

// replayAllJournals replays ballot and comment journals for every stored proposal
// this function can be called without the lock held
func (g *gitBackEnd) replayAllJournals() error {
	log.Infof("replayAllJournals")
	files, err := ioutil.ReadDir(g.journals)
	if err != nil {
		return fmt.Errorf("Read dir journals: %v", err)
	}
	for _, f := range files {
		name := f.Name()
		// replay comments for all props
		_, err = g.replayComments(name)
		if err != nil {
			return fmt.Errorf("replayAllJournals replayComments %s %v", name, err)
		}
	}
	journalsReplayed = true
	return nil
}

//SetDecredPluginSetting removes a setting if the value is "" and adds a setting otherwise.
func setDecredPluginSetting(key, value string) {
	if value == "" {
		delete(decredPluginSettings, key)
		return
	}

	decredPluginSettings[key] = value
}

func setDecredPluginHook(name string, f func(string) error) {
	decredPluginHooks[name] = f
}

func (g *gitBackEnd) vettedPropExists(token string) bool {
	tokenb, err := util.ConvertStringToken(token)
	if err != nil {
		return false
	}
	return g.VettedExists(tokenb)
}

func (g *gitBackEnd) getNewCid(token string) (string, error) {
	dir := pijoin(g.journals, token)
	err := os.MkdirAll(dir, 0774)
	if err != nil {
		return "", err
	}

	filename := pijoin(dir, defaultCommentIDFilename)

	g.Lock()
	defer g.Unlock()

	fh, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE, 0664)
	if err != nil {
		return "", err
	}
	defer fh.Close()

	// Determine if file is empty
	fi, err := fh.Stat()
	if err != nil {
		return "", err
	}
	if fi.Size() == 0 {
		// First comment id
		_, err := fmt.Fprintf(fh, "1\n")
		if err != nil {
			return "", err
		}
		return "1", nil
	}

	// Only allow one line
	var cid string
	s := bufio.NewScanner(fh)
	for i := 0; s.Scan(); i++ {
		if i != 0 {
			return "", fmt.Errorf("comment id file corrupt")
		}

		c, err := strconv.ParseUint(s.Text(), 10, 64)
		if err != nil {
			return "", err
		}

		// Increment comment id
		c++
		cid = strconv.FormatUint(c, 10)

		// Write back new comment id
		_, err = fh.Seek(0, io.SeekStart)
		if err != nil {
			return "", err
		}
		_, err = fmt.Fprintf(fh, "%v\n", c)
		if err != nil {
			return "", err
		}
	}
	if err := s.Err(); err != nil {
		return "", err
	}

	return cid, nil
}

// verifyMessage verifies a message is properly signed.
// Copied from https://github.com/decred/dcrd/blob/0fc55252f912756c23e641839b1001c21442c38a/rpcserver.go#L5605
func (g *gitBackEnd) verifyMessage(address, message, signature string) (bool, error) {
	// Decode the provided address.
	addr, err := dcrutil.DecodeAddress(address, g.activeNetParams)
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
	a, err := dcrutil.NewAddressSecpPubKey(serializedPK, g.activeNetParams)
	if err != nil {
		// Again mirror Bitcoin Core behavior, which treats error in
		// public key reconstruction as invalid signature.
		return false, nil
	}

	// Return boolean if addresses match.
	return a.Address() == address, nil
}

func bestBlock() (*dcrdataapi.BlockDataBasic, error) {
	url := decredPluginSettings["dcrdata"] + "/api/block/best"
	log.Debugf("connecting to %v", url)
	// XXX this http command needs a reasonable timeout.
	r, err := http.Get(url)
	log.Debugf("http connecting to %v", url)
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

	var bdb dcrdataapi.BlockDataBasic
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&bdb); err != nil {
		return nil, err
	}

	return &bdb, nil
}

func block(block uint32) (*dcrdataapi.BlockDataBasic, error) {
	h := strconv.FormatUint(uint64(block), 10)
	url := decredPluginSettings["dcrdata"] + "/api/block/" + h
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

	var bdb dcrdataapi.BlockDataBasic
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&bdb); err != nil {
		return nil, err
	}

	return &bdb, nil
}

func snapshot(hash string) ([]string, error) {
	url := decredPluginSettings["dcrdata"] + "/api/stake/pool/b/" + hash +
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

	var tickets []string
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&tickets); err != nil {
		return nil, err
	}

	return tickets, nil
}

func batchTransactions(hashes []string) ([]dcrdataapi.TrimmedTx, error) {
	// Request body is dcrdataapi.Txns marshalled to JSON
	reqBody, err := json.Marshal(dcrdataapi.Txns{
		Transactions: hashes,
	})
	if err != nil {
		return nil, err
	}

	// Make the POST request
	url := decredPluginSettings["dcrdata"] + "/api/txs/trimmed"
	log.Debugf("connecting to %v", url)
	r, err := http.Post(url, "application/json; charset=utf-8",
		bytes.NewReader(reqBody))
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

	// Unmarshal the response
	var ttx []dcrdataapi.TrimmedTx
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&ttx); err != nil {
		return nil, err
	}
	return ttx, nil
}

// largestCommitmentResult returns the largest commitment address or an error.
type largestCommitmentResult struct {
	bestAddr string
	err      error
}

func largestCommitmentAddresses(hashes []string) ([]largestCommitmentResult, error) {
	// Batch request all of the transaction info from dcrdata.
	ttxs, err := batchTransactions(hashes)
	if err != nil {
		return nil, err
	}

	// Find largest commitment address for each transaction.
	r := make([]largestCommitmentResult, len(hashes))
	for i := range ttxs {
		// Best is address with largest commit amount.
		var bestAddr string
		var bestAmount float64
		for _, v := range ttxs[i].Vout {
			if v.ScriptPubKeyDecoded.CommitAmt == nil {
				continue
			}
			if *v.ScriptPubKeyDecoded.CommitAmt > bestAmount {
				if len(v.ScriptPubKeyDecoded.Addresses) == 0 {
					// jrick, does this need to be printed?
					log.Errorf("unexpected addresses "+
						"length: %v", ttxs[i].TxID)
					continue
				}
				bestAddr = v.ScriptPubKeyDecoded.Addresses[0]
				bestAmount = *v.ScriptPubKeyDecoded.CommitAmt
			}
		}

		if bestAddr == "" || bestAmount == 0.0 {
			r[i].err = fmt.Errorf("no best commitment address found: %v",
				ttxs[i].TxID)
			continue
		}
		r[i].bestAddr = bestAddr
	}

	return r, nil
}

// pluginBestBlock returns current best block height from wallet.
func (g *gitBackEnd) pluginBestBlock() (string, error) {
	bb, err := bestBlock()
	if err != nil {
		return "", err
	}
	return strconv.FormatUint(uint64(bb.Height), 10), nil
}

// decredPluginPostEdit called after and edit is complete but before commit.
func (g *gitBackEnd) decredPluginPostEdit(token string) error {
	log.Tracef("decredPluginPostEdit: %v", token)

	// The post edit hook gets called on both unvetted and vetted
	// proposals, but comments can only be made on vetted proposals.
	var destination string
	var err error
	if g.vettedPropExists(token) {
		destination, err = g.flushComments(token)
		if err != nil {
			return err
		}
	}

	// When destination is empty there was nothing to do
	if destination == "" {
		log.Tracef("decredPluginPostEdit: nothing to do %v", token)
		return nil
	}

	// Add comments to git
	return g.gitAdd(g.unvetted, destination)
}

// createFlushFile creates a file that indicates that the a journal was flused.
//
// Must be called WITH the mutex held.
func createFlushFile(filename string) error {
	// Mark directory as flushed
	f, err := os.Create(filename)
	if err != nil {
		return err
	}

	defer f.Close()

	// Stuff timestamp in flushfile
	j := json.NewEncoder(f)
	err = j.Encode(FlushRecord{
		Version:   flushRecordVersion,
		Timestamp: strconv.FormatInt(time.Now().Unix(), 10),
	})

	return err
}

// flushJournalsUnwind unwinds all the flushing action if something goes wrong.
//
// Must be called WITH the mutex held.
func (g *gitBackEnd) flushJournalsUnwind(id string) error {
	// git stash, can fail if there are no uncommitted failures
	err := g.gitStash(g.unvetted)
	if err == nil {
		// git stash drop, allowed to fail
		_ = g.gitStashDrop(g.unvetted)
	}

	// git checkout master
	err = g.gitCheckout(g.unvetted, "master")
	if err != nil {
		return err
	}
	//  delete branch
	err = g.gitBranchDelete(g.unvetted, id)
	if err != nil {
		return err
	}
	// git clean -xdf
	return g.gitClean(g.unvetted)
}

// flushCommentflushes comments journal to decred plugin directory in
// git. It returns the filename that was coppied into git repo.
//
// Must be called WITH the mutex held.
func (g *gitBackEnd) flushComments(token string) (string, error) {
	if !g.vettedPropExists(token) {
		return "", fmt.Errorf("unknown proposal: %v", token)
	}

	// Setup source filenames and verify they actually exist
	srcDir := pijoin(g.journals, token)
	srcComments := pijoin(srcDir, defaultCommentFilename)
	if !util.FileExists(srcComments) {
		return "", nil
	}

	// Setup destination filenames
	version, err := getLatest(pijoin(g.unvetted, token))
	if err != nil {
		return "", err
	}
	dir := pijoin(g.unvetted, token, version, pluginDataDir)
	comments := pijoin(dir, defaultCommentFilename)

	// Create the destination container dir
	_ = os.MkdirAll(dir, 0764)

	// Move journal and comment id into place
	err = g.journal.Copy(srcComments, comments)
	if err != nil {
		return "", err
	}

	// Return filename that is relative to git dir.
	return pijoin(token, version, pluginDataDir, defaultCommentFilename),
		nil
}

// flushCommentJournal flushes an individual comment journal.
//
// Must be called WITH the mutex held.
func (g *gitBackEnd) flushCommentJournal(token string) (string, error) {
	// We simply copy the journal into git
	destination, err := g.flushComments(token)
	if err != nil {
		return "", fmt.Errorf("Could not flush %v: %v", token, err)
	}

	// Create flush record
	filename := pijoin(g.journals, token, defaultCommentsFlushed)
	err = createFlushFile(filename)
	if err != nil {
		return "", fmt.Errorf("Could not mark flushed %v: %v", token,
			err)
	}

	return destination, nil
}

// _flushCommentJournals walks all comment journal directories and copies
// modified journals into the unvetted repo. It returns an array of filenames
// that need to be added to the git repo and subsequently rebased into the
// vetted repo .
//
// Must be called WITH the mutex held.
func (g *gitBackEnd) _flushCommentJournals() ([]string, error) {
	dirs, err := ioutil.ReadDir(g.journals)
	if err != nil {
		return nil, err
	}

	files := make([]string, 0, len(dirs))
	for _, v := range dirs {
		filename := pijoin(g.journals, v.Name(),
			defaultCommentsFlushed)
		log.Tracef("Checking: %v", v.Name())
		if util.FileExists(filename) {
			continue
		}

		log.Infof("Flushing comments: %v", v.Name())

		// Add filename to work
		destination, err := g.flushCommentJournal(v.Name())
		if err != nil {
			log.Error(err)
			continue
		}

		files = append(files, destination)
	}

	return files, nil
}

// flushCommentJournals wraps _flushCommentJournals in git magic to revert
// flush in case of errors.
//
// Must be called WITHOUT the mutex held.
func (g *gitBackEnd) flushCommentJournals() error {
	log.Tracef("flushCommentJournals")

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

	// git checkout -b timestamp_flushcomments
	branch := strconv.FormatInt(time.Now().Unix(), 10) + "_flushcomments"
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
	files, err := g._flushCommentJournals()
	if err != nil {
		errUnwind = err
		return err
	}

	if len(files) == 0 {
		log.Info("flushCommentJournals: nothing to do")
		err = g.flushJournalsUnwind(branch)
		if err != nil {
			log.Errorf("flushJournalsUnwind: %v", err)
		}
		return nil
	}

	// git add journals
	commitMessage := "Flush comment journals.\n\n"
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

// flushVotes flushes votes journal to decred plugin directory in git. It
// returns the filename that was coppied into git repo.
//
// Must be called WITH the mutex held.
func (g *gitBackEnd) flushVotes(token string) (string, error) {
	if !g.vettedPropExists(token) {
		return "", fmt.Errorf("unknown proposal: %v", token)
	}

	// Setup source filenames and verify they actually exist
	srcDir := pijoin(g.journals, token)
	srcVotes := pijoin(srcDir, defaultBallotFilename)
	if !util.FileExists(srcVotes) {
		return "", nil
	}

	// Setup destination filenames
	version, err := getLatest(pijoin(g.unvetted, token))
	if err != nil {
		return "", err
	}
	dir := pijoin(g.unvetted, token, version, pluginDataDir)
	votes := pijoin(dir, defaultBallotFilename)

	// Create the destination container dir
	_ = os.MkdirAll(dir, 0764)

	// Move journal into place
	err = g.journal.Copy(srcVotes, votes)
	if err != nil {
		return "", err
	}

	// Return filename that is relative to git dir.
	return pijoin(token, version, pluginDataDir, defaultBallotFilename), nil
}

// _flushVotesJournals walks all votes journal directories and copies
// modified journals into the unvetted repo. It returns an array of filenames
// that need to be added to the git repo and subsequently rebased into the
// vetted repo .
//
// Must be called WITH the mutex held.
func (g *gitBackEnd) _flushVotesJournals() ([]string, error) {
	dirs, err := ioutil.ReadDir(g.journals)
	if err != nil {
		return nil, err
	}

	files := make([]string, 0, len(dirs))
	for _, v := range dirs {
		filename := pijoin(g.journals, v.Name(),
			defaultBallotFlushed)
		log.Tracef("Checking: %v", v.Name())
		if util.FileExists(filename) {
			continue
		}

		log.Infof("Flushing votes: %v", v.Name())

		// We simply copy the journal into git
		destination, err := g.flushVotes(v.Name())
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

// flushVoteJournals wraps _flushVoteJournals in git magic to revert
// flush in case of errors.
//
// Must be called WITHOUT the mutex held.
func (g *gitBackEnd) flushVoteJournals() error {
	log.Tracef("flushVoteJournals")

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
	files, err := g._flushVotesJournals()
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
func (g *gitBackEnd) decredPluginJournalFlusher() {
	// XXX make this a single PR instead of 2 to save some git time
	err := g.flushCommentJournals()
	if err != nil {
		log.Errorf("decredPluginJournalFlusher: %v", err)
	}
	err = g.flushVoteJournals()
	if err != nil {
		log.Errorf("decredPluginVoteFlusher: %v", err)
	}
}

func (g *gitBackEnd) pluginNewComment(payload string) (string, error) {
	// XXX this should become part of some sort of context
	fiJSON, ok := decredPluginSettings[decredPluginIdentity]
	if !ok {
		return "", fmt.Errorf("full identity not set")
	}
	fi, err := identity.UnmarshalFullIdentity([]byte(fiJSON))
	if err != nil {
		return "", err
	}

	// Decode comment
	comment, err := decredplugin.DecodeNewComment([]byte(payload))
	if err != nil {
		return "", fmt.Errorf("DecodeNewComment: %v", err)
	}

	// Verify proposal exists, we can run this lockless
	if !g.vettedPropExists(comment.Token) {
		return "", fmt.Errorf("unknown proposal: %v", comment.Token)
	}

	// Do some cheap things before expensive calls
	cfilename := pijoin(g.journals, comment.Token,
		defaultCommentFilename)
	if comment.ParentID == "" {
		// Empty ParentID means comment 0
		comment.ParentID = "0"
	}

	// Sign signature
	r := fi.SignMessage([]byte(comment.Signature))
	receipt := hex.EncodeToString(r[:])

	// Create new comment id
	cid, err := g.getNewCid(comment.Token)
	if err != nil {
		return "", fmt.Errorf("could not generate new comment id: %v",
			err)
	}

	// Create Journal entry
	c := decredplugin.Comment{
		Token:     comment.Token,
		ParentID:  comment.ParentID,
		Comment:   comment.Comment,
		Signature: comment.Signature,
		PublicKey: comment.PublicKey,
		CommentID: cid,
		Receipt:   receipt,
		Timestamp: time.Now().Unix(),
	}
	blob, err := decredplugin.EncodeComment(c)
	if err != nil {
		return "", fmt.Errorf("EncodeComment: %v", err)
	}

	// Add comment to journal
	err = g.journal.Journal(cfilename, string(journalAdd)+
		string(blob))
	if err != nil {
		return "", fmt.Errorf("could not journal %v: %v", c.Token, err)
	}

	// Comment journal filename
	flushFilename := pijoin(g.journals, comment.Token,
		defaultCommentsFlushed)

	// Cache comment
	g.Lock()

	// Mark comment journal dirty
	_ = os.Remove(flushFilename)

	// Remove from cash.
	if _, ok := decredPluginCommentsCache[c.Token]; !ok {
		decredPluginCommentsCache[c.Token] =
			make(map[string]decredplugin.Comment)
	}
	_, ok = decredPluginCommentsCache[c.Token][c.CommentID]
	if ok {
		// Sanity
		log.Errorf("comment should not have existed.")
	}
	decredPluginCommentsCache[c.Token][c.CommentID] = c
	g.Unlock()

	// Encode reply
	ncr := decredplugin.NewCommentReply{
		CommentID: c.CommentID,
		Receipt:   c.Receipt,
		Timestamp: c.Timestamp,
	}
	ncrb, err := decredplugin.EncodeNewCommentReply(ncr)
	if err != nil {
		return "", fmt.Errorf("EncodeNewCommentReply: %v", err)
	}

	// return success and encoded answer
	return string(ncrb), nil
}

func (g *gitBackEnd) pluginCensorComment(payload string) (string, error) {
	log.Tracef("pluginCensorComment")

	// Check if journals were replayed
	if !journalsReplayed {
		return "", backend.ErrJournalsNotReplayed
	}

	// XXX this should become part of some sort of context
	fiJSON, ok := decredPluginSettings[decredPluginIdentity]
	if !ok {
		return "", fmt.Errorf("full identity not set")
	}
	fi, err := identity.UnmarshalFullIdentity([]byte(fiJSON))
	if err != nil {
		return "", fmt.Errorf("UnmarshalFullIdentity: %v", err)
	}

	// Decode censor comment
	censor, err := decredplugin.DecodeCensorComment([]byte(payload))
	if err != nil {
		return "", fmt.Errorf("DecodeCensorComment: %v", err)
	}

	// Verify proposal exists, we can run this lockless
	if !g.vettedPropExists(censor.Token) {
		return "", fmt.Errorf("unknown proposal: %v", censor.Token)
	}

	// Sign signature
	r := fi.SignMessage([]byte(censor.Signature))
	receipt := hex.EncodeToString(r[:])

	// Comment journal filename
	flushFilename := pijoin(g.journals, censor.Token,
		defaultCommentsFlushed)

	// Ensure proposal exists in comments cache
	g.Lock()

	// Mark comment journal dirty
	_ = os.Remove(flushFilename)

	// Verify cache
	_, ok = decredPluginCommentsCache[censor.Token]
	if !ok {
		g.Unlock()
		return "", fmt.Errorf("proposal not found %v", censor.Token)
	}

	// Ensure comment exists in comments cache and has not
	// already been censored
	c, ok := decredPluginCommentsCache[censor.Token][censor.CommentID]
	if !ok {
		g.Unlock()
		return "", fmt.Errorf("comment not found %v:%v",
			censor.Token, censor.CommentID)
	}
	if c.Censored {
		g.Unlock()
		return "", fmt.Errorf("comment already censored %v: %v",
			censor.Token, censor.CommentID)
	}

	// Update comments cache
	oc := c
	c.Comment = ""
	c.Censored = true
	decredPluginCommentsCache[censor.Token][censor.CommentID] = c

	g.Unlock()

	// We create an unwind function that MUST be called from all error
	// paths. If everything works ok it is a no-op.
	unwind := func() {
		g.Lock()
		decredPluginCommentsCache[censor.Token][censor.CommentID] = oc
		g.Unlock()
	}

	// Create Journal entry
	cc := decredplugin.CensorComment{
		Token:     censor.Token,
		CommentID: censor.CommentID,
		Reason:    censor.Reason,
		Signature: censor.Signature,
		PublicKey: censor.PublicKey,
		Receipt:   receipt,
		Timestamp: time.Now().Unix(),
	}
	blob, err := decredplugin.EncodeCensorComment(cc)
	if err != nil {
		unwind()
		return "", fmt.Errorf("EncodeCensorComment: %v", err)
	}

	// Add censor comment to journal
	cfilename := pijoin(g.journals, censor.Token,
		defaultCommentFilename)
	err = g.journal.Journal(cfilename, string(journalDel)+string(blob))
	if err != nil {
		unwind()
		return "", fmt.Errorf("could not journal %v: %v", cc.Token, err)
	}

	// Encode reply
	ccr := decredplugin.CensorCommentReply{
		Receipt: cc.Receipt,
	}
	ccrb, err := decredplugin.EncodeCensorCommentReply(ccr)
	if err != nil {
		unwind()
		return "", fmt.Errorf("EncodeCensorCommentReply: %v", err)
	}

	return string(ccrb), nil
}

// encodeGetCommentsReply converts a comment map into a JSON string that can be
// returned as a decredplugin reply. If the comment map is nil it returns a
// valid empty reply structure.
func encodeGetCommentsReply(cm map[string]decredplugin.Comment) (string, error) {
	if cm == nil {
		cm = make(map[string]decredplugin.Comment)
	}

	// Encode reply
	gcr := decredplugin.GetCommentsReply{
		Comments: make([]decredplugin.Comment, 0, len(cm)),
	}
	for _, v := range cm {
		gcr.Comments = append(gcr.Comments, v)
	}

	gcrb, err := decredplugin.EncodeGetCommentsReply(gcr)
	if err != nil {
		return "", fmt.Errorf("encodeGetCommentsReply: %v", err)
	}

	return string(gcrb), nil
}

// replayComments replay the comments for a given proposal
// the proposal is matched by the provided token
// this function can be called WITHOUT the lock held
func (g *gitBackEnd) replayComments(token string) (map[string]decredplugin.Comment, error) {
	log.Debugf("replayComments %s", token)
	// Verify proposal exists, we can run this lockless
	if !g.vettedPropExists(token) {
		return nil, nil
	}

	// Do some cheap things before expensive calls
	cfilename := pijoin(g.journals, token,
		defaultCommentFilename)

	// Replay journal
	err := g.journal.Open(cfilename)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("journal.Open: %v", err)
		}
		return nil, nil
	}
	defer func() {
		err = g.journal.Close(cfilename)
		if err != nil {
			log.Errorf("journal.Close: %v", err)
		}
	}()

	comments := make(map[string]decredplugin.Comment)

	for {
		err = g.journal.Replay(cfilename, func(s string) error {
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
				var c decredplugin.Comment
				err = d.Decode(&c)
				if err != nil {
					return fmt.Errorf("journal add: %v",
						err)
				}

				// Sanity
				if _, ok := comments[c.CommentID]; ok {
					log.Errorf("duplicate comment id %v",
						c.CommentID)
				}
				comments[c.CommentID] = c

			case journalActionDel:
				var cc decredplugin.CensorComment
				err = d.Decode(&cc)
				if err != nil {
					return fmt.Errorf("journal censor: %v",
						err)
				}

				// Ensure comment has been added
				c, ok := comments[cc.CommentID]
				if !ok {
					// Complain but we can't do anything
					// about it. Can't return error or we'd
					// abort journal loop.
					log.Errorf("comment not found: %v",
						cc.CommentID)
					return nil
				}

				// Delete comment
				c.Comment = ""
				c.Censored = true
				comments[cc.CommentID] = c

			default:
				return fmt.Errorf("invalid action: %v",
					action.Action)
			}
			return nil
		})
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, err
		}
	}

	g.Lock()
	decredPluginCommentsCache[token] = comments
	g.Unlock()

	return comments, nil
}

func (g *gitBackEnd) pluginGetComments(payload string) (string, error) {
	log.Tracef("pluginGetComments")

	// Check if journals were replayed
	if !journalsReplayed {
		return "", backend.ErrJournalsNotReplayed
	}

	// Decode comment
	gc, err := decredplugin.DecodeGetComments([]byte(payload))
	if err != nil {
		return "", fmt.Errorf("DecodeGetComments: %v", err)
	}

	g.Lock()
	comments := decredPluginCommentsCache[gc.Token]
	g.Unlock()
	return encodeGetCommentsReply(comments)
}
