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
	"github.com/decred/dcrd/dcrec/secp256k1"
	"github.com/decred/dcrd/dcrutil"
	"github.com/decred/dcrd/wire"
	dcrdataapi "github.com/decred/dcrdata/api/types/v4"
	"github.com/decred/politeia/decredplugin"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/util"
)

// XXX plugins really need to become an interface. Run with this for now.

const (
	decredPluginIdentity  = "fullidentity"
	decredPluginJournals  = "journals"
	decredPluginInventory = "inventory"

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

type CastVoteJournal struct {
	CastVote decredplugin.CastVote `json:"castvote"` // Client side vote
	Receipt  string                `json:"receipt"`  // Signature of CastVote.Signature
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
	decredPluginSettings map[string]string             // [key]setting
	decredPluginHooks    map[string]func(string) error // [key]func(token) error

	// Cached values, requires lock. These caches are lazy loaded.
	// XXX why is this a pointer? Convert if possible after investigating
	decredPluginVoteCache         = make(map[string]*decredplugin.StartVote)     // [token]startvote
	decredPluginVoteSnapshotCache = make(map[string]decredplugin.StartVoteReply) // [token]StartVoteReply

	// Pregenerated journal actions
	journalAdd     []byte
	journalDel     []byte
	journalAddLike []byte

	// Plugin specific data that CANNOT be treated as metadata
	pluginDataDir = filepath.Join("plugins", "decred")

	// Cached values, requires lock. These caches are built on startup.
	decredPluginVotesCache         = make(map[string]map[string]struct{})             // [token][ticket]struct{}
	decredPluginCommentsCache      = make(map[string]map[string]decredplugin.Comment) // [token][commentid]comment
	decredPluginCommentsLikesCache = make(map[string][]decredplugin.LikeComment)      // [token]LikeComment

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
				Value: "https://testnet.decred.org:443/",
			},
		)
	} else {
		decredPlugin.Settings = append(decredPlugin.Settings,
			backend.PluginSetting{
				Key:   "dcrdata",
				Value: "https://dcrdata.decred.org:443/",
			})
	}

	// This setting is used to tell politeiad how to retrieve the
	// decred plugin data that is required to build the external
	// politeiad cache.
	decredPlugin.Settings = append(decredPlugin.Settings,
		backend.PluginSetting{
			Key:   decredPluginInventory,
			Value: decredplugin.CmdInventory,
		})

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
		// replay ballot for all props
		err := g.replayBallot(name)
		if err != nil {
			return fmt.Errorf("replayAllJournals replayBallot %s %v", name, err)
		}
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

func (g *gitBackEnd) propExists(repo, token string) bool {
	_, err := os.Stat(pijoin(repo, token))
	return err == nil
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
	url := decredPluginSettings["dcrdata"] + "api/block/" + h
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
	url := decredPluginSettings["dcrdata"] + "api/stake/pool/b/" + hash +
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
	url := decredPluginSettings["dcrdata"] + "api/txs/trimmed"
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

	destination, err := g.flushComments(token)
	if err != nil {
		return err
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
	if !g.propExists(g.unvetted, token) {
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
	if !g.propExists(g.unvetted, token) {
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
	if !g.propExists(g.vetted, comment.Token) {
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

// pluginLikeComment handles up and down votes of comments.
func (g *gitBackEnd) pluginLikeComment(payload string) (string, error) {
	log.Tracef("pluginLikeComment")

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
		return "", err
	}

	// Decode comment
	like, err := decredplugin.DecodeLikeComment([]byte(payload))
	if err != nil {
		return "", fmt.Errorf("DecodeLikeComment: %v", err)
	}

	// Make sure action makes sense
	if like.Action != "-1" && like.Action != "1" {
		return "", fmt.Errorf("invalid action")
	}

	// Verify proposal exists, we can run this lockless
	if !g.propExists(g.vetted, like.Token) {
		return "", fmt.Errorf("unknown proposal: %v", like.Token)
	}

	// XXX make sure comment id exists and is in the right prop

	// Sign signature
	r := fi.SignMessage([]byte(like.Signature))
	receipt := hex.EncodeToString(r[:])

	// Comment journal filename
	flushFilename := pijoin(g.journals, like.Token,
		defaultCommentsFlushed)

	// Ensure proposal exists in comments cache
	g.Lock()

	// Mark comment journal dirty
	_ = os.Remove(flushFilename)

	// Verify cache
	c, ok := decredPluginCommentsCache[like.Token][like.CommentID]
	if !ok {
		g.Unlock()
		return "", fmt.Errorf("comment not found %v:%v",
			like.Token, like.CommentID)
	}

	cc := decredPluginCommentsLikesCache[like.Token]

	// Update cache
	decredPluginCommentsLikesCache[like.Token] = append(cc, *like)
	g.Unlock()

	// We create an unwind function that MUST be called from all error
	// paths. If everything works ok it is a no-op.
	unwind := func() {
		g.Lock()
		decredPluginCommentsLikesCache[like.Token] = cc
		g.Unlock()
	}

	// Create Journal entry
	lc := decredplugin.LikeComment{
		Token:     like.Token,
		CommentID: like.CommentID,
		Action:    like.Action,
		Signature: like.Signature,
		PublicKey: like.PublicKey,
		Receipt:   receipt,
		Timestamp: time.Now().Unix(),
	}
	blob, err := decredplugin.EncodeLikeComment(lc)
	if err != nil {
		unwind()
		return "", fmt.Errorf("EncodeLikeComment: %v", err)
	}

	// Add comment to journal
	cfilename := pijoin(g.journals, like.Token,
		defaultCommentFilename)
	err = g.journal.Journal(cfilename, string(journalAddLike)+
		string(blob))
	if err != nil {
		unwind()
		return "", fmt.Errorf("could not journal %v: %v", lc.Token, err)
	}

	// Encode reply
	lcr := decredplugin.LikeCommentReply{
		Total:   c.TotalVotes,
		Result:  c.ResultVotes,
		Receipt: receipt,
	}
	lcrb, err := decredplugin.EncodeLikeCommentReply(lcr)
	if err != nil {
		unwind()
		return "", fmt.Errorf("EncodeLikeCommentReply: %v", err)
	}

	// return success and encoded answer
	return string(lcrb), nil
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
	if !g.propExists(g.vetted, censor.Token) {
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
	if !g.propExists(g.vetted, token) {
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
	commentsLikes := make([]decredplugin.LikeComment, 0, 1024)

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

			case journalActionAddLike:
				var lc decredplugin.LikeComment
				err = d.Decode(&lc)
				if err != nil {
					return fmt.Errorf("journal addlike: %v",
						err)
				}

				commentsLikes = append(commentsLikes, lc)

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

	g.Lock()
	decredPluginCommentsCache[token] = comments
	decredPluginCommentsLikesCache[token] = commentsLikes
	g.Unlock()

	return comments, nil
}

// pluginGetProposalCommentLikes return all UserCommentVotes for a given proposal
func (g *gitBackEnd) pluginGetProposalCommentsLikes(payload string) (string, error) {
	var gpclr decredplugin.GetProposalCommentsLikesReply

	gpcl, err := decredplugin.DecodeGetProposalCommentsLikes([]byte(payload))
	if err != nil {
		return "", fmt.Errorf("DecodeGetProposalCommentsLikes: %v", err)
	}

	g.Lock()
	gpclr.CommentsLikes = decredPluginCommentsLikesCache[gpcl.Token]
	g.Unlock()

	egpclr, err := decredplugin.EncodeGetProposalCommentsLikesReply(gpclr)
	if err != nil {
		return "", fmt.Errorf("EncodeGetProposalCommentsLikesReply: %v", err)
	}
	return string(egpclr), nil
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

// pluginAuthorizeVote updates the vetted repo with vote authorization
// metadata from the proposal author.
func (g *gitBackEnd) pluginAuthorizeVote(payload string) (string, error) {
	log.Tracef("pluginAuthorizeVote")

	// Decode authorize vote
	authorize, err := decredplugin.DecodeAuthorizeVote([]byte(payload))
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
	av := decredplugin.AuthorizeVote{
		Version:   decredplugin.VersionAuthorizeVote,
		Receipt:   receipt,
		Timestamp: t,
		Action:    authorize.Action,
		Token:     token,
		Signature: authorize.Signature,
		PublicKey: authorize.PublicKey,
	}
	avb, err := decredplugin.EncodeAuthorizeVote(av)
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
		fmt.Sprintf("%02v%v", decredplugin.MDStreamVoteBits,
			defaultMDFilenameSuffix)))
	if err == nil {
		// Vote has already started. This should not happen.
		return "", fmt.Errorf("proposal vote already started: %v",
			token)
	}

	// Update metadata
	err = g._updateVettedMetadata(tokenb, nil, []backend.MetadataStream{
		{
			ID:      decredplugin.MDStreamAuthorizeVote,
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
	avr := decredplugin.AuthorizeVoteReply{
		Action:        av.Action,
		RecordVersion: version,
		Receipt:       av.Receipt,
		Timestamp:     av.Timestamp,
	}
	avrb, err := decredplugin.EncodeAuthorizeVoteReply(avr)
	if err != nil {
		return "", err
	}

	log.Infof("Vote authorized for %v", token)

	return string(avrb), nil
}

func (g *gitBackEnd) pluginStartVote(payload string) (string, error) {
	vote, err := decredplugin.DecodeStartVote([]byte(payload))
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
	if vote.Vote.Duration < decredplugin.VoteDurationMin ||
		vote.Vote.Duration > decredplugin.VoteDurationMax {
		// XXX return a user error instead of an internal error
		return "", fmt.Errorf("invalid duration: %v (%v - %v)",
			vote.Vote.Duration, decredplugin.VoteDurationMin,
			decredplugin.VoteDurationMax)
	}

	svr := decredplugin.StartVoteReply{
		Version: decredplugin.VersionStartVoteReply,
		StartBlockHeight: strconv.FormatUint(uint64(snapshotBlock.Height),
			10),
		StartBlockHash: snapshotBlock.Hash,
		// On EndHeight: we start in the past, add maturity to correct
		EndHeight: strconv.FormatUint(uint64(snapshotBlock.Height+
			vote.Vote.Duration+
			uint32(g.activeNetParams.TicketMaturity)), 10),
		EligibleTickets: snapshot,
	}
	svrb, err := decredplugin.EncodeStartVoteReply(svr)
	if err != nil {
		return "", fmt.Errorf("EncodeStartVoteReply: %v", err)
	}

	// Add version to on disk structure
	vote.Version = decredplugin.VersionStartVote
	voteb, err := decredplugin.EncodeStartVote(*vote)
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
		fmt.Sprintf("%02v%v", decredplugin.MDStreamAuthorizeVote,
			defaultMDFilenameSuffix)))
	_, err2 := os.Stat(pijoin(joinLatest(g.vetted, token),
		fmt.Sprintf("%02v%v", decredplugin.MDStreamVoteBits,
			defaultMDFilenameSuffix)))
	_, err3 := os.Stat(pijoin(joinLatest(g.vetted, token),
		fmt.Sprintf("%02v%v", decredplugin.MDStreamVoteSnapshot,
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
		fmt.Sprintf("%02v%v", decredplugin.MDStreamAuthorizeVote,
			defaultMDFilenameSuffix)))
	if err != nil {
		return "", fmt.Errorf("readfile authorizevote: %v", err)
	}
	av, err := decredplugin.DecodeAuthorizeVote(b)
	if err != nil {
		return "", fmt.Errorf("DecodeAuthorizeVote: %v", err)
	}
	if av.Action == decredplugin.AuthVoteActionRevoke {
		return "", fmt.Errorf("vote authorization revoked")
	}

	// Store snapshot in metadata
	err = g._updateVettedMetadata(tokenB, nil, []backend.MetadataStream{
		{
			ID:      decredplugin.MDStreamVoteBits,
			Payload: string(voteb),
		},
		{
			ID:      decredplugin.MDStreamVoteSnapshot,
			Payload: string(svrb),
		}})
	if err != nil {
		return "", fmt.Errorf("_updateVettedMetadata: %v", err)
	}

	// Add vote snapshot to in-memory cache
	decredPluginVoteSnapshotCache[token] = svr

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
	if vote.Mask&bit != bit {
		return invalidVoteBitError{
			err: fmt.Errorf("invalid mask 0x%x bit 0x%x",
				vote.Mask, bit),
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
		decredplugin.MDStreamVoteBits))
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
func (g *gitBackEnd) loadVoteSnapshotCache(token string) (*decredplugin.StartVoteReply, error) {
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
		decredplugin.MDStreamVoteSnapshot))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var svr decredplugin.StartVoteReply
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
func (g *gitBackEnd) writeVote(v decredplugin.CastVote, receipt, journalPath string) error {
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
	ballot, err := decredplugin.DecodeBallot([]byte(payload))
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

	br := decredplugin.BallotReply{
		Receipts: make([]decredplugin.CastVoteReply, len(ballot.Votes)),
	}
	for k, v := range ballot.Votes {
		// Verify proposal exists, we can run this lockless
		if !g.propExists(g.vetted, v.Token) {
			log.Errorf("pluginBallot: proposal not found: %v",
				v.Token)
			e := decredplugin.ErrorStatusProposalNotFound
			br.Receipts[k].ErrorStatus = e
			br.Receipts[k].Error = fmt.Sprintf("%v: %v",
				decredplugin.ErrorStatus[e], v.Token)
			continue
		}

		// Ensure that the votebits are correct
		err = g.validateVoteBit(v.Token, v.VoteBit)
		if err != nil {
			if e, ok := err.(invalidVoteBitError); ok {
				es := decredplugin.ErrorStatusInvalidVoteBit
				br.Receipts[k].ErrorStatus = es
				br.Receipts[k].Error = fmt.Sprintf("%v: %v",
					decredplugin.ErrorStatus[es], e.err.Error())
				continue
			}
			t := time.Now().Unix()
			log.Errorf("pluginBallot: validateVoteBit %v %v %v %v",
				v.Ticket, v.Token, t, err)
			e := decredplugin.ErrorStatusInternalError
			br.Receipts[k].ErrorStatus = e
			br.Receipts[k].Error = fmt.Sprintf("%v: %v",
				decredplugin.ErrorStatus[e], t)
			continue
		}

		// Verify voting period has not ended
		endHeight, err := g.voteEndHeight(v.Token)
		if err != nil {
			t := time.Now().Unix()
			log.Errorf("pluginBallot: voteEndHeight %v %v %v %v",
				v.Ticket, v.Token, t, err)
			e := decredplugin.ErrorStatusInternalError
			br.Receipts[k].ErrorStatus = e
			br.Receipts[k].Error = fmt.Sprintf("%v: %v",
				decredplugin.ErrorStatus[e], t)
			continue
		}
		if bb.Height >= endHeight {
			e := decredplugin.ErrorStatusVoteHasEnded
			br.Receipts[k].ErrorStatus = e
			br.Receipts[k].Error = fmt.Sprintf("%v: %v",
				decredplugin.ErrorStatus[e], v.Token)
			continue
		}

		// See if there was an error for this address
		if ticketAddresses[k].err != nil {
			t := time.Now().Unix()
			log.Errorf("pluginBallot: ticketAddresses %v %v %v %v",
				v.Ticket, v.Token, t, err)
			e := decredplugin.ErrorStatusInternalError
			br.Receipts[k].ErrorStatus = e
			br.Receipts[k].Error = fmt.Sprintf("%v: %v",
				decredplugin.ErrorStatus[e], t)
			continue
		}

		// Verify that vote is signed correctly
		err = g.validateVoteByAddress(v.Token, v.Ticket,
			ticketAddresses[k].bestAddr, v.VoteBit, v.Signature)
		if err != nil {
			t := time.Now().Unix()
			log.Errorf("pluginBallot: validateVote %v %v %v %v",
				v.Ticket, v.Token, t, err)
			e := decredplugin.ErrorStatusInternalError
			br.Receipts[k].ErrorStatus = e
			br.Receipts[k].Error = fmt.Sprintf("%v: %v",
				decredplugin.ErrorStatus[e], t)
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
				e := decredplugin.ErrorStatusDuplicateVote
				br.Receipts[k].ErrorStatus = e
				br.Receipts[k].Error = fmt.Sprintf("%v: %v",
					decredplugin.ErrorStatus[e], v.Token)
				continue
			case errIneligibleTicket:
				e := decredplugin.ErrorStatusIneligibleTicket
				br.Receipts[k].ErrorStatus = e
				br.Receipts[k].Error = fmt.Sprintf("%v: %v",
					decredplugin.ErrorStatus[e], v.Token)
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
	brb, err := decredplugin.EncodeBallotReply(br)
	if err != nil {
		return "", fmt.Errorf("EncodeBallotReply: %v", err)
	}

	// return success and encoded answer
	return string(brb), nil
}

// tallyVotes replays the ballot journal for a proposal and tallies the votes.
//
// Function must be called WITH the lock held.
func (g *gitBackEnd) tallyVotes(token string) ([]decredplugin.CastVote, error) {
	// Do some cheap things before expensive calls
	bfilename := pijoin(g.journals, token, defaultBallotFilename)

	// Replay journal
	err := g.journal.Open(bfilename)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("journal.Open: %v", err)
		}
		return []decredplugin.CastVote{}, nil
	}
	defer func() {
		err = g.journal.Close(bfilename)
		if err != nil {
			log.Errorf("journal.Close: %v", err)
		}
	}()

	cv := make([]decredplugin.CastVote, 0, 41000)
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

	vote, err := decredplugin.DecodeVoteResults([]byte(payload))
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
	var vrr decredplugin.VoteResultsReply

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
	reply, err := decredplugin.EncodeVoteResultsReply(vrr)
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
	comments := make([]decredplugin.Comment, 0, count)
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
	likes := make([]decredplugin.LikeComment, 0, count)
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
	avFile := fmt.Sprintf("%02v%v", decredplugin.MDStreamAuthorizeVote,
		defaultMDFilenameSuffix)
	svFile := fmt.Sprintf("%02v%v", decredplugin.MDStreamVoteBits,
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
	av := make([]decredplugin.AuthorizeVote, 0, len(avPaths))
	avr := make([]decredplugin.AuthorizeVoteReply, 0, len(avPaths))
	for _, v := range avPaths {
		// Read in authorize vote file into memory
		b, err := ioutil.ReadFile(v)
		if err != nil {
			return "", fmt.Errorf("ReadFile: %v", err)
		}

		// Decode authorize vote
		a, err := decredplugin.DecodeAuthorizeVote(b)
		if err != nil {
			return "", fmt.Errorf("DecodeAuthorizeVote: %v", err)
		}
		av = append(av, *a)

		// Parse record version out of file path
		versionDir := filepath.Dir(v)
		version := filepath.Base(versionDir)

		// Create authorize vote reply
		avr = append(avr, decredplugin.AuthorizeVoteReply{
			Action:        a.Action,
			RecordVersion: version,
			Receipt:       a.Receipt,
			Timestamp:     a.Timestamp,
		})
	}

	// Compile the start vote tuples. The in-memory caches that
	// contain the vote bits and the vote snapshots are lazy
	// loaded so we have to read vote metadata directly from disk.
	svt := make([]decredplugin.StartVoteTuple, 0, len(decredPluginVoteCache))
	for _, v := range svPaths {
		// Read vote bits file into memory
		b, err := ioutil.ReadFile(v)
		if err != nil {
			return "", fmt.Errorf("ReadFile %v: %v", v, err)
		}

		// Decode vote bits
		sv, err := decredplugin.DecodeStartVote(b)
		if err != nil {
			return "", fmt.Errorf("DecodeStartVote: %v", err)
		}

		// Read vote snapshot file into memory
		dir := filepath.Dir(v)
		filename := fmt.Sprintf("%02v%v", decredplugin.MDStreamVoteSnapshot,
			defaultMDFilenameSuffix)
		path := filepath.Join(dir, filename)
		b, err = ioutil.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("ReadFile %v: %v", path, err)
		}

		// Decode vote snapshot
		svr, err := decredplugin.DecodeStartVoteReply(b)
		if err != nil {
			return "", fmt.Errorf("DecodeStartVoteReply: %v", err)
		}

		// Create start vote tuple
		svt = append(svt, decredplugin.StartVoteTuple{
			StartVote:      *sv,
			StartVoteReply: *svr,
		})
	}

	// Compile cast votes. The in-memory votes cache does not
	// store the full cast vote struct so we need to replay the
	// vote journals.

	// Walk journals directory and tally votes for all ballot
	// journals that are found.
	cv := make([][]decredplugin.CastVote, 0, len(svt))
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
	votes := make([]decredplugin.CastVote, 0, count)
	for _, v := range cv {
		votes = append(votes, v...)
	}

	// Prepare reply
	ir := decredplugin.InventoryReply{
		Comments:             comments,
		LikeComments:         likes,
		AuthorizeVotes:       av,
		AuthorizeVoteReplies: avr,
		StartVoteTuples:      svt,
		CastVotes:            votes,
	}

	payload, err := decredplugin.EncodeInventoryReply(ir)
	if err != nil {
		return "", fmt.Errorf("EncodeInventoryReply: %v", err)
	}

	return string(payload), nil
}

// pluginLoadVoteResults is a pass through function. CmdLoadVoteResults does
// not require any work to be performed in gitBackEnd.
func (g *gitBackEnd) pluginLoadVoteResults() (string, error) {
	r := decredplugin.LoadVoteResultsReply{}
	reply, err := decredplugin.EncodeLoadVoteResultsReply(r)
	if err != nil {
		return "", err
	}
	return string(reply), nil
}
