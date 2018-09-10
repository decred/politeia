package gitbe

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/decred/dcrd/chaincfg/chainec"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrutil"
	"github.com/decred/dcrd/wire"
	dcrdataapi "github.com/decred/dcrdata/api/types"
	"github.com/decred/politeia/decredplugin"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/util"
)

// XXX plugins really need to become an interface. Run with this for now.

const (
	decredPluginIdentity = "fullidentity"
	decredPluginJournals = "journals"

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

	// cached values, requires lock
	// XXX why is this a pointer? Convert if possible after investigating
	decredPluginVoteCache = make(map[string]*decredplugin.StartVote) // [token]startvote

	// Pregenerated journal actions
	journalAdd     []byte
	journalDel     []byte
	journalAddLike []byte

	// Plugin specific data that CANNOT be treated as metadata
	pluginDataDir = filepath.Join("plugins", "decred")

	// Individual votes cache
	//decredPluginVotesCache = make(map[string]map[string]decredplugin.CastVote) // [token][ticket]castvote
	decredPluginVotesCache = make(map[string]map[string]struct{})

	decredPluginCommentsCache     = make(map[string]map[string]decredplugin.Comment) // [token][commentid]comment
	decredPluginCommentsUserCache = make(map[string]map[string]int64)                // [token+pubkey][commentid]

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

	// Initialize hooks
	decredPluginHooks = make(map[string]func(string) error)

	// Initialize settings map
	decredPluginSettings = make(map[string]string)
	for _, v := range decredPlugin.Settings {
		decredPluginSettings[v.Key] = v.Value
	}
	return decredPlugin
}

// initDecredPlugin is called externaly to run initial procedures
// such as replaying journals
func (g *gitBackEnd) initDecredPluginJournals() error {
	log.Infof("initDecredPlugin")

	// check if backend journal is intialized
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
		g.replayBallot(name)
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
	// XXX this http command needs a reasonable timeout.
	r, err := http.Get(url)
	log.Debugf("http connecting to %v", url)
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
		return nil, fmt.Errorf("POST request failed: %d", r.StatusCode)
	}

	// Unmarshal the resonse
	var ttx []dcrdataapi.TrimmedTx
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&ttx); err != nil {
		return nil, err
	}
	return ttx, nil
}

// largestCommitmentResult returns the largest commitment addres or an error.
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
	} else {
		// Sanity
		log.Errorf("comment should not have existed.")
	}
	decredPluginCommentsCache[c.Token][c.CommentID] = c
	g.Unlock()

	// Encode reply
	ncr := decredplugin.NewCommentReply{
		Comment: c,
	}
	ncrb, err := decredplugin.EncodeNewCommentReply(ncr)
	if err != nil {
		return "", fmt.Errorf("EncodeNewCommentReply: %v", err)
	}

	// return success and encoded answer
	return string(ncrb), nil
}

func replyLikeCommentReplyError(failure error) (string, error) {
	lcr := decredplugin.LikeCommentReply{
		Error: failure.Error(),
	}
	lcrb, err := decredplugin.EncodeLikeCommentReply(lcr)
	if err != nil {
		return "", fmt.Errorf("EncodeLikeCommentReply: %v", err)
	}

	return string(lcrb), nil
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
	var action int64
	switch like.Action {
	case "-1":
		action = -1
	case "1":
		action = 1
	default:
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

	key := like.Token + like.PublicKey
	if _, ok := decredPluginCommentsUserCache[key]; !ok {
		decredPluginCommentsUserCache[key] = make(map[string]int64)
	}

	newUserResult, commentResult,
		commentTotal := calculateCommentVotingValues(key, like.CommentID,
		decredPluginCommentsUserCache, c.TotalVotes, c.ResultVotes, action)

	cc := c

	// Update cache
	decredPluginCommentsUserCache[key][like.CommentID] = newUserResult
	c.ResultVotes = commentResult
	c.TotalVotes = commentTotal
	decredPluginCommentsCache[like.Token][like.CommentID] = c

	g.Unlock()

	// We create an unwind function that MUST be called from all error
	// paths. If everything works ok it is a no-op.
	unwind := func() {
		g.Lock()
		decredPluginCommentsCache[like.Token][like.CommentID] = cc
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

	// Ensure comment exists in comments cache
	c, ok := decredPluginCommentsCache[censor.Token][censor.CommentID]
	if !ok {
		g.Unlock()
		return "", fmt.Errorf("comment not found %v:%v",
			censor.Token, censor.CommentID)
	}

	// Update comments cache
	delete(decredPluginCommentsCache[censor.Token], censor.CommentID)

	g.Unlock()

	// We create an unwind function that MUST be called from all error
	// paths. If everything works ok it is a no-op.
	unwind := func() {
		g.Lock()
		decredPluginCommentsCache[censor.Token][censor.CommentID] = c
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

// calculateCommentVotingValues calculates the new values to be cached for
// decredPluginCommentsUserCache (newUserResult) and the new totalVotes and resultVotes
// of the provided comment.
// it must be called WITH the lock held IF the provided userComments refers to decredPluginUserCache
// otherwise it can be called WITHOUT the lock held
// (e.g: replayComments use a internal map before assigning it to the cache)
func calculateCommentVotingValues(key, commentID string, userComments map[string]map[string]int64,
	totalVotes uint64, resultVotes int64, action int64) (int64, int64, uint64) {
	var newUserResult int64
	commentResult := resultVotes
	commentTotal := totalVotes
	// See if this user has voted on this comment already
	if userResult, ok := userComments[key][commentID]; !ok {
		newUserResult = action
		commentResult += action
		commentTotal++
	} else {
		// In case user action is equals the user result
		// result is set to 0 (e.g: revert last action)
		if userResult == action {
			newUserResult = 0
			commentResult -= action
			commentTotal--
		} else {
			// otherwise the user voting result
			// is the new action provided
			newUserResult = action
			commentResult += action - userResult //reverse previous action and add the new one
			if userResult == 0 {
				commentTotal++
			}
		}
	}
	return newUserResult, commentResult, commentTotal
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
	seen := make(map[string]map[string]int64)
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
				_, ok := comments[cc.CommentID]
				if !ok {
					// Complain but we can't do anything
					// about it. Can't return error or we'd
					// abort journal loop.
					log.Errorf("comment not found: %v",
						cc.CommentID)
					return nil
				}

				// Delete comment
				delete(comments, cc.CommentID)

			case journalActionAddLike:
				var lc decredplugin.LikeComment
				err = d.Decode(&lc)
				if err != nil {
					return fmt.Errorf("journal addlike: %v",
						err)
				}

				// Fish out comment pointer
				c, ok := comments[lc.CommentID]
				if !ok {
					// Complain but we can't do anything
					// about it. Can'treturn error or we'd
					// abort journal loop.
					log.Errorf("comment not found: %v",
						lc.CommentID)
					return nil
				}

				//Update score
				action, err := strconv.ParseInt(lc.Action, 10, 64)
				if err != nil {
					log.Errorf("invalid action: %v %v",
						lc.CommentID, lc.Action)
				}

				key := lc.Token + lc.PublicKey
				if _, ok := seen[key]; !ok {
					seen[key] = make(map[string]int64)
				}

				newUserResult, commentResult,
					commentTotal := calculateCommentVotingValues(key, lc.CommentID,
					seen, c.TotalVotes, c.ResultVotes, action)

				c.ResultVotes = commentResult
				c.TotalVotes = commentTotal
				seen[key][lc.CommentID] = newUserResult
				// Write back updated version
				comments[lc.CommentID] = c
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
	decredPluginCommentsUserCache = seen
	g.Unlock()

	return comments, nil
}

// pluginGetProposalCommentVotes return all UserCommentVotes for a given proposal
func (g *gitBackEnd) pluginGetProposalCommentVotes(payload string) (string, error) {
	var gpcvr decredplugin.GetProposalCommentsVotesReply

	gpcv, err := decredplugin.DecodeGetProposalCommentsVotes([]byte(payload))
	if err != nil {
		return "", fmt.Errorf("DecodeGetProposalCommentsVotes: %v", err)
	}

	// XXX Shouldn't be iterating over the cache
	// Todo: find a better cache solution which deals with accessing
	// multiple entries in a optimized fashion
	g.Lock()
	for key, value := range decredPluginCommentsUserCache {
		// check if token matches the key prefix

		if pubkey := strings.TrimPrefix(key, gpcv.Token); pubkey != key {
			// if token is the prefix, the remaining part is the pubkey
			// now iterate over the map [commentid][action]
			for cid, action := range value {
				gpcvr.UserCommentsVotes = append(gpcvr.UserCommentsVotes, decredplugin.UserCommentVote{
					Pubkey:    pubkey,
					CommentID: cid,
					Action:    strconv.Itoa(int(action)),
					Token:     gpcv.Token,
				})
			}
		}
	}
	g.Unlock()

	egpcvr, err := decredplugin.EncodeGetProposalCommentsVotesReply(gpcvr)
	if err != nil {
		return "", fmt.Errorf("EncodeGetProposalCommentsVotesReply: %v", err)
	}
	return string(egpcvr), nil
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

	// Verify proposal is in the right state
	_, err1 := os.Stat(pijoin(joinLatest(g.vetted, token),
		fmt.Sprintf("%02v%v", decredplugin.MDStreamVoteBits,
			defaultMDFilenameSuffix)))
	_, err2 := os.Stat(pijoin(joinLatest(g.vetted, token),
		fmt.Sprintf("%02v%v", decredplugin.MDStreamVoteSnapshot,
			defaultMDFilenameSuffix)))
	if err1 != nil && err2 != nil {
		// Vote has not started, continue
	} else if err1 == nil && err2 == nil {
		// Vote has started
		return "", fmt.Errorf("proposal vote already started: %v",
			token)
	} else {
		// This is bad, both files should exist or not exist
		return "", fmt.Errorf("proposal is unknown vote state: %v",
			token)
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
		return "", fmt.Errorf("no eligble voters for %v", token)
	}

	// Make sure vote duration isn't too large. Assume < 2 weeks
	// XXX calculate this value for testnet instead of using hard coded values.
	if vote.Vote.Duration < 2016 || vote.Vote.Duration > 2016*2 {
		// XXX return a user error instead of an internal error
		return "", fmt.Errorf("invalid duration: %v (%v - %v)",
			vote.Vote.Duration, 2016, 2016*2)
	}

	svr := decredplugin.StartVoteReply{
		Version: decredplugin.VersionStartVoteReply,
		StartBlockHeight: strconv.FormatUint(uint64(snapshotBlock.Height),
			10),
		StartBlockHash: snapshotBlock.Hash,
		EndHeight: strconv.FormatUint(uint64(snapshotBlock.Height+
			vote.Vote.Duration), 10),
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

	// Store snapshot in metadata
	err = g.UpdateVettedMetadata(tokenB, nil, []backend.MetadataStream{
		{
			ID:      decredplugin.MDStreamVoteBits,
			Payload: string(voteb),
		},
		{
			ID:      decredplugin.MDStreamVoteSnapshot,
			Payload: string(svrb),
		}})
	if err != nil {
		return "", fmt.Errorf("UpdateVettedMetadata: %v", err)
	}

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

// voteExists verifies if a vote exists in the memory cache. If the cache does
// not exists it is replayed from disk. If the vote exists in the cache the
// functions returns true.
//
// Functions must be called WITH the lock held.
func (g *gitBackEnd) voteExists(v decredplugin.CastVote) (bool, error) {
	// Check if journal exists, use fast path
	_, ok := decredPluginVotesCache[v.Token][v.Ticket]
	return ok, nil
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
			br.Receipts[k].Error = "proposal not found: " + v.Token
			continue
		}

		// Replay individual votes journal
		dup, err := g.voteExists(v)
		if err != nil {
			t := time.Now().Unix()
			log.Errorf("pluginBallot: voteExists %v %v %v %v",
				v.Ticket, v.Token, t, err)
			br.Receipts[k].Error = fmt.Sprintf("internal error %v",
				t)
			continue
		}
		if dup {
			br.Receipts[k].Error = "duplicate vote: " + v.Token
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
		br.Receipts[k].ClientSignature = v.Signature

		dir := pijoin(g.journals, v.Token)
		bfilename := pijoin(dir, defaultBallotFilename)
		err = os.MkdirAll(dir, 0774)
		if err != nil {
			// Should not fail, so return failure to alert people
			return "", fmt.Errorf("EncodeCastVoteJournal: %v", err)
		}

		// Sign signature
		r := fi.SignMessage([]byte(v.Signature))
		receipt := hex.EncodeToString(r[:])
		br.Receipts[k].Signature = receipt

		// Create Journal entry
		cvj := CastVoteJournal{
			CastVote: v,
			Receipt:  receipt,
		}
		blob, err := encodeCastVoteJournal(cvj)
		if err != nil {
			// Should not fail, so return failure to alert people
			return "", fmt.Errorf("EncodeCastVoteJournal: %v", err)
		}

		// Add comment to journal
		err = g.journal.Journal(bfilename, string(journalAdd)+
			string(blob))
		if err != nil {
			// Should not fail, so return failure to alert people
			return "", fmt.Errorf("could not journal vote %v: %v %v",
				v.Token, v.Ticket, err)
		}

		// Add to cache
		g.Lock()
		if _, ok := decredPluginVotesCache[v.Token]; !ok {
			decredPluginVotesCache[v.Token] = make(map[string]struct{})
		}
		decredPluginVotesCache[v.Token][v.Ticket] = struct{}{}
		g.Unlock()

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

	// Prepare reply
	var vrr decredplugin.VoteResultsReply

	// Fill out cast votes
	vrr.CastVotes, err = g.tallyVotes(vote.Token)
	if err != nil {
		return "", fmt.Errorf("Could not tally votes: %v", err)
	}

	// This portion is must run locked

	// git checkout master
	g.Lock()
	defer g.Unlock()

	if g.shutdown {
		return "", backend.ErrShutdown
	}
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
		decredplugin.MDStreamVoteBits)
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
	reply, err := decredplugin.EncodeVoteResultsReply(vrr)
	if err != nil {
		return "", fmt.Errorf("Could not encode VoteResultsReply: %v",
			err)
	}

	return string(reply), nil
}
