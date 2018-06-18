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
	decredPluginSettings map[string]string // [key]setting

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
	decredPluginCommentsUserCache = make(map[string]map[string]struct{})             // [token+pubkey][commentid]
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

func (g *gitBackEnd) propExists(repo, token string) bool {
	_, err := os.Stat(filepath.Join(repo, token))
	return err == nil
}

func (g *gitBackEnd) getNewCid(token string) (string, error) {
	dir := filepath.Join(g.journals, token)
	err := os.MkdirAll(dir, 0774)
	if err != nil {
		return "", err
	}

	filename := filepath.Join(dir, defaultCommentIDFilename)

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
		_, err = fh.Seek(0, os.SEEK_SET)
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

// pluginBestBlock returns current best block height from wallet.
func (g *gitBackEnd) pluginBestBlock() (string, error) {
	bb, err := bestBlock()
	if err != nil {
		return "", err
	}
	return strconv.FormatUint(uint64(bb.Height), 10), nil
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
	srcDir := filepath.Join(g.journals, token)
	srcComments := filepath.Join(srcDir, defaultCommentFilename)
	if !util.FileExists(srcComments) {
		return "", nil
	}

	// Setup destination filenames
	dir := filepath.Join(g.unvetted, token, pluginDataDir)
	comments := filepath.Join(dir, defaultCommentFilename)

	// Create the destination container dir
	_ = os.MkdirAll(dir, 0764)

	// Move journal and comment id into place
	err := g.journal.Copy(srcComments, comments)
	if err != nil {
		return "", err
	}

	// Return filename that is relative to git dir.
	return filepath.Join(token, pluginDataDir, defaultCommentFilename), nil
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
		filename := filepath.Join(g.journals, v.Name(),
			defaultCommentsFlushed)
		log.Tracef("Checking: %v", v.Name())
		if util.FileExists(filename) {
			continue
		}

		log.Infof("Flushing comments: %v", v.Name())

		// We simply copy the journal into git
		destination, err := g.flushComments(v.Name())
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
	srcDir := filepath.Join(g.journals, token)
	srcVotes := filepath.Join(srcDir, defaultBallotFilename)
	if !util.FileExists(srcVotes) {
		return "", nil
	}

	// Setup destination filenames
	dir := filepath.Join(g.unvetted, token, pluginDataDir)
	votes := filepath.Join(dir, defaultBallotFilename)

	// Create the destination container dir
	_ = os.MkdirAll(dir, 0764)

	// Move journal into place
	err := g.journal.Copy(srcVotes, votes)
	if err != nil {
		return "", err
	}

	// Return filename that is relative to git dir.
	return filepath.Join(token, pluginDataDir, defaultBallotFilename), nil
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
		filename := filepath.Join(g.journals, v.Name(),
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
	cfilename := filepath.Join(g.journals, comment.Token,
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

	// Mark comment journal dirty
	flushFilename := filepath.Join(g.journals, comment.Token,
		defaultCommentsFlushed)
	_ = os.Remove(flushFilename)

	// Cache comment
	g.Lock()
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

	// Mark comment journal dirty
	flushFilename := filepath.Join(g.journals, like.Token,
		defaultCommentsFlushed)
	_ = os.Remove(flushFilename)

	// Update counts
	g.Lock()

	// See if we need to replay the journal
	c, ok := decredPluginCommentsCache[like.Token][like.CommentID]
	if !ok {
		g.Unlock()
		_, err = g.replayComments(like.Token)
		if err != nil {
			return "", fmt.Errorf("could not replay journal %v: %v",
				like.Token, err)
		}
	}

	// Try again
	c, ok = decredPluginCommentsCache[like.Token][like.CommentID]
	if !ok {
		g.Unlock()
		return "", fmt.Errorf("comment not found %v:%v",
			like.Token, like.CommentID)
	}
	// See if this user has voted on this comment already
	key := like.Token + like.PublicKey
	if _, ok := decredPluginCommentsUserCache[key]; !ok {
		decredPluginCommentsUserCache[key] = make(map[string]struct{})
	}
	var new bool
	if _, ok = decredPluginCommentsUserCache[key][like.CommentID]; !ok {
		decredPluginCommentsUserCache[key][like.CommentID] = struct{}{}
		new = true
	}
	result := c.ResultVotes + action
	if result < -1 || result > 1 {
		g.Unlock()
		return replyLikeCommentReplyError(fmt.Errorf("can " +
			"only once vote up or down"))
	}

	// We create an unwind function that MUST be called from all error
	// paths. If everything works ok it is a no-op.
	cc := c
	unwind := func() {
		g.Lock()
		decredPluginCommentsCache[like.Token][like.CommentID] = cc
		g.Unlock()
	}

	// Update cache
	c.ResultVotes = result
	if new {
		c.TotalVotes++
	}
	decredPluginCommentsCache[like.Token][like.CommentID] = c

	g.Unlock()

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
	cfilename := filepath.Join(g.journals, like.Token,
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

func (g *gitBackEnd) replayComments(token string) (map[string]decredplugin.Comment, error) {
	// Verify proposal exists, we can run this lockless
	if !g.propExists(g.vetted, token) {
		return nil, nil
	}

	// Do some cheap things before expensive calls
	cfilename := filepath.Join(g.journals, token,
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
	seen := make(map[string]map[string]struct{})
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
				panic("not yet") // XXX add censor comment
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

				// Only update total if user has not voted yet
				key := lc.Token + lc.PublicKey
				if _, ok := seen[key]; !ok {
					seen[key] = make(map[string]struct{})
				}
				if _, ok := seen[key][lc.CommentID]; !ok {
					// Not seen before
					seen[key][lc.CommentID] = struct{}{}
					c.TotalVotes++
				}
				c.ResultVotes += action

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

func (g *gitBackEnd) pluginGetComments(payload string) (string, error) {
	// Decode comment
	gc, err := decredplugin.DecodeGetComments([]byte(payload))
	if err != nil {
		return "", fmt.Errorf("DecodeGetComments: %v", err)
	}

	g.Lock()
	if comments, ok := decredPluginCommentsCache[gc.Token]; ok {
		g.Unlock()
		return encodeGetCommentsReply(comments)
	}
	g.Unlock()

	comments, err := g.replayComments(gc.Token)
	if err != nil {
		return "", err
	}

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
	_, err1 := os.Stat(filepath.Join(g.vetted, token, fmt.Sprintf("%02v%v",
		decredplugin.MDStreamVoteBits, defaultMDFilenameSuffix)))
	_, err2 := os.Stat(filepath.Join(g.vetted, token, fmt.Sprintf("%02v%v",
		decredplugin.MDStreamVoteSnapshot, defaultMDFilenameSuffix)))
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
	bfilename := filepath.Join(g.journals, token,
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
	if ok {
		return true, nil
	}

	// See if we need to replay journal
	_, ok = decredPluginVotesCache[v.Token]
	if !ok {
		// Replay journal
		err := g.replayBallot(v.Token)
		if err != nil {
			return false, err
		}
	}

	// And try to see if the ticket exists
	_, ok = decredPluginVotesCache[v.Token][v.Ticket]

	// Vote + ticket doesn't exist
	return ok, nil
}

func (g *gitBackEnd) pluginBallot(payload string) (string, error) {
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
			log.Errorf("pluginBallot: voteExists %v %v %v",
				v.Token, t, err)
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
			log.Errorf("pluginBallot: validateVoteBit %v %v %v",
				v.Token, t, err)
			br.Receipts[k].Error = fmt.Sprintf("internal error %v",
				t)
			continue
		}

		// Verify that vote is signed correctly
		err = g.validateVote(v.Token, v.Ticket, v.VoteBit, v.Signature)
		if err != nil {
			t := time.Now().Unix()
			log.Errorf("pluginBallot: validateVote %v %v %v",
				v.Token, t, err)
			br.Receipts[k].Error = fmt.Sprintf("internal error %v",
				t)
			continue
		}
		br.Receipts[k].ClientSignature = v.Signature

		dir := filepath.Join(g.journals, v.Token)
		bfilename := filepath.Join(dir, defaultBallotFilename)
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
		flushFilename := filepath.Join(g.journals, v.Token,
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
	bfilename := filepath.Join(g.journals, token, defaultBallotFilename)

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
