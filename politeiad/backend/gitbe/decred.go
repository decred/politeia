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

	commentJournalVersion   = "1"   // Version 1 of the comment journal
	commentJournalActionAdd = "add" // Add comment
	commentJournalActionDel = "del" // Delete comment

	flushRecordVersion = "1" // Version 1 of the flush journal
)

// FlushRecord is a structure that is stored on disk when a journal has been
// flushed.
type FlushRecord struct {
	Version   string `json:"version"`   // Version
	Timestamp string `json:"timestamp"` // Timestamp
}

// CommentJournalAction prefixes and determines what the next structure is in
// the JSON journal.
// Version is used to determine what version of the comment journal structure
// follows.
// commentJournalActionAdd -> Comment
// commentJournalActionDel -> CensorComment
type CommentJournalAction struct {
	Version string `json:"version"` //Version
	Action  string `json:"action"`  // Add/Del
}

var (
	decredPluginSettings map[string]string // [key]setting

	// cached values, requires lock
	decredPluginVoteCache = make(map[string]*decredplugin.Vote) // [token]vote

	// Pregenerated journal actions
	commentJournalAdd []byte
	commentJournalDel []byte

	// Plugin specific data that is CANNOT be treated as metadata
	pluginDataDir = filepath.Join("plugins", "decred")
)

// init is used to pregenerate the JSON journal actions.
func init() {
	var err error

	commentJournalAdd, err = json.Marshal(CommentJournalAction{
		Version: commentJournalVersion,
		Action:  commentJournalActionAdd,
	})
	if err != nil {
		panic(err.Error())
	}
	commentJournalDel, err = json.Marshal(CommentJournalAction{
		Version: commentJournalVersion,
		Action:  commentJournalActionDel,
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
// Must be called WITH the mutex set.
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

// flushCommentflushes comments journal to decred plugin directory in
// git. It returns the filename that was coppied into git repo.
//
// Must be called WITH the mutex set.
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
// Must be called WITH the mutex set.
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

// flushCommentJournalsUnwind unwinds all the flushing action oif something
// goes wrong.
//
// Must be called WITH the mutex set.
func (g *gitBackEnd) flushCommentJournalsUnwind(id string) error {
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

// flushCommentJournals wraps _flushCommentJournals in git magic to revert
// flush in case of errors.
//
// Must be called WITHOUT the mutex set.
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
		err := g.flushCommentJournalsUnwind(branch)
		if err != nil {
			log.Errorf("flushCommentJournalsUnwind: %v", err)
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
		err = g.flushCommentJournalsUnwind(branch)
		if err != nil {
			log.Errorf("flushCommentJournalsUnwind: %v", err)
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

func (g *gitBackEnd) decredPluginJournalFlusher() {
	err := g.flushCommentJournals()
	if err != nil {
		log.Errorf("decredPluginJournalFlusher: %v", err)
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
	err = g.journal.Journal(cfilename, string(commentJournalAdd)+
		string(blob))
	if err != nil {
		return "", fmt.Errorf("could not journal %v: %v", c.Token, err)
	}

	// Mark comment journal dirty
	flushFilename := filepath.Join(g.journals, comment.Token,
		defaultCommentsFlushed)
	_ = os.Remove(flushFilename)

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

func (g *gitBackEnd) pluginGetComments(payload string) (string, error) {
	// Decode comment
	gc, err := decredplugin.DecodeGetComments([]byte(payload))
	if err != nil {
		return "", fmt.Errorf("DecodeGetComments: %v", err)
	}

	// Verify proposal exists, we can run this lockless
	if !g.propExists(g.vetted, gc.Token) {
		return encodeGetCommentsReply(nil)
	}

	// Do some cheap things before expensive calls
	cfilename := filepath.Join(g.journals, gc.Token,
		defaultCommentFilename)

	// Replay journal
	err = g.journal.Open(cfilename)
	if err != nil {
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("journal.Open: %v", err)
		}
		return encodeGetCommentsReply(nil)
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
			var action CommentJournalAction
			err = d.Decode(&action)
			if err != nil {
				return fmt.Errorf("journal action: %v", err)
			}

			switch action.Action {
			case commentJournalActionAdd:
				log.Errorf("+++++%v", s)
				var c decredplugin.Comment
				err = d.Decode(&c)
				if err != nil {
					return fmt.Errorf("journal add: %v",
						err)
				}
				comments[c.CommentID] = c
			case commentJournalActionDel:
				panic("not yet")
			default:
				return fmt.Errorf("invalid action: %v",
					action.Action)
			}
			return nil
		})
		if err == io.EOF {
			break
		} else if err != nil {
			return "", err
		}
	}

	return encodeGetCommentsReply(comments)
}

func (g *gitBackEnd) pluginStartVote(payload string) (string, error) {
	vote, err := decredplugin.DecodeVote([]byte(payload))
	if err != nil {
		return "", fmt.Errorf("DecodeVote %v", err)
	}

	// XXX verify vote bits are sane

	// Verify proposal exists
	if !g.propExists(g.vetted, vote.Token) {
		return "", fmt.Errorf("unknown proposal: %v", vote.Token)
	}

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

	// Make sure vote duration isn't too large. Assume < 2 weeks
	// XXX calculate this value for testnet instead of using hard coded values.
	if vote.Duration < 2016 || vote.Duration > 2016*2 {
		// XXX return a user error instead of an internal error
		return "", fmt.Errorf("invalid duration: %v (%v - %v)",
			vote.Duration, 2016, 2016*2)
	}

	svr := decredplugin.StartVoteReply{
		StartBlockHeight: strconv.FormatUint(uint64(snapshotBlock.Height),
			10),
		StartBlockHash: snapshotBlock.Hash,
		EndHeight: strconv.FormatUint(uint64(snapshotBlock.Height+
			vote.Duration), 10),
		EligibleTickets: snapshot,
	}
	svrb, err := decredplugin.EncodeStartVoteReply(svr)
	if err != nil {
		return "", fmt.Errorf("EncodeStartVoteReply: %v", err)
	}

	// Store snapshot in metadata
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

	g.Lock()
	defer g.Unlock()
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

func (g *gitBackEnd) _pluginCastVotes(payload string) (string, error) {
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
	g.Lock()
	defer g.Unlock()
	if g.shutdown {
		return "", backend.ErrShutdown
	}

	// XXX split out git commands so we can do a stash + stash drop if the operation fails

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
		index      int
		content    map[string]struct{} // [token+ticket]
	}
	files := make(map[string]*file)
	for _, v := range dedupVotes {
		// This loop must be exited in order to close all open file
		// handles.
		var f *file
		if f, ok = files[v.vote.Token]; !ok {
			// Lazily open files and recreate content
			filename := mdFilename(g.unvetted, v.vote.Token,
				decredplugin.MDStreamVotes)
			fh, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE,
				0666)
			if err != nil {
				t := time.Now().Unix()
				log.Errorf("pluginCastVotes: OpenFile %v %v %v",
					v.vote.Token, t, err)
				cbr[v.index].Error = fmt.Sprintf("internal error %v", t)
				continue
			}
			f = &file{
				fileHandle: fh,
				token:      v.vote.Token,
				mdFilename: strconv.FormatUint(uint64(decredplugin.MDStreamVotes),
					10) + defaultMDFilenameSuffix,
				index:   v.index,
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

					t := time.Now().Unix()
					log.Errorf("pluginCastVotes: Decode %v %v %v",
						v.vote.Token, t, err)
					cbr[v.index].Error = fmt.Sprintf("internal error %v", t)
					continue
				}
				cvs = append(cvs, cv)
			}

			// Recreate keys
			for _, vv := range cvs {
				key := vv.Token + vv.Ticket
				// Sanity
				if _, ok := f.content[key]; ok {
					t := time.Now().Unix()
					log.Errorf("pluginCastVotes: not found %v %v %v",
						key, t, err)
					cbr[v.index].Error = fmt.Sprintf("internal error %v", t)
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
			t := time.Now().Unix()
			log.Errorf("pluginCastVotes: Seek %v %v %v",
				v.vote.Token, t, err)
			cbr[v.index].Error = fmt.Sprintf("internal error %v", t)
			continue
		}
		e := json.NewEncoder(f.fileHandle)
		err = e.Encode(*v.vote)
		if err != nil {
			t := time.Now().Unix()
			log.Errorf("pluginCastVotes: Encode %v %v %v",
				v.vote.Token, t, err)
			cbr[v.index].Error = fmt.Sprintf("internal error %v", t)
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
			t := time.Now().Unix()
			log.Errorf("pluginCastVotes: gitAdd %v %v %v",
				v.token, t, err)
			cbr[v.index].Error = fmt.Sprintf("internal error %v", t)
			continue
		}
	}

	// If there are no changes DO NOT update the record and reply with no
	// changes.
	if g.gitHasChanges(g.unvetted) {
		// Commit change
		err = g.gitCommit(g.unvetted, "Update record metadata via plugin")
		if err != nil {
			return "", fmt.Errorf("Could not commit: %v", err)
		}

		// create and rebase PR
		err = g.rebasePR(idTmp)
		if err != nil {
			return "", fmt.Errorf("Could not rebase: %v", err)
		}
	}

	reply, err := decredplugin.EncodeCastVoteReplies(cbr)
	if err != nil {
		return "", fmt.Errorf("Could not encode CastVoteReply %v", err)
	}

	return string(reply), nil
}

func (g *gitBackEnd) pluginCastVotes(payload string) (string, error) {
	return "", fmt.Errorf("boom")
}

func (g *gitBackEnd) pluginProposalVotes(payload string) (string, error) {
	log.Tracef("pluginProposalVotes: %v", payload)

	vote, err := decredplugin.DecodeVoteResults([]byte(payload))
	if err != nil {
		return "", fmt.Errorf("DecodeVoteResults %v", err)
	}

	// Lock tree while we pull out the results
	g.Lock()
	defer g.Unlock()
	if g.shutdown {
		return "", backend.ErrShutdown
	}

	// git checkout master
	err = g.gitCheckout(g.vetted, "master")
	if err != nil {
		return "", err
	}

	// Verify proposal exists
	// XXX should we return a NOT FOUND error here instead of percolating a
	// 500 to the user?
	if !g.propExists(g.vetted, vote.Token) {
		return "", fmt.Errorf("unknown proposal: %v", vote.Token)
	}

	// Prepare reply
	vrr := decredplugin.VoteResultsReply{
		CastVotes: make([]decredplugin.CastVote, 0, 41000),
	}

	var (
		d, dd *json.Decoder
		f, ff *os.File
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

	err = dd.Decode(&vrr.Vote)
	if err != nil {
		if err == io.EOF {
			goto nodata
		}
		return "", err
	}

	// Fill out cast votes
	filename = mdFilename(g.vetted, vote.Token, decredplugin.MDStreamVotes)
	f, err = os.Open(filename)
	if err != nil {
		if os.IsNotExist(err) {
			goto nodata
		}
		return "", err
	}
	defer f.Close()
	d = json.NewDecoder(f)

	for {
		var cv decredplugin.CastVote
		err = d.Decode(&cv)
		if err != nil {
			if err == io.EOF {
				break
			}
			return "", err
		}

		vrr.CastVotes = append(vrr.CastVotes, cv)
	}

nodata:
	reply, err := decredplugin.EncodeVoteResultsReply(vrr)
	if err != nil {
		return "", fmt.Errorf("Could not encode VoteResultsReply %v",
			err)
	}

	return string(reply), nil
}
