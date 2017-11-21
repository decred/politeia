package gitbe

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/decred/dcrtime/api/v1"
	"github.com/decred/dcrtime/merkle"
	pd "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/api/v1/mime"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/util"
	"github.com/marcopeereboom/lockfile"
	"github.com/robfig/cron"
	"github.com/syndtr/goleveldb/leveldb"
)

const (
	// Lockfile is the filesystem lock filename.  Export for external utilities.
	LockFilename = ".lock"

	// LockDuration is the maximum lock time duration allowed.  15 seconds
	// is ~3x of anchoring without internet delay.
	LockDuration = 15 * time.Second

	// DefaultDbPath is the database path.  Export for external utilities.
	DefaultDbPath = "db"

	// defaultUnvettedPath is the landing zone for unvetted content.
	defaultUnvettedPath = "unvetted"

	// defaultVettedPath is the publicly visible git vetted proposal repo.
	defaultVettedPath = "vetted"

	// defaultProposalStorageRecordFilename is the filename of the proposal
	// metadata record.
	defaultProposalStorageRecordFilename = "psr.json"

	// defaultAuditTrailFile is the filename where a human readable audit
	// trail is kept.
	defaultAuditTrailFile = "anchor_audit_trail.txt"

	// defaultAnchorsDirectory is the directory where anchors are stored.
	// They are indexed by TX.
	defaultAnchorsDirectory = "anchors"

	// defaultPayloadDir is the default path to store a proposal payload.
	defaultPayloadDir = "payload"

	// anchorSchedule determines how often we anchor the vetted repo.
	// Seconds Minutes Hours Days Months DayOfWeek
	anchorSchedule = "0 58 * * * *" // At 58 minutes every hour

	// expectedTestTX is a fake TX used by unit tests.
	expectedTestTX = "TESTTX"
)

var (
	_ backend.Backend = (*gitBackEnd)(nil)

	defaultRepoConfig = map[string]string{
		// This prevents git from converting CRLF when committing and checking
		// out files, which helps when running on Windows.
		"core.autocrlf": "false",
	}

	errNothingToDo = errors.New("nothing to do")
)

// file is an internal representation of a file that resides in memory.
type file struct {
	name    string // Basename of the file
	digest  []byte // SHA256 of payload
	payload []byte // Actual file payload
}

// gitBackEnd is a git based backend context that satisfies the backend
// interface.
type gitBackEnd struct {
	lock        *lockfile.LockFile // Global lock
	db          *leveldb.DB        // Database
	cron        *cron.Cron         // Scheduler for periodic tasks
	shutdown    bool               // Backend is shutdown
	root        string             // Root directory
	unvetted    string             // Unvettend content
	vetted      string             // Vetted, public, visible content
	dcrtimeHost string             // Dcrtimed directory
	gitPath     string             // Path to git
	gitTrace    bool               // Enable git tracing
	test        bool               // Set during UT
	exit        chan struct{}      // Close channel
	checkAnchor chan struct{}      // Work notification

	// The following items are used for testing only
	testAnchors map[string]bool // [digest]anchored
}

// extendSHA1 appends 0 to make a SHA1 the size of a SHA256 digest.
func extendSHA1(d []byte) []byte {
	if len(d) != sha1.Size {
		panic("invalid sha1 length")
	}
	digest := make([]byte, sha256.Size)
	copy(digest, d)
	return digest
}

// unextendSHA1ToSha256 removes 0 to make a SHA256 the size of a SHA1 digest.
func unextendSHA256(d []byte) []byte {
	if len(d) != sha256.Size {
		panic("invalid sha256 length")
	}
	// make sure this was an extended digest
	for _, x := range d[sha1.Size:] {
		if x != 0 {
			panic("invalid extended sha256")
		}
	}
	digest := make([]byte, sha1.Size)
	copy(digest, d)
	return digest
}

// extendSHA1FromString takes a string and ensures it is a digest and then
// extends it using extendSHA1.  It returns a string representation of the
// digest.
func extendSHA1FromString(s string) (string, error) {
	ds, err := hex.DecodeString(s)
	if err != nil {
		return "", fmt.Errorf("not hex: %v", s)
	}
	d := extendSHA1(ds)
	return hex.EncodeToString(d), nil
}

// newUniqueID returns a new unique proposal ID.  The function will hold the
// unvettedLock if successful.  The callee is responsible for releasing the
// lock.
//
// This function must be called without holding the unvetted lock.
func (g *gitBackEnd) newUniqueID() (uint64, error) {
	err := g.lock.Lock(LockDuration)
	if err != nil {
		return 0, err
	}

	// Get Dirs.
	files, err := ioutil.ReadDir(g.unvetted)
	if err != nil {
		return 0, err
	}

	// Find biggest proposal ID
	var last uint64
	for _, file := range files {
		// This check ignores lockFilename as well
		if !file.IsDir() {
			continue
		}
		p, err := strconv.ParseUint(file.Name(), 10, 64)
		if err != nil {
			continue
		}
		if p > last {
			last = p
		}
	}
	id := last + 1

	// Create directory
	err = os.MkdirAll(filepath.Join(g.unvetted, strconv.FormatUint(id, 10)),
		0764)
	if err != nil {
		return 0, err
	}

	return id, nil
}

// verifyContent verifies that all provided backend.File are sane and returns a
// cooked array of the files.
func verifyContent(files []backend.File) ([]file, error) {
	fa := make([]file, 0, len(files))
	for i := range files {
		// Validate digest
		d, ok := util.ConvertDigest(files[i].Digest)
		if !ok {
			return nil, backend.ContentVerificationError{
				ErrorCode: pd.ErrorStatusInvalidFileDigest,
				ErrorContext: []string{
					files[i].Name,
				},
			}
		}

		// Setup cooked file.
		f := file{
			name: files[i].Name,
		}

		// Decode base64 payload
		var err error
		f.payload, err = base64.StdEncoding.DecodeString(files[i].Payload)
		if err != nil {
			return nil, backend.ContentVerificationError{
				ErrorCode: pd.ErrorStatusInvalidBase64,
				ErrorContext: []string{
					files[i].Name,
				},
			}
		}

		// Calculate payload digest
		dp := util.Digest(f.payload)
		if !bytes.Equal(d[:], dp) {
			return nil, backend.ContentVerificationError{
				ErrorCode: pd.ErrorStatusInvalidFileDigest,
				ErrorContext: []string{
					files[i].Name,
				},
			}
		}
		f.digest = dp

		// Verify MIME
		detectedMIMEType := http.DetectContentType(f.payload)
		if detectedMIMEType != files[i].MIME {
			return nil, backend.ContentVerificationError{
				ErrorCode: pd.ErrorStatusInvalidMIMEType,
				ErrorContext: []string{
					files[i].Name,
					detectedMIMEType,
				},
			}
		}
		if !mime.MimeValid(files[i].MIME) {
			return nil, backend.ContentVerificationError{
				ErrorCode: pd.ErrorStatusUnsupportedMIMEType,
				ErrorContext: []string{
					files[i].Name,
					files[i].MIME,
				},
			}
		}

		fa = append(fa, f)
	}

	return fa, nil
}

// loadProposal loads an entire proposal of disk.  It returns an array of
// backend.File that is completely filled out.
//
// This function must be called with the lock held.
func loadProposal(path, id string) ([]backend.File, error) {
	// Get dir.
	propDir := filepath.Join(path, id, defaultPayloadDir)
	files, err := ioutil.ReadDir(propDir)
	if err != nil {
		return nil, err
	}

	bf := make([]backend.File, 0, len(files))
	// Load all files
	for _, file := range files {
		fn := filepath.Join(propDir, file.Name())
		if file.IsDir() {
			return nil, fmt.Errorf("proposal corrupt: %v", path)
		}

		f := backend.File{Name: file.Name()}
		f.MIME, f.Digest, f.Payload, err = util.LoadFile(fn)
		if err != nil {
			return nil, err
		}
		bf = append(bf, f)
	}

	return bf, nil
}

// loadPSR loads a ProposalStorageRecord from the provided path/id.  This may
// be unvetted/id or vetted/id.
//
// This function should be called with the lock held.
func loadPSR(path, id string) (*backend.ProposalStorageRecord, error) {
	filename := filepath.Join(path, id,
		defaultProposalStorageRecordFilename)
	f, err := os.Open(filename)
	if err != nil {
		if os.IsNotExist(err) {
			err = backend.ErrProposalNotFound
		}
		return nil, err
	}
	defer f.Close()

	var psr backend.ProposalStorageRecord
	decoder := json.NewDecoder(f)
	if err = decoder.Decode(&psr); err != nil {
		return nil, err
	}
	return &psr, nil
}

// createPSR stores a ProposalStorageRecord to the provided path/id.  This may be
// unvetted/id or vetted/id.
//
// This function should be called with the lock held.
func createPSR(path, id string, status backend.PSRStatusT, version uint, hashes []*[sha256.Size]byte, token []byte) (*backend.ProposalStorageRecord, error) {
	// Create proposal storage record
	psr := backend.ProposalStorageRecord{
		Version:   version,
		Status:    status,
		Merkle:    *merkle.Root(hashes),
		Timestamp: time.Now().Unix(),
		Token:     token,
	}

	err := updatePSR(path, id, &psr)
	if err != nil {
		return nil, err
	}

	return &psr, nil
}

// updatePSR updates the ProposalStorageRecord status to the provided path/id.
//
// This function should be called with the lock held.
func updatePSR(path, id string, psr *backend.ProposalStorageRecord) error {
	// Store proposal record.
	filename := filepath.Join(path, id, defaultProposalStorageRecordFilename)
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	return json.NewEncoder(f).Encode(*psr)
}

// commitPSR commits the PSR into a git repo.
//
// This function should be called with the lock held.
func (g *gitBackEnd) commitPSR(path, id, msg string) error {
	// git add id/psr.json
	filename := filepath.Join(path, id,
		defaultProposalStorageRecordFilename)
	err := g.gitAdd(path, filename)
	if err != nil {
		return err
	}

	// git commit -m "message"
	return g.gitCommit(path, "Update proposal status "+id+" "+msg)
}

// deltaCommits returns sha1 extended digests and one line commit messages to
// the caller.  If lastAnchor is empty then the range is from the dawn of time
// until now.  If lastAnchor is a valid hash the range is from lastAnchor up
// until no.
//
// This function should be called with the lock held.
func (g *gitBackEnd) deltaCommits(path string, lastAnchor []byte) ([]*[sha256.Size]byte, []string, []string, error) {
	// Sanity
	if !(len(lastAnchor) == 0 || len(lastAnchor) == sha256.Size) {
		return nil, nil, nil, fmt.Errorf("invalid digest size")
	}

	// Minimal git arguments
	args := []string{"log", "--pretty=oneline"}

	// Determine digest range
	latestCommit, err := g.gitLastDigest(path)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(lastAnchor) != 0 {
		// git log lastAnchor..latestCommit --pretty=oneline
		sha1LastAnchor := unextendSHA256(lastAnchor)
		if bytes.Equal(sha1LastAnchor, latestCommit) {
			return nil, nil, nil, errNothingToDo
		}
		args = append(args, hex.EncodeToString(sha1LastAnchor)+".."+
			hex.EncodeToString(latestCommit))
	}

	// Execute git
	out, err := g.git(path, args...)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(out) == 0 {
		return nil, nil, nil, fmt.Errorf("invalid git output")
	}

	// Generate return data
	digests := make([]*[sha256.Size]byte, 0, len(out))
	commitMessages := make([]string, 0, len(out))
	for _, line := range out {
		// Returned data is "<digest> <commit message>"
		ds := strings.SplitN(line, " ", 2)
		if len(ds) == 0 {
			return nil, nil, nil, fmt.Errorf("invalid log")
		}

		// Validate returned digest
		sha1Digest, err := hex.DecodeString(ds[0])
		if err != nil {
			return nil, nil, nil, err
		}
		if len(sha1Digest) != sha1.Size {
			return nil, nil, nil, fmt.Errorf("invalid sha1 size")
		}
		sha256DigestB := extendSHA1(sha1Digest)
		var sha256Digest [sha256.Size]byte
		copy(sha256Digest[:], sha256DigestB)

		// Fill out return values
		digests = append(digests, &sha256Digest)
		commitMessages = append(commitMessages, ds[1])
	}

	return digests, commitMessages, out, nil
}

// anchor takes a slice of commit digests and commit messages that are stored
// in the local database once they are anchored in dcrtime.
//
// This function is being clever with the anchors.  It sends two values to
// dcrtime.  The idea is that we anchor the merkle root of the provided set and
// that is stored in the db.  The cleverness comes in that we *also* anchor all
// individual commit hashes.  We do the last bit in order to be able to
// externally validate that a commit hash made it into the time stamp.  If we
// don't do that we'd have to create a tool to verify individual hashes for the
// truly curious.  This is essentially free because dcrtime compresses all
// digests into a single merkle root.
//
// This function should be called with the lock held.
// TODO: the physical write to dcrtime needs to come out of the lock.
func (g *gitBackEnd) anchor(digests []*[sha256.Size]byte) error {
	// Anchor all digests
	if g.test {
		// We always append the anchorKey as the last element
		x := len(digests) - 1
		g.testAnchors[hex.EncodeToString(digests[x][:])] = false
		return nil
	}

	return util.Timestamp(g.dcrtimeHost, digests)
}

// appendAuditTrail adds a record to the audit trail.
func (g *gitBackEnd) appendAuditTrail(path string, ts int64, merkle [sha256.Size]byte, lines []string) error {
	f, err := os.OpenFile(filepath.Join(path, defaultAuditTrailFile),
		os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	fmt.Fprintf(f, "%v: --- Audit Trail Record %x ---\n", ts, merkle)
	for _, line := range lines {
		fmt.Fprintf(f, "%v: %v\n", ts, strings.Trim(line, " \t\n"))
	}

	return nil
}

// anchorRepo drops an anchor for an individual repo.
// It prints the basename during its actions.
//
// This function should be called with the lock held.
func (g *gitBackEnd) anchorRepo(path string) (*[sha256.Size]byte, error) {
	// Make sure we have a repo we understand
	repo := filepath.Base(path)

	// Fsck
	log.Infof("Running git fsck on %v repository", repo)
	err := g.gitCheckout(path, "master")
	if err != nil {
		return nil, fmt.Errorf("anchor checkout master %v: %v", repo,
			err)
	}
	_, err = g.gitFsck(path)
	if err != nil {
		return nil, fmt.Errorf("anchor fsck master %v: %v", repo, err)
	}

	// Check for unanchored commits
	last, err := g.readLastAnchorRecord()
	if err != nil {
		return nil, fmt.Errorf("could not find last %v digest: %v", repo,
			err)
	}

	// Fill out unvetted digests
	digests, messages, _, err := g.deltaCommits(path, last.Last)
	if err != nil {
		if err == errNothingToDo {
			return nil, err
		}
		return nil, fmt.Errorf("could not determine delta %v: %v",
			repo, err)
	}
	if len(digests) != len(messages) {
		// Really can't happen
		return nil, fmt.Errorf("invalid digests(%v)/messages(%v) count",
			len(digests), len(messages))
	}

	// Create commit message BEFORE calling anchor.  anchor calls
	// merkle.Root which in turn sorts the digests and that is fine but not
	// what we want to display to the user.
	commitMessage := ""
	auditLines := make([]string, 0, len(digests))
	for k, digest := range digests {
		line := fmt.Sprintf("%x %v\n", *digest, messages[k])
		commitMessage += line
		auditLines = append(auditLines, line)
	}

	// Create database record early for the same reason.
	anchorRecord, anchorKey, err := newAnchorRecord(AnchorUnverified,
		digests, messages)
	if err != nil {
		return nil, fmt.Errorf("newAnchorRecord: %v", err)
	}

	// Append MerkleRoot to digests.  We have to do this since this is
	// politeia's lookup key but dcrtime will likely return a different
	// merkle.  Dcrtime returns a different merkle when there are
	// additional digests in the set.
	digests = append(digests, anchorKey)

	// Anchor commits
	log.Infof("Anchoring %v repository", repo)
	err = g.anchor(digests)
	if err != nil {
		return nil, fmt.Errorf("anchor: %v", err)
	}

	// Prefix commitMessage with merkle root
	commitMessage = fmt.Sprintf("Anchor %x\n\n%v", *anchorKey,
		commitMessage)

	// Commit merkle root as an anchor and append included commits to audit
	// trail
	err = g.appendAuditTrail(path, anchorRecord.Time, *anchorKey,
		auditLines)
	if err != nil {
		return nil, fmt.Errorf("could not append to audit trail: %v",
			err)
	}
	err = g.gitAdd(path, defaultAuditTrailFile)
	if err != nil {
		return nil, fmt.Errorf("gitAdd: %v", err)
	}
	err = g.gitCommit(path, commitMessage)
	if err != nil {
		return nil, fmt.Errorf("gitCommit: %v", err)
	}

	// git commit can't return the long digest.
	gitLastCommitDigest, err := g.gitLastDigest(path)
	if err != nil {
		return nil, fmt.Errorf("gitLastDigest: %v", err)
	}

	// Commit anchor to database
	err = g.writeAnchorRecord(*anchorKey, *anchorRecord)
	if err != nil {
		return nil, fmt.Errorf("writeAnchorRecord: %v", err)
	}

	// Commit LastAnchor to database
	mr := make([]byte, sha256.Size)
	copy(mr, anchorKey[:])
	la := LastAnchor{
		Last:   extendSHA1(gitLastCommitDigest),
		Time:   anchorRecord.Time,
		Merkle: mr,
	}
	err = g.writeLastAnchorRecord(la)
	if err != nil {
		return nil, fmt.Errorf("writeLastAnchorRecord: %v", err)
	}

	// Append merkle to unconfirmed anchor record
	ua, err := g.readUnconfirmedAnchorRecord()
	if err != nil {
		return nil, err
	}
	ua.Merkles = append(ua.Merkles, mr)
	err = g.writeUnconfirmedAnchorRecord(*ua)
	if err != nil {
		return nil, fmt.Errorf("writeUnconfirmedAnchorRecord: %v", err)
	}

	return anchorKey, nil
}

// anchor verifies if there are new commits in all repos and if that is the
// case it drops and anchor in dcrtime for each of them.
func (g *gitBackEnd) anchorAllRepos() error {
	log.Infof("Dropping anchor")
	// Lock filesystem
	err := g.lock.Lock(LockDuration)
	if err != nil {
		return fmt.Errorf("anchorAllRepos lock error: %v", err)
	}
	defer func() {
		err := g.lock.Unlock()
		if err != nil {
			log.Errorf("anchorAllRepos unlock error: %v", err)
		}
	}()
	if g.shutdown {
		return fmt.Errorf("anchorAllRepos: %v", backend.ErrShutdown)
	}

	//  Anchor vetted
	log.Infof("Anchoring %v", g.vetted)
	mr, err := g.anchorRepo(g.vetted)
	if err != nil {
		if err == errNothingToDo {
			log.Infof("Anchoring %v: nothing to do", g.vetted)
			return nil
		}
		return fmt.Errorf("anchor repo %v: %v", g.vetted, err)
	}

	// Sync vetted to unvetted

	// git pull --ff-only --rebase
	err = g.gitPull(g.unvetted, true)
	if err != nil {
		return err
	}

	log.Infof("Dropping anchor complete: %x", *mr)

	return nil
}

// periodicAnchorChecker must be run as a go routine.  It sits around and
// periodically checks if there is work to do.  It can also be tickled by
// messaging checkAnchor.
func (g *gitBackEnd) periodicAnchorChecker() {
	log.Infof("Periodic anchor checker launched")
	defer log.Infof("Periodic anchor checker exited")
	for {
		select {
		case <-g.exit:
			return
		case <-g.checkAnchor:
		case <-time.After(5 * time.Minute):
		}

		if g.shutdown {
			return
		}

		// Do lengthy work, this may have to be its own go routine
		err := g.anchorChecker()
		if err != nil {
			// Not much we can do past logging
			log.Errorf("periodicAnchorChecker: %v", err)
		}
	}
}

// anchorChecker does the work for periodicAnchorChecker.  It lives in its own
// function for testing purposes.
func (g *gitBackEnd) anchorChecker() error {
	// Get work, requires lock
	ua, err := g.safeReadUnconfirmedAnchorRecord()
	if err != nil {
		return fmt.Errorf("anchorChecker read: %v", err)
	}

	// Check for work
	if len(ua.Merkles) == 0 {
		return nil
	}

	// Do one verify at a time for now
	vrs := make([]v1.VerifyDigest, 0, len(ua.Merkles))
	precious := make([][]byte, 0, len(ua.Merkles))
	for _, u := range ua.Merkles {
		digest := hex.EncodeToString(u)
		vr, err := g.verifyAnchor(digest)
		if err != nil {
			precious = append(precious, u)
			log.Errorf("anchorChecker verify: %v", err)
			continue
		}
		vrs = append(vrs, *vr)
	}

	err = g.afterAnchorVerify(vrs, precious)
	if err != nil {
		return fmt.Errorf("afterAnchorVerify: %v", err)
	}

	return nil
}

// afterAnchorVerify completes the anchor verification process.  It is a
// separate function in order not having to futz with locks.
func (g *gitBackEnd) afterAnchorVerify(vrs []v1.VerifyDigest, precious [][]byte) error {
	// Lock filesystem
	err := g.lock.Lock(LockDuration)
	if err != nil {
		return err
	}
	defer func() {
		err := g.lock.Unlock()
		if err != nil {
			log.Errorf("afterAnchorVerify unlock error: %v", err)
		}
	}()

	if len(vrs) != 0 {
		// git checkout master
		err = g.gitCheckout(g.vetted, "master")
		if err != nil {
			return err
		}
	}
	// Handle verified vrs
	var commitMsg string
	for _, vr := range vrs {
		if vr.ChainInformation.ChainTimestamp == 0 {
			// dcrtime returns 0 when there are not enough
			// confirmations yet.
			return fmt.Errorf("not enough confirmations: %v",
				vr.Digest)
		}

		// Use the audit trail as the file to be committed
		mr, ok := util.ConvertDigest(vr.Digest)
		if !ok {
			return fmt.Errorf("invalid digest: %v", vr.Digest)
		}
		line := fmt.Sprintf("%v anchored in TX %v", vr.Digest,
			vr.ChainInformation.Transaction)
		commitMsg += line + "\n"
		err = g.appendAuditTrail(g.vetted,
			vr.ChainInformation.ChainTimestamp, mr, []string{line})
		if err != nil {
			return err
		}

		// Store dcrtime information.
		// In vetted store the ChainInformation as a json object in
		// directory anchor.
		// In Vetted in the proposal directory add a file called anchor
		// that points to the TX id.
		anchorDir := filepath.Join(g.vetted, defaultAnchorsDirectory)
		err = os.MkdirAll(anchorDir, 0764)
		if err != nil {
			return err
		}
		ar, err := json.Marshal(vr.ChainInformation)
		if err != nil {
			return err
		}
		err = ioutil.WriteFile(filepath.Join(anchorDir, vr.Digest),
			ar, 0444)
		if err != nil {
			return err
		}
		err = g.gitAdd(g.vetted,
			filepath.Join(defaultAnchorsDirectory, vr.Digest))
		if err != nil {
			return err
		}

		// Update database with dcrtime information
		var d [sha256.Size]byte
		dd, err := hex.DecodeString(vr.Digest)
		if err != nil {
			return err
		}
		copy(d[:], dd)
		anchor, err := g.readAnchorRecord(d)
		if err != nil {
			return err
		}
		anchor.Type = AnchorVerified
		anchor.ChainTimestamp = vr.ChainInformation.ChainTimestamp
		anchor.Transaction = vr.ChainInformation.Transaction
		err = g.writeAnchorRecord(d, *anchor)
		if err != nil {
			return err
		}

		// Mark test anchors as confirmed by dcrtime
		if g.test {
			g.testAnchors[vr.Digest] = true
		}
	}
	if len(vrs) != 0 {
		err = g.gitAdd(g.vetted, defaultAuditTrailFile)
		if err != nil {
			return err
		}
		// git commit anchor confirmation
		err = g.gitCommit(g.vetted, "Anchor confirmation\n\n"+commitMsg)
		if err != nil {
			return err
		}

		// git checkout master unvetted
		err = g.gitCheckout(g.unvetted, "master")
		if err != nil {
			return err
		}

		// git pull --ff-only --rebase
		err = g.gitPull(g.unvetted, true)
		if err != nil {
			return err
		}

		// Update last anchor record so that we skip anchoring anchor
		// commits
		// git commit can't return the long digest.
		gitLastCommitDigest, err := g.gitLastDigest(g.vetted)
		if err != nil {
			return fmt.Errorf("gitLastDigest: %v", err)
		}
		// Commit LastAnchor to database
		la := LastAnchor{
			Last: extendSHA1(gitLastCommitDigest),
			Time: time.Now().Unix(),
		}
		err = g.writeLastAnchorRecord(la)
		if err != nil {
			return fmt.Errorf("writeLastAnchorRecord: %v", err)
		}
	}

	// Update database record
	ua := UnconfirmedAnchor{Merkles: precious}
	return g.writeUnconfirmedAnchorRecord(ua)
}

// safeReadUnconfirmedAnchorRecord is a wrapper around
// readUnconfirmedAnchorRecord that handles locking.
func (g *gitBackEnd) safeReadUnconfirmedAnchorRecord() (*UnconfirmedAnchor, error) {
	// Lock filesystem
	err := g.lock.Lock(LockDuration)
	if err != nil {
		return nil, err
	}
	defer func() {
		err := g.lock.Unlock()
		if err != nil {
			log.Errorf("safeReadUnconfirmedAnchorRecord unlock "+
				"error: %v", err)
		}
	}()

	return g.readUnconfirmedAnchorRecord()
}

// anchorAllReposCronJob is the cron job that anchors all repos at a preset time.
func (g *gitBackEnd) anchorAllReposCronJob() {
	err := g.anchorAllRepos()
	if err != nil {
		log.Errorf("%v", err)
	}
}

// verifyAnchor asks dcrtime if an anchor has been verified and returns a TX if
// it has.
func (g *gitBackEnd) verifyAnchor(digest string) (*v1.VerifyDigest, error) {
	var (
		vr  *v1.VerifyReply
		err error
	)

	// In test mode we fake success.
	if g.test {
		// Fake success
		vr = &v1.VerifyReply{}
		anchored, ok := g.testAnchors[digest]
		if !ok {
			return nil, fmt.Errorf("test not found")
		}
		if anchored {
			return nil, fmt.Errorf("already anchored")
		}
		vr.Digests = append(vr.Digests, v1.VerifyDigest{
			Digest: digest,
			Result: v1.ResultOK,
			ChainInformation: v1.ChainInformation{
				ChainTimestamp: time.Now().Unix(),
				Transaction:    expectedTestTX,
			},
		})
	} else {
		// Call dcrtime
		vr, err = util.Verify(g.dcrtimeHost, []string{digest})
		if err != nil {
			return nil, err
		}
	}

	// Do some sanity checks
	if len(vr.Digests) != 1 {
		return nil, fmt.Errorf("unexpected number of digests")
	}
	if vr.Digests[0].Result != v1.ResultOK {
		return nil, fmt.Errorf("unexpected result: %v",
			vr.Digests[0].Result)
	}

	return &vr.Digests[0], nil
}

// New takes a proposal verifies it and drops it on disk in the unvetted
// directory.  Proposals and metadata are stored in unvetted/token/.  the
// function returns a ProposaltorageRecord.
//
// New satisfies the backend interface.
func (g *gitBackEnd) New(files []backend.File) (*backend.ProposalStorageRecord, error) {
	fa, err := verifyContent(files)
	if err != nil {
		return nil, err
	}

	if len(fa) == 0 {
		return nil, fmt.Errorf("empty proposal")
	}

	// Prevent duplicate filenames
	for i := range files {
		for j := range files {
			if i == j {
				continue
			}
			if files[i].Name == files[j].Name {
				return nil, fmt.Errorf("duplicate filename %v",
					files[i].Name)
			}
		}
	}

	// Create a censorship token.
	token, err := util.Random(32)
	if err != nil {
		return nil, err
	}
	id := hex.EncodeToString(token)

	// Lock filesystem
	err = g.lock.Lock(LockDuration)
	if err != nil {
		return nil, err
	}
	defer func() {
		// XXX add git unwind in here too
		err := g.lock.Unlock()
		if err != nil {
			log.Errorf("Unlock error: %v", err)
		}
	}()
	if g.shutdown {
		return nil, backend.ErrShutdown
	}

	// git checkout master
	err = g.gitCheckout(g.unvetted, "master")
	if err != nil {
		return nil, err
	}

	// git pull --ff-only --rebase
	err = g.gitPull(g.unvetted, true)
	if err != nil {
		return nil, err
	}

	// git checkout -b id
	err = g.gitNewBranch(g.unvetted, id)
	if err != nil {
		return nil, err
	}

	// Process files.
	path := filepath.Join(g.unvetted, id, defaultPayloadDir)
	err = os.MkdirAll(path, 0764)
	if err != nil {
		return nil, err
	}

	hashes := make([]*[sha256.Size]byte, 0, len(fa))
	for i := range fa {
		// Copy files into directory id/payload/filename.
		filename := filepath.Join(path, fa[i].name)
		err = ioutil.WriteFile(filename, fa[i].payload, 0444)
		if err != nil {
			return nil, err
		}
		var d [sha256.Size]byte
		copy(d[:], fa[i].digest)
		hashes = append(hashes, &d)

		// git add id/payload/filename
		err = g.gitAdd(g.unvetted, filename)
		if err != nil {
			return nil, err
		}

	}

	// Save Proposal Storage Record
	psr, err := createPSR(g.unvetted, id, backend.PSRStatusUnvetted, 1,
		hashes, token)
	if err != nil {
		return nil, err
	}

	// git add id/psr.json
	filename := filepath.Join(g.unvetted, id,
		defaultProposalStorageRecordFilename)
	err = g.gitAdd(g.unvetted, filename)
	if err != nil {
		return nil, err
	}

	// git commit -m "message"
	err = g.gitCommit(path, "Add proposal "+id)
	if err != nil {
		return nil, err
	}

	// git checkout master
	err = g.gitCheckout(g.unvetted, "master")
	if err != nil {
		return nil, err
	}

	return psr, nil
}

// getProposalLock is the generic implementation of GetUnvetted/GetVetted.  It
// returns a proposal record from the provided repo.
//
// This function must be called WITHOUT the lock held.
func (g *gitBackEnd) getProposalLock(token []byte, repo string, includeFiles bool) (*backend.ProposalRecord, error) {
	// Lock filesystem
	err := g.lock.Lock(LockDuration)
	if err != nil {
		return nil, err
	}
	defer func() {
		err := g.lock.Unlock()
		if err != nil {
			log.Errorf("Unlock error: %v", err)
		}
	}()
	if g.shutdown {
		return nil, backend.ErrShutdown
	}

	return g.getProposal(token, repo, includeFiles)
}

// getProposal is the generic implementation of GetUnvetted/GetVetted.  It
// returns a proposal record from the provided repo.
//
// This function must be called WITH the lock held.
func (g *gitBackEnd) getProposal(token []byte, repo string, includeFiles bool) (*backend.ProposalRecord, error) {
	id := hex.EncodeToString(token)
	if repo == g.unvetted {
		// git checkout id
		err := g.gitCheckout(repo, id)
		if err != nil {
			return nil, backend.ErrProposalNotFound
		}
	}
	defer func() {
		// git checkout master
		err := g.gitCheckout(repo, "master")
		if err != nil {
			log.Errorf("could not switch to master: %v", err)
		}
	}()

	// load PSR
	psr, err := loadPSR(repo, id)
	if err != nil {
		return nil, err
	}

	var files []backend.File
	if includeFiles {
		// load files
		files, err = loadProposal(repo, id)
		if err != nil {
			return nil, err
		}
	}

	return &backend.ProposalRecord{
		ProposalStorageRecord: *psr,
		Files: files,
	}, nil
}

// fsck performs a git fsck and additionally it validates the git tree against
// dcrtime.  This is an expensive operation and should not be run during
// runtime.
//
// This function must be called WITH holding the lock.
func (g *gitBackEnd) fsck(path string) error {
	// obtain all commit digests and verify them.  We don't store anchor
	// confirmations so we have to skip those.
	out, err := g.git(path, "log", "--pretty=oneline")
	if err != nil {
		return err
	}
	if len(out) == 0 {
		return fmt.Errorf("invalid git output")
	}

	// Create an index of all git digests
	gitDigests := make(map[string]struct{})
	for _, v := range out {
		// Skip anchor commits, this simplifies reconcile process.
		if strings.Contains(v, "Anchor") {
			continue
		}
		// git output is digest followed by one liner commit message
		s := strings.SplitN(v, " ", 2)
		if len(s) != 2 {
			log.Infof("%v", spew.Sdump(s))
			return fmt.Errorf("unexpected split: %v", v)
		}
		ds, err := extendSHA1FromString(s[0])
		if err != nil {
			return fmt.Errorf("not a digest: %v", v)
		}
		if _, ok := gitDigests[ds]; ok {
			return fmt.Errorf("duplicate git digest: %v", ds)
		}
		gitDigests[ds] = struct{}{}
	}

	if len(gitDigests) == 0 {
		log.Infof("fsck: nothing to do")
		return nil
	}

	log.Infof("fsck: dcrtime verification started")
	defer log.Infof("fsck: dcrtime verification completed")

	// Iterate over all db records and pick out the anchors.  Take note of
	// unanchored commits and exclude those from the precious list.
	type AnchorT struct {
		key    string
		anchor *Anchor
	}
	var (
		version      *Version
		lastAnchor   *LastAnchor
		unconfAnchor *UnconfirmedAnchor
		anchors      []AnchorT
	)

	i := g.db.NewIterator(nil, nil)
	for i.Next() {
		// Guess what record type based on key
		key := i.Key()
		value := i.Value()
		if string(key) == VersionKey {
			version, err = DecodeVersion(value)
			if err != nil {
				return err
			}
			if version.Version != DbVersion {
				return fmt.Errorf("fsck: version error got %v "+
					"expected %v", version.Version,
					DbVersion)
			}
		} else if string(key) == LastAnchorKey {
			lastAnchor, err = DecodeLastAnchor(value)
			if err != nil {
				return err
			}
		} else if string(key) == UnconfirmedKey {
			unconfAnchor, err = DecodeUnconfirmedAnchor(value)
			if err != nil {
				return err
			}
		} else {
			anchor, err := DecodeAnchor(value)
			if err != nil {
				return err
			}
			anchors = append(anchors, AnchorT{
				key:    hex.EncodeToString(key),
				anchor: anchor,
			})
		}
	}
	i.Release()
	if err := i.Error(); err != nil {
		return err
	}

	if lastAnchor == nil || unconfAnchor == nil {
		// This happens on first launch.
		return nil
	}

	// Peel out anchored commits and create a precious list to verify with
	// dcrtime.
	digests := make([]string, 0, len(out))
	for _, v := range anchors {
		if v.anchor.Type != AnchorVerified {
			log.Infof("skipping anchor %v", v.key)

			// Remove digests from reconcile map.
			for _, d := range v.anchor.Digests {
				k := hex.EncodeToString(d)
				if _, ok := gitDigests[k]; !ok {
					return fmt.Errorf("unknown unanchored"+
						" git digest: %v", k)
				}
				log.Debugf("delete unanchored %v", k)
				delete(gitDigests, k)
			}
			continue
		}
		log.Infof("verify anchor %v", v.key)
		for _, d := range v.anchor.Digests {
			k := hex.EncodeToString(d)

			// Remove digests from reconcile map as well.
			if _, ok := gitDigests[k]; !ok {
				return fmt.Errorf("unknown git digest: %v", k)
			}
			log.Debugf("delete %v", k)
			delete(gitDigests, k)

			digests = append(digests, k)
		}
	}

	// Verify anchored commits
	vr, err := util.Verify(g.dcrtimeHost, digests)
	if err != nil {
		return err
	}

	// Verify all results
	var fail bool
	for _, v := range vr.Digests {
		if v.Result != v1.ResultOK {
			fail = true
			log.Errorf("dcrtime error: %v %v %v", v.Digest,
				v.Result, v1.Result[v.Result])
		}
	}
	if fail {
		return fmt.Errorf("dcrtime fsck failed")
	}

	// At this point we know the database is sane.  Now we need to
	// reconcile git with the database.
	if len(gitDigests) != 0 {
		for k := range gitDigests {
			log.Errorf("unexpected digest: %v", k)
		}
		return fmt.Errorf("expected reconcile map to be empty")
	}

	return nil
}

// GetUnvetted checks out branch token and returns the content of
// unvetted/token directory.
//
// GetUnvetted satisfies the backend interface.
func (g *gitBackEnd) GetUnvetted(token []byte) (*backend.ProposalRecord, error) {
	return g.getProposalLock(token, g.unvetted, true)
}

// GetVetted returns the content of vetted/token directory.
//
// GetVetted satisfies the backend interface.
func (g *gitBackEnd) GetVetted(token []byte) (*backend.ProposalRecord, error) {
	return g.getProposalLock(token, g.vetted, true)
}

// SetUnvettedStatus tries to update the status for an unvetted proposal.  If
// the proposal is found the prior status is returned if the function errors
// out.  This is a bit unusual so keep it in mind.
//
// SetUnvettedStatus satisfies the backend interface.
func (g *gitBackEnd) SetUnvettedStatus(token []byte, status backend.PSRStatusT) (backend.PSRStatusT, error) {
	// Lock filesystem
	err := g.lock.Lock(LockDuration)
	if err != nil {
		return backend.PSRStatusInvalid, err
	}
	defer func() {
		err := g.lock.Unlock()
		if err != nil {
			log.Errorf("Unlock error: %v", err)
		}
	}()
	if g.shutdown {
		return backend.PSRStatusInvalid, backend.ErrShutdown
	}

	// git checkout id
	id := hex.EncodeToString(token)
	err = g.gitCheckout(g.unvetted, id)
	if err != nil {
		return backend.PSRStatusInvalid, backend.ErrProposalNotFound
	}
	defer func() {
		// git checkout master
		err = g.gitCheckout(g.unvetted, "master")
		if err != nil {
			log.Errorf("could not switch to master: %v", err)
		}
	}()

	// Load PSR
	psr, err := loadPSR(g.unvetted, id)
	if err != nil {
		return backend.PSRStatusInvalid, err
	}
	oldStatus := psr.Status

	// We only allow a transition from unvetted to vetted or censored
	switch {
	case psr.Status == backend.PSRStatusUnvetted &&
		status == backend.PSRStatusVetted:

		// unvetted -> vetted

		// Update PSR first
		psr.Status = backend.PSRStatusVetted
		psr.Version += 1
		err = updatePSR(g.unvetted, id, psr)
		if err != nil {
			return oldStatus, err
		}

		// Commit psr
		err = g.commitPSR(g.unvetted, id, "published")
		if err != nil {
			return oldStatus, err
		}

		// on unvetted repo:
		//     git checkout master
		//     git pull --ff--only --rebase
		//     git checkout id
		//     git rebase master
		//     git push --set-upstream origin id
		// on vetted repo:
		//     git rebase id
		//     git branch -D id
		// on unvetted repo:
		//     git checkout master
		//     git branch -D id
		//     git pull --ff-only

		//
		// UNVETTED REPO CREATE PR
		//
		// git checkout master
		err = g.gitCheckout(g.unvetted, "master")
		if err != nil {
			return oldStatus, err
		}

		// git pull --ff-only --rebase
		err = g.gitPull(g.unvetted, true)
		if err != nil {
			return oldStatus, err
		}

		// git checkout id
		err = g.gitCheckout(g.unvetted, id)
		if err != nil {
			return oldStatus, backend.ErrProposalNotFound
		}

		// git rebase master
		err = g.gitRebase(g.unvetted, "master")
		if err != nil {
			return oldStatus, err
		}

		// git push --set-upstream origin id
		err = g.gitPush(g.unvetted, "origin", id, true)
		if err != nil {
			return oldStatus, err
		}

		//
		// VETTED REPO REPLAY BRANCH
		//

		// git rebase id
		err = g.gitRebase(g.vetted, id)
		if err != nil {
			return oldStatus, err
		}

		// git branch -D id
		err = g.gitBranchDelete(g.vetted, id)
		if err != nil {
			return oldStatus, err
		}

		//
		// UNVETTED REPO SYNC
		//

		// git checkout master
		err = g.gitCheckout(g.unvetted, "master")
		if err != nil {
			return oldStatus, err
		}

		// git pull --ff-only --rebase
		err = g.gitPull(g.unvetted, true)
		if err != nil {
			return oldStatus, err
		}

		// git branch -D id
		err = g.gitBranchDelete(g.unvetted, id)
		if err != nil {
			return oldStatus, err
		}

	case psr.Status == backend.PSRStatusUnvetted &&
		status == backend.PSRStatusCensored:
		// unvetted -> censored
		psr.Status = backend.PSRStatusCensored
		psr.Version += 1
		err = updatePSR(g.unvetted, id, psr)
		if err != nil {
			return oldStatus, err
		}

		// Commit psr
		err = g.commitPSR(g.unvetted, id, "censored")
		if err != nil {
			return oldStatus, err
		}
	default:
		return oldStatus, backend.ErrInvalidTransition
	}

	return psr.Status, nil
}

// Inventory returns an inventory of vetted and unvetted proposals.  If
// includeFiles is set the content is also returned.
func (g *gitBackEnd) Inventory(vettedCount, branchCount uint, includeFiles bool) ([]backend.ProposalRecord, []backend.ProposalRecord, error) {
	// Lock filesystem
	err := g.lock.Lock(LockDuration)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		err := g.lock.Unlock()
		if err != nil {
			log.Errorf("Unlock error: %v", err)
		}
	}()
	if g.shutdown {
		return nil, nil, backend.ErrShutdown
	}

	// Walk vetted, we can simply take the vetted directory and sort the
	// entries by time.
	files, err := ioutil.ReadDir(g.vetted)
	if err != nil {
		return nil, nil, err
	}

	// Strip non proposal directories
	pr := make([]backend.ProposalRecord, 0, len(files))
	for _, v := range files {
		id := v.Name()
		if !util.IsDigest(id) {
			continue
		}

		ids, err := hex.DecodeString(id)
		if err != nil {
			return nil, nil, err
		}
		prv, err := g.getProposal(ids, g.vetted, includeFiles)
		if err != nil {
			return nil, nil, err
		}
		pr = append(pr, *prv)
	}

	// Walk Branches on unvetted
	branches, err := g.gitBranches(g.unvetted)
	if err != nil {
		return nil, nil, err
	}
	br := make([]backend.ProposalRecord, 0, len(branches))
	for _, id := range branches {
		if !util.IsDigest(id) {
			continue
		}

		ids, err := hex.DecodeString(id)
		if err != nil {
			return nil, nil, err
		}
		pru, err := g.getProposal(ids, g.unvetted, includeFiles)
		if err != nil {
			return nil, nil, err
		}
		br = append(br, *pru)
	}

	return pr, br, nil
}

// Close shuts down the backend.  It obtains the lock and sets the shutdown
// boolean to true.  All interface functions MUST return with errShutdown if
// the backend is shutting down.
//
// Close satisfies the backend interface.
func (g *gitBackEnd) Close() {
	err := g.lock.Lock(LockDuration)
	if err != nil {
		log.Errorf("Lock error: %v", err)
		return
	}
	defer func() {
		err := g.lock.Unlock()
		if err != nil {
			log.Errorf("Unlock error: %v", err)
		}
	}()

	g.shutdown = true
	close(g.exit)
	g.db.Close()
}

// newLocked runs the portion of new that has to be locked.
func (g *gitBackEnd) newLocked() error {
	// Initialize global filesystem lock
	var err error
	g.lock, err = lockfile.New(filepath.Join(g.root,
		LockFilename), 100*time.Millisecond)
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
			log.Errorf("New unlock error: %v", err)
		}
	}()

	// Ensure git works
	version, err := g.gitVersion()
	if err != nil {
		return err
	}

	log.Infof("Git version: %v", version)

	// Init vetted git repo
	err = g.gitInitRepo(g.vetted, defaultRepoConfig)
	if err != nil {
		return err
	}

	// Clone vetted repo into unvetted
	err = g.gitClone(g.vetted, g.unvetted, defaultRepoConfig)
	if err != nil {
		return err
	}

	// Open DB
	err = g.openDB(filepath.Join(g.root, DefaultDbPath))
	if err != nil {
		return err
	}

	// Fsck _o/
	log.Infof("Running git fsck on vetted repository")
	_, err = g.gitFsck(g.vetted)
	if err != nil {
		return err
	}
	log.Infof("Running git fsck on unvetted repository")
	_, err = g.gitFsck(g.unvetted)
	if err != nil {
		return err
	}

	log.Infof("Running dcrtime fsck on vetted repository")
	return g.fsck(g.vetted)
}

// New returns a gitBackEnd context.  It verifies that git is installed.
func New(root, dcrtimeHost, gitPath string, gitTrace bool) (*gitBackEnd, error) {
	// Default to system git
	if gitPath == "" {
		gitPath = "git"
	}

	g := &gitBackEnd{
		root:        root,
		cron:        cron.New(),
		unvetted:    filepath.Join(root, defaultUnvettedPath),
		vetted:      filepath.Join(root, defaultVettedPath),
		gitPath:     gitPath,
		dcrtimeHost: dcrtimeHost,
		gitTrace:    gitTrace,
		exit:        make(chan struct{}),
		checkAnchor: make(chan struct{}),
		testAnchors: make(map[string]bool),
	}

	err := g.newLocked()
	if err != nil {
		return nil, err
	}

	// Launch anchor checker and don't do any work just yet.  The
	// unanchored bits will be picked up during the next go-round.  We
	// don't try to be clever in order to prevent dual commits for the same
	// anchor which can happen if the daemon is launched right around the
	// scheduled anchor drop.
	go g.periodicAnchorChecker()

	// Launch cron.
	err = g.cron.AddFunc(anchorSchedule, func() {
		g.anchorAllReposCronJob()
	})
	if err != nil {
		return nil, err
	}
	g.cron.Start()

	// Message user
	log.Infof("Timestamp host: %v", g.dcrtimeHost)

	return g, nil
}
