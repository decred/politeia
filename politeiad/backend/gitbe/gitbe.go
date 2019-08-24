// Copyright (c) 2017-2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

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
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/decred/dcrd/chaincfg"
	v1 "github.com/decred/dcrtime/api/v1"
	"github.com/decred/dcrtime/merkle"
	"github.com/decred/politeia/decredplugin"
	pd "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/api/v1/mime"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/util"
	filesystem "github.com/otiai10/copy"
	"github.com/robfig/cron"
	"github.com/subosito/gozaru"
)

const (
	// LockDuration is the maximum lock time duration allowed.  15 seconds
	// is ~3x of anchoring without internet delay.
	LockDuration = 15 * time.Second

	// defaultUnvettedPath is the landing zone for unvetted content.
	DefaultUnvettedPath = "unvetted"

	// defaultVettedPath is the publicly visible git vetted record repo.
	DefaultVettedPath = "vetted"

	// defaultJournalsPath is the path where data is journaled and/or
	// cached.
	DefaultJournalsPath = "journals" // XXX it looks like this belongs in plugins

	// defaultRecordMetadataFilename is the filename of record record.
	defaultRecordMetadataFilename = "recordmetadata.json"

	// defaultMDFilenameSuffix is the filename suffic for the user provided
	// metadata record.  The metadata record shall be string encoded.
	defaultMDFilenameSuffix = ".metadata.txt"

	// defaultAuditTrailFile is the filename where a human readable audit
	// trail is kept.
	defaultAuditTrailFile = "anchor_audit_trail.txt"

	// defaultAnchorsDirectory is the directory where anchors are stored.
	// They are indexed by TX.
	defaultAnchorsDirectory = "anchors"

	// defaultPayloadDir is the default path to store a record payload.
	defaultPayloadDir = "payload"

	// anchorSchedule determines how often we anchor the vetted repo.
	// Seconds Minutes Hours Days Months DayOfWeek
	anchorSchedule = "0 58 * * * *" // At 58 minutes every hour

	// expectedTestTX is a fake TX used by unit tests.
	expectedTestTX = "TESTTX"

	// markerAnchor is used in commit messages to determine
	// where an anchor has been committed.  This value is
	// parsed and therefore must be a const.
	markerAnchor = "Anchor"

	// markerAnchorConfirmation is used in commit messages to determine
	// where an anchor confirmation has been committed.  This value is
	// parsed and therefore must be a const.
	markerAnchorConfirmation = "Anchor confirmation"
)

var (
	_ backend.Backend = (*gitBackEnd)(nil)

	defaultRepoConfig = map[string]string{
		// This prevents git from converting CRLF when committing and checking
		// out files, which helps when running on Windows.
		"core.autocrlf": "false",
		"user.name":     "Politeia",
		"user.email":    "noreply@decred.org",
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
	sync.Mutex                       // Global lock
	cron            *cron.Cron       // Scheduler for periodic tasks
	activeNetParams *chaincfg.Params // indicator if we are running on testnet
	journal         *Journal         // Journal context
	shutdown        bool             // Backend is shutdown
	root            string           // Root directory
	unvetted        string           // Unvettend content
	vetted          string           // Vetted, public, visible content
	journals        string           // Journals/cache
	dcrtimeHost     string           // Dcrtimed host
	gitPath         string           // Path to git
	gitTrace        bool             // Enable git tracing
	test            bool             // Set during UT
	exit            chan struct{}    // Close channel
	checkAnchor     chan struct{}    // Work notification
	plugins         []backend.Plugin // Plugins

	// The following items are used for testing only
	testAnchors map[string]bool // [digest]anchored
}

func pijoin(elements ...string) string {
	return filepath.Join(elements...)
}

// getLatest returns the latest version as a string.
// This function must be called with the lock held.
func getLatest(dir string) (string, error) {
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return "", backend.ErrRecordNotFound
	}

	if len(files) == 0 {
		return "", backend.ErrRecordNotFound
	}

	// We expect only numeric filenames
	versions := make([]int, 0, len(files))
	for _, v := range files {
		u, err := strconv.ParseInt(v.Name(), 10, 64)
		if err != nil {
			return "", err
		}
		versions = append(versions, int(u))
	}
	sort.Ints(versions)

	return strconv.FormatInt(int64(versions[len(versions)-1]), 10), nil
}

// getNext looks at the current latest version and increments the count by one.
// This function must be called with the lock held.
func getNext(dir string) (string, string, error) {
	v, err := getLatest(dir)
	if err != nil {
		return "", "", backend.ErrRecordNotFound
	}

	vv, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return "", "", err
	}
	vv++

	// Sanity
	if vv <= 0 {
		return "", "", fmt.Errorf("invalid version")
	}

	return v, strconv.FormatInt(vv, 10), nil
}

// _joinLatest joins the provided path elements and adds the latest version of
// the provided directory.
func _joinLatest(elements ...string) (string, error) {
	dir := pijoin(elements...)
	v, err := getLatest(dir)
	if err != nil {
		return "", err
	}
	return pijoin(dir, v), nil
}

// getPathToVersion returns the directory path to the specified record version
// if the version isn't provided, the latest version is returned by default
func getPathToVersion(path, id, version string) string {
	if version == "" {
		return joinLatest(path, id)
	} else {
		return pijoin(path, id, version)
	}
}

// joinLatest joins the provided path elements and adds the latest version of
// the provided directory. This function panic when it errors out, this is by
// design in order to find all incorrect invocations.
func joinLatest(elements ...string) string {
	path, err := _joinLatest(elements...)
	if err != nil {
		panic(err)
	}
	return path
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

// verifyContent verifies that all provided backend.MetadataStream and
// backend.File are sane and returns a cooked array of the files.
func verifyContent(metadata []backend.MetadataStream, files []backend.File, filesDel []string) ([]file, error) {
	// Make sure all metadata is within maxima.
	for _, v := range metadata {
		if v.ID > pd.MetadataStreamsMax-1 {
			return nil, backend.ContentVerificationError{
				ErrorCode: pd.ErrorStatusInvalidMDID,
				ErrorContext: []string{
					strconv.FormatUint(v.ID, 10),
				},
			}
		}
	}
	for i := range metadata {
		for j := range metadata {
			// Skip self and non duplicates.
			if i == j || metadata[i].ID != metadata[j].ID {
				continue
			}
			return nil, backend.ContentVerificationError{
				ErrorCode: pd.ErrorStatusDuplicateMDID,
				ErrorContext: []string{
					strconv.FormatUint(metadata[i].ID, 10),
				},
			}
		}
	}

	// Prevent paths
	for i := range files {
		if filepath.Base(files[i].Name) != files[i].Name {
			return nil, backend.ContentVerificationError{
				ErrorCode: pd.ErrorStatusInvalidFilename,
				ErrorContext: []string{
					files[i].Name,
				},
			}
		}
	}
	for _, v := range filesDel {
		if filepath.Base(v) != v {
			return nil, backend.ContentVerificationError{
				ErrorCode: pd.ErrorStatusInvalidFilename,
				ErrorContext: []string{
					v,
				},
			}
		}
	}

	// Now check files
	if len(files) == 0 {
		return nil, backend.ContentVerificationError{
			ErrorCode: pd.ErrorStatusEmpty,
		}
	}

	// Prevent bad filenames and duplicate filenames
	for i := range files {
		for j := range files {
			if i == j {
				continue
			}
			if files[i].Name == files[j].Name {
				return nil, backend.ContentVerificationError{
					ErrorCode: pd.ErrorStatusDuplicateFilename,
					ErrorContext: []string{
						files[i].Name,
					},
				}
			}
		}
		// Check against filesDel
		for _, v := range filesDel {
			if files[i].Name == v {
				return nil, backend.ContentVerificationError{
					ErrorCode: pd.ErrorStatusDuplicateFilename,
					ErrorContext: []string{
						files[i].Name,
					},
				}
			}
		}
	}

	fa := make([]file, 0, len(files))
	for i := range files {
		if gozaru.Sanitize(files[i].Name) != files[i].Name {
			return nil, backend.ContentVerificationError{
				ErrorCode: pd.ErrorStatusInvalidFilename,
				ErrorContext: []string{
					files[i].Name,
				},
			}
		}

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
		detectedMIMEType := mime.DetectMimeType(f.payload)
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

// loadRecord loads an entire record of disk.  It returns an array of
// backend.File that is completely filled out.
//
// This function must be called with the lock held.
func loadRecord(path, id, version string) ([]backend.File, error) {
	pathToVersion := getPathToVersion(path, id, version)
	// Get dir.
	recordDir := pijoin(pathToVersion, defaultPayloadDir)
	files, err := ioutil.ReadDir(recordDir)
	if err != nil {
		return nil, err
	}

	bf := make([]backend.File, 0, len(files))
	// Load all files
	for _, file := range files {
		fn := pijoin(recordDir, file.Name())
		if file.IsDir() {
			return nil, fmt.Errorf("record corrupt: %v", path)
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

// mdFilename generates the proper filename for a specified repo + proposal and
// metadata stream.
func mdFilename(path, id string, mdID int) string {
	return pijoin(joinLatest(path, id),
		strconv.FormatUint(uint64(mdID), 10)+defaultMDFilenameSuffix)
}

// loadMDStreams loads all streams of disk.  It returns an array of
// backend.MetadataStream that is completely filled out.
//
// This function must be called with the lock held.
func loadMDStreams(path, id, version string) ([]backend.MetadataStream, error) {
	pathToVersion := getPathToVersion(path, id, version)
	files, err := ioutil.ReadDir(pathToVersion)
	if err != nil {
		return nil, err
	}

	ms := make([]backend.MetadataStream, 0, len(files))
	for _, v := range files {
		// Skip irrelevant files
		if !strings.HasSuffix(v.Name(), defaultMDFilenameSuffix) {
			continue
		}

		// Fish out metadata stream ID from filename
		ids := strings.TrimSuffix(v.Name(), defaultMDFilenameSuffix)
		mdid, err := strconv.ParseUint(ids, 10, 64)
		if err != nil {
			return nil, err
		}

		// Load metadata stream
		fn := pijoin(pathToVersion, v.Name())
		md, err := ioutil.ReadFile(fn)
		if err != nil {
			return nil, err
		}
		ms = append(ms, backend.MetadataStream{
			ID:      mdid,
			Payload: string(md),
		})
	}

	return ms, nil
}

// loadMD loads a RecordMetadata from the provided path/id.  This may
// be unvetted/id or vetted/id.
//
// This function should be called with the lock held.
func loadMD(path, id, version string) (*backend.RecordMetadata, error) {
	pathToVersion := getPathToVersion(path, id, version)
	filename := pijoin(pathToVersion,
		defaultRecordMetadataFilename)
	f, err := os.Open(filename)
	if err != nil {
		if os.IsNotExist(err) {
			err = backend.ErrRecordNotFound
		}
		return nil, err
	}
	defer f.Close()

	var brm backend.RecordMetadata
	decoder := json.NewDecoder(f)
	if err = decoder.Decode(&brm); err != nil {
		return nil, err
	}
	return &brm, nil
}

// createMD stores a RecordMetadata to the provided path/id.  This may be
// unvetted/id or vetted/id.
//
// This function should be called with the lock held.
func createMD(path, id string, status backend.MDStatusT, iteration uint64, hashes []*[sha256.Size]byte) (*backend.RecordMetadata, error) {
	// Create record metadata
	m := *merkle.Root(hashes)
	brm := backend.RecordMetadata{
		Version:   backend.VersionRecordMD,
		Iteration: iteration,
		Status:    status,
		Merkle:    hex.EncodeToString(m[:]),
		Timestamp: time.Now().Unix(),
		Token:     id,
	}

	err := updateMD(path, id, &brm)
	if err != nil {
		return nil, err
	}

	return &brm, nil
}

// updateMD updates the RecordMetadata status to the provided path/id.
//
// This function should be called with the lock held.
func updateMD(path, id string, brm *backend.RecordMetadata) error {
	// Store metadata record.
	filename := pijoin(joinLatest(path, id), defaultRecordMetadataFilename)
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	return json.NewEncoder(f).Encode(*brm)
}

// commitMD commits the MD into a git repo.
//
// This function should be called with the lock held.
func (g *gitBackEnd) commitMD(path, id, msg string) error {
	// git add id/brm.json
	filename := pijoin(joinLatest(path, id),
		defaultRecordMetadataFilename)
	err := g.gitAdd(path, filename)
	if err != nil {
		return err
	}

	// git commit -m "message"
	return g.gitCommit(path, "Update record status "+id+" "+msg)
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

		// Ignore anchor confirmation commits
		if regexAnchorConfirmation.MatchString(ds[1]) {
			continue
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

	if len(digests) == 0 {
		return nil, nil, nil, errNothingToDo
	}

	return digests, commitMessages, out, nil
}

// anchor takes a slice of commit digests and anchors them in dcrtime.
//
// This function is being clever with the anchors.  It sends two values to
// dcrtime.  We anchor the merkle root, and we *also* anchor all
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

	return util.Timestamp("politeia", g.dcrtimeHost, digests)
}

// appendAuditTrail adds a record to the audit trail.
func (g *gitBackEnd) appendAuditTrail(path string, ts int64, merkle [sha256.Size]byte, lines []string) error {
	f, err := os.OpenFile(pijoin(path, defaultAuditTrailFile),
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

	// Create anchor record early for the same reason.
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
	commitMessage = fmt.Sprintf("%v %x\n\n%v", markerAnchor, *anchorKey,
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

	return anchorKey, nil
}

// anchor verifies if there are new commits in all repos and if that is the
// case it drops and anchor in dcrtime for each of them.
func (g *gitBackEnd) anchorAllRepos() error {
	log.Infof("Dropping anchor")
	// Lock filesystem
	g.Lock()
	defer g.Unlock()
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

		g.Lock()
		isShutdown := g.shutdown
		g.Unlock()
		if isShutdown {
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
	ua, err := g.readUnconfirmedAnchorRecord()
	if err != nil {
		return fmt.Errorf("anchorChecker read: %v", err)
	}

	// Check for work
	if len(ua.Merkles) == 0 {
		return nil
	}

	// Do one verify at a time for now
	vrs := make([]v1.VerifyDigest, 0, len(ua.Merkles))
	for _, u := range ua.Merkles {
		digest := hex.EncodeToString(u)
		vr, err := g.verifyAnchor(digest)
		if err != nil {
			log.Errorf("anchorChecker verify: %v", err)
			continue
		}
		vrs = append(vrs, *vr)
	}

	err = g.afterAnchorVerify(vrs)
	if err != nil {
		return fmt.Errorf("afterAnchorVerify: %v", err)
	}

	return nil
}

// afterAnchorVerify completes the anchor verification process.  It is a
// separate function in order not having to futz with locks.
func (g *gitBackEnd) afterAnchorVerify(vrs []v1.VerifyDigest) error {
	// Lock filesystem
	g.Lock()
	defer g.Unlock()

	var err error

	if len(vrs) != 0 {
		// git checkout master
		err = g.gitCheckout(g.vetted, "master")
		if err != nil {
			return err
		}
	}
	// Handle verified vrs
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
		txLine := fmt.Sprintf("%v anchored in TX %v\n", vr.Digest,
			vr.ChainInformation.Transaction)
		err = g.appendAuditTrail(g.vetted,
			vr.ChainInformation.ChainTimestamp, mr, []string{txLine})
		if err != nil {
			return err
		}
		err = g.gitAdd(g.vetted, defaultAuditTrailFile)
		if err != nil {
			return err
		}

		// Store dcrtime information.
		// In vetted store the ChainInformation as a json object in
		// directory anchor.
		// In Vetted in the record directory add a file called anchor
		// that points to the TX id.
		anchorDir := pijoin(g.vetted, defaultAnchorsDirectory)
		err = os.MkdirAll(anchorDir, 0774)
		if err != nil {
			return err
		}
		ar, err := json.Marshal(vr.ChainInformation)
		if err != nil {
			return err
		}
		err = ioutil.WriteFile(pijoin(anchorDir, vr.Digest),
			ar, 0664)
		if err != nil {
			return err
		}
		err = g.gitAdd(g.vetted,
			pijoin(defaultAnchorsDirectory, vr.Digest))
		if err != nil {
			return err
		}

		// git commit anchor confirmation
		commitMsg := markerAnchorConfirmation + " " + vr.Digest + "\n\n" + txLine
		err = g.gitCommit(g.vetted, commitMsg)
		if err != nil {
			return err
		}

		// Mark test anchors as confirmed by dcrtime
		if g.test {
			g.testAnchors[vr.Digest] = true
		}
	}
	if len(vrs) != 0 {
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
	}

	return nil
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
		vr, err = util.Verify("politeia", g.dcrtimeHost,
			[]string{digest})
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

// _newRecord adds a new record to the unvetted repo.  Note that this function
// must be wrapped by a function that delivers the call with the unvetted repo
// sitting in the correct branch.  The idea is that if this function fails we
// can simply unwind it said branch.
//
// Function must be called with the lock held.
func (g *gitBackEnd) _newRecord(id string, metadata []backend.MetadataStream, fa []file) (*backend.RecordMetadata, error) {
	// Process files.
	path := pijoin(g.unvetted, id, "1", defaultPayloadDir)
	err := os.MkdirAll(path, 0774)
	if err != nil {
		return nil, err
	}

	hashes := make([]*[sha256.Size]byte, 0, len(fa))
	for i := range fa {
		// Copy files into directory id/payload/filename.
		filename := pijoin(path, fa[i].name)
		err = ioutil.WriteFile(filename, fa[i].payload, 0664)
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

	// Save all metadata streams
	for i := range metadata {
		filename := pijoin(joinLatest(g.unvetted, id),
			fmt.Sprintf("%02v%v", metadata[i].ID,
				defaultMDFilenameSuffix))
		err = ioutil.WriteFile(filename, []byte(metadata[i].Payload),
			0664)
		if err != nil {
			return nil, err
		}
		// git add id/metadata.txt
		err = g.gitAdd(g.unvetted, filename)
		if err != nil {
			return nil, err
		}
	}

	// Save record metadata
	brm, err := createMD(g.unvetted, id, backend.MDStatusUnvetted, 1,
		hashes)
	if err != nil {
		return nil, err
	}

	// git add id/version/recordmetadata.json
	filename := pijoin(joinLatest(g.unvetted, id),
		defaultRecordMetadataFilename)
	err = g.gitAdd(g.unvetted, filename)
	if err != nil {
		return nil, err
	}

	// git commit -m "message"
	err = g.gitCommit(path, "Add record "+id)
	if err != nil {
		return nil, err
	}

	return brm, nil
}

// newRecord adds a new record to the unvetted repo. If something fails it
// unwinds changes made and returns sitting in the master branch.  Note that if
// the call fails the branch is deleted because the branch does not contain
// anything of value.
//
// Function must be called with the lock held.
func (g *gitBackEnd) newRecord(token []byte, metadata []backend.MetadataStream, fa []file) (*backend.RecordMetadata, error) {
	id := hex.EncodeToString(token)

	log.Tracef("newRecord %v", id)

	// git checkout -b id
	err := g.gitNewBranch(g.unvetted, id)
	if err != nil {
		return nil, err
	}

	rm, err2 := g._newRecord(id, metadata, fa)
	if err2 != nil {
		// Unwind and complain
		err = g.gitUnwindBranch(g.unvetted, id)
		if err != nil {
			// We are in trouble and should consider a panic
			log.Criticalf("newRecord: %v", err)
		}
		return nil, err2
	}

	// git checkout master
	err = g.gitCheckout(g.unvetted, "master")
	if err != nil {
		return nil, err
	}

	return rm, nil
}

// New takes a record verifies it and drops it on disk in the unvetted
// directory.  Records and metadata are stored in unvetted/token/.  the
// function returns a RecordMetadata.
//
// New satisfies the backend interface.
func (g *gitBackEnd) New(metadata []backend.MetadataStream, files []backend.File) (*backend.RecordMetadata, error) {
	log.Tracef("New")
	fa, err := verifyContent(metadata, files, []string{})
	if err != nil {
		return nil, err
	}

	// Create a censorship token.
	token, err := util.Random(pd.TokenSize)
	if err != nil {
		return nil, err
	}

	log.Debugf("New %x", token)

	// Lock filesystem
	g.Lock()
	defer g.Unlock()
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

	return g.newRecord(token, metadata, fa)
}

// updateMetadata appends or overwrites in the unvetted repository.
// Additionally it does the git bits when called.
// Function must be called with the lock held.
func (g *gitBackEnd) updateMetadata(id string, mdAppend, mdOverwrite []backend.MetadataStream) error {
	// Overwrite metadata
	for i := range mdOverwrite {
		filename := pijoin(joinLatest(g.unvetted, id),
			fmt.Sprintf("%02v%v", mdOverwrite[i].ID,
				defaultMDFilenameSuffix))
		err := ioutil.WriteFile(filename, []byte(mdOverwrite[i].Payload),
			0664)
		if err != nil {
			return err
		}
		// git add id/metadata.txt
		err = g.gitAdd(g.unvetted, filename)
		if err != nil {
			return err
		}
	}

	// Append metadata
	for i := range mdAppend {
		filename := pijoin(joinLatest(g.unvetted, id),
			fmt.Sprintf("%02v%v", mdAppend[i].ID,
				defaultMDFilenameSuffix))
		f, err := os.OpenFile(filename,
			os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			return err
		}
		_, err = io.WriteString(f, mdAppend[i].Payload)
		if err != nil {
			f.Close()
			return err
		}
		f.Close()
		// git add id/metadata.txt
		err = g.gitAdd(g.unvetted, filename)
		if err != nil {
			return err
		}
	}
	return nil
}

func (g *gitBackEnd) checkoutRecordBranch(id string) (bool, error) {
	// See if branch already exists
	branches, err := g.gitBranches(g.unvetted)
	if err != nil {
		return false, err
	}
	var found bool
	for _, v := range branches {
		if !util.IsDigest(v) {
			continue
		}
		if v == id {
			found = true
			break
		}
	}

	if found {
		// Branch exists, modify branch
		err := g.gitCheckout(g.unvetted, id)
		if err != nil {
			return true, backend.ErrRecordNotFound
		}
	} else {
		// Branch does not exist, create it if record exists
		fi, err := os.Stat(pijoin(g.unvetted, id))
		if err != nil {
			if os.IsNotExist(err) {
				return false, backend.ErrRecordNotFound
			}
		}
		if !fi.IsDir() {
			return false, fmt.Errorf("unvetted repo corrupt: %v "+
				"is not a dir", fi.Name())
		}
		// git checkout -b id
		err = g.gitNewBranch(g.unvetted, id)
		if err != nil {
			return false, err
		}
	}

	return found, nil
}

// _updateRecord takes various parameters to update a record.  Note that this
// function must be wrapped by a function that delivers the call with the repo
// sitting in the correct branch/master.  The idea is that if this function
// fails we can simply unwind it by calling a git stash.
// If commit is true the changes will be committed to record, if it is false
// it'll return ErrChangesRecord if the error would change; the caller is
// responsible to unwinding the changes.
//
// Function must be  called with the lock held.
func (g *gitBackEnd) _updateRecord(commit bool, id string, mdAppend, mdOverwrite []backend.MetadataStream, fa []file, filesDel []string) error {
	// Get version for relative git rm command later.
	version, err := getLatest(pijoin(g.unvetted, id))
	if err != nil {
		return err
	}

	log.Tracef("updating %v %v", commit, id)
	defer func() { log.Tracef("updating complete: %v", id) }()

	// Load MD
	brm, err := loadMD(g.unvetted, id, "")
	if err != nil {
		return err
	}
	if !(brm.Status == backend.MDStatusVetted ||
		brm.Status == backend.MDStatusUnvetted ||
		brm.Status == backend.MDStatusIterationUnvetted ||
		brm.Status == backend.MDStatusArchived) {
		return fmt.Errorf("can not update record that "+
			"has status: %v %v", brm.Status,
			backend.MDStatus[brm.Status])
	}

	// Verify all deletes before executing
	for _, v := range filesDel {
		fi, err := os.Stat(pijoin(joinLatest(g.unvetted, id),
			defaultPayloadDir, v))
		if err != nil {
			if os.IsNotExist(err) {
				return backend.ContentVerificationError{
					ErrorCode:    pd.ErrorStatusFileNotFound,
					ErrorContext: []string{v},
				}
			}
		}
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("not a file: %v", fi.Name())
		}
	}

	// At this point we should be ready to add/remove/update all the things.
	path := pijoin(joinLatest(g.unvetted, id), defaultPayloadDir)
	for i := range fa {
		// Copy files into directory id/payload/filename.
		filename := pijoin(path, fa[i].name)
		err = ioutil.WriteFile(filename, fa[i].payload, 0664)
		if err != nil {
			return err
		}

		// git add id/payload/filename
		err = g.gitAdd(g.unvetted, filename)
		if err != nil {
			return err
		}
	}

	// Delete files
	relativeRmDir := pijoin(id, version, defaultPayloadDir)
	for _, v := range filesDel {
		err = g.gitRm(g.unvetted, pijoin(relativeRmDir, v), true)
		if err != nil {
			return err
		}
	}

	// Handle metadata
	err = g.updateMetadata(id, mdAppend, mdOverwrite)
	if err != nil {
		return err
	}

	// Find all hashes
	hashes := make([]*[sha256.Size]byte, 0, len(fa))
	ppath := pijoin(joinLatest(g.unvetted, id), defaultPayloadDir)
	newRecordFiles, err := ioutil.ReadDir(ppath)
	if err != nil {
		if os.IsNotExist(err) {
			return backend.ContentVerificationError{
				ErrorCode: pd.ErrorStatusEmpty,
			}
		}
		return err
	}
	for _, v := range newRecordFiles {
		digest, err := util.DigestFileBytes(pijoin(ppath,
			v.Name()))
		if err != nil {
			return err
		}
		var d [sha256.Size]byte
		copy(d[:], digest)
		hashes = append(hashes, &d)
	}

	// If there are no changes DO NOT update the record and reply with no
	// changes.
	log.Tracef("_updateRecord: verify changes %v", id)
	if !g.gitHasChanges(g.unvetted) {
		return backend.ErrNoChanges
	}

	if !commit {
		return backend.ErrChangesRecord
	}

	log.Tracef("_updateRecord: committing %v", id)

	// Update record metadata
	ns := backend.MDStatusIterationUnvetted
	if brm.Status == backend.MDStatusVetted {
		ns = backend.MDStatusVetted
	}
	_, err = createMD(g.unvetted, id, ns, brm.Iteration+1, hashes)
	if err != nil {
		return err
	}

	// Check for authorizevote metadata and delete it if found
	avFilename := fmt.Sprintf("%02v%v", decredplugin.MDStreamAuthorizeVote,
		defaultMDFilenameSuffix)
	_, err = os.Stat(pijoin(joinLatest(g.unvetted, id), avFilename))
	if err == nil {
		err = g.gitRm(g.unvetted, pijoin(id, version, avFilename), true)
		if err != nil {
			return err
		}
	}

	// Call plugin hooks
	f, ok := decredPluginHooks[PluginPostHookEdit]
	if ok {
		log.Tracef("Calling hook: %v(%v)", PluginPostHookEdit, id)
		err = f(id)
		if err != nil {
			return err
		}
	}

	// git add id/recordmetadata.json
	filename := pijoin(joinLatest(g.unvetted, id),
		defaultRecordMetadataFilename)
	err = g.gitAdd(g.unvetted, filename)
	if err != nil {
		return err
	}

	// git commit -m "message"
	err = g.gitCommit(g.unvetted, "Update record "+id)
	if err != nil {
		return err
	}

	log.Tracef("Returning complete record: %v", id)
	// This is a bit inefficient but let's roll with it for now.
	return nil
}

// wouldChange applies a diff into a repo and undoes that. The point of this
// call is to determine if applying said diff would change the repo.
//
// This is a very expensive call. Only use this sparingly.
//
// Must be called WITHOUT the lock held.
func (g *gitBackEnd) wouldChange(id string, mdAppend []backend.MetadataStream, mdOverwrite []backend.MetadataStream, fa []file, filesDel []string) (bool, error) {
	idTmp := id + "_rm"
	_ = g.gitBranchDelete(g.unvetted, idTmp) // Delete it just in case
	err := g.gitNewBranch(g.unvetted, idTmp)
	if err != nil {
		return false, err
	}

	var rv bool
	err = g._updateRecord(false, id, mdAppend, mdOverwrite, fa, filesDel)
	if err == backend.ErrChangesRecord {
		rv = true
	}
	return rv, g.gitUnwindBranch(g.unvetted, idTmp)
}

// updateRecord puts the correct git repo in the correct state (branch or
// master) and then updates the the record content. It returns a version if an
// update occurred on master.
//
// Must be called WITHOUT the lock held.
func (g *gitBackEnd) updateRecord(token []byte, mdAppend []backend.MetadataStream, mdOverwrite []backend.MetadataStream, filesAdd []backend.File, filesDel []string, master bool) (*backend.Record, error) {
	log.Tracef("updateRecord: %x", token)

	// Send in a single metadata array to verify there are no dups.
	allMD := append(mdAppend, mdOverwrite...)
	fa, err := verifyContent(allMD, filesAdd, filesDel)
	if err != nil {
		e, ok := err.(backend.ContentVerificationError)
		if !ok {
			return nil, err
		}
		// Allow ErrorStatusEmpty
		if e.ErrorCode != pd.ErrorStatusEmpty {
			return nil, err
		}
	}

	// Lock filesystem
	g.Lock()
	defer g.Unlock()
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

	id := hex.EncodeToString(token)
	if master {
		// Vetted path

		// Check to make sure this prop is vetted
		dir := pijoin(g.unvetted, id)
		_, err = os.Stat(dir)
		if err != nil {
			return nil, backend.ErrRecordNotFound
		}

		// Make sure there are actually changes before we commence the
		// revision update

		// We got a new revision, do the work
		change, err := g.wouldChange(id, mdAppend, mdOverwrite, fa,
			filesDel)
		if err != nil {
			return nil, err
		}
		if !change {
			return nil, backend.ErrNoChanges
		}

		// Get old and new version
		oldV, newV, err := getNext(dir)
		if err != nil {
			return nil, err
		}

		// Checkout temporary branch
		idTmp := id + "_tmp"
		_ = g.gitBranchDelete(g.unvetted, idTmp) // Delete leftovers
		err = g.gitNewBranch(g.unvetted, idTmp)
		if err != nil {
			return nil, err
		}

		// Copy entire prop
		log.Debugf("cp %v, %v", pijoin(g.unvetted, id, oldV),
			pijoin(g.unvetted, id, newV))
		err = filesystem.Copy(pijoin(g.unvetted, id, oldV),
			pijoin(g.unvetted, id, newV))
		if err != nil {
			return nil, err
		}

		// We need to add the new path here so that git rm can delete a
		// known file
		err = g.gitAdd(g.unvetted, pijoin(g.unvetted, id, newV))
		if err != nil {
			return nil, err
		}

		// defer branch delete
		log.Debugf("updating vetted %v -> %v %v", oldV, newV, id)

		// Do the work, if there is an error we must unwind git.
		errReturn := g._updateRecord(true, id, mdAppend, mdOverwrite,
			fa, filesDel)
		if errReturn == nil {
			// Success path

			// create and rebase PR
			err = g.rebasePR(idTmp)
			if err != nil {
				return nil, err
			}

			// g.vetted is correct!
			return g.getRecord(token, "", g.vetted, true)
		}

		// git stash
		err = g.gitUnwindBranch(g.unvetted, idTmp)
		if err != nil {
			// We are in trouble! Consider a panic.
			log.Criticalf("update vetted record unwind: %v", err)
		}

		return nil, errReturn
	}

	// Unvetted path

	// Check to make sure this prop is not vetted
	_, err = os.Stat(pijoin(g.unvetted, id))
	if err == nil {
		return nil, backend.ErrRecordFound
	}

	// Checkout branch
	_, err = g.checkoutRecordBranch(id)
	if err != nil {
		return nil, err
	}

	// We now are sitting in branch id
	log.Debugf("updating unvetted %v", id)

	// Do the work, if there is an error we must unwind git.
	errReturn := g._updateRecord(true, id, mdAppend, mdOverwrite, fa,
		filesDel)
	if errReturn == nil {
		// success
		return g.getRecord(token, "", g.unvetted, true)
	}

	// git stash
	err = g.gitUnwind(g.unvetted)
	if err != nil {
		log.Criticalf("update unvetted record unwind: %v", err)
	}

	// git checkout master
	err = g.gitCheckout(g.unvetted, "master")
	if err != nil {
		log.Criticalf("update unvetted record checkout master: %v", err)
	}

	return nil, errReturn
}

// UpdateVettedRecord updates the vetted record.
//
// This function is part of the interface.
func (g *gitBackEnd) UpdateVettedRecord(token []byte, mdAppend []backend.MetadataStream, mdOverwrite []backend.MetadataStream, filesAdd []backend.File, filesDel []string) (*backend.Record, error) {
	log.Debugf("UpdateVettedRecord %x", token)
	return g.updateRecord(token, mdAppend, mdOverwrite, filesAdd, filesDel,
		true)
}

// UpdateUnvettedRecord updates the unvetted record.
//
// This function is part of the interface.
func (g *gitBackEnd) UpdateUnvettedRecord(token []byte, mdAppend []backend.MetadataStream, mdOverwrite []backend.MetadataStream, filesAdd []backend.File, filesDel []string) (*backend.Record, error) {
	log.Debugf("UpdateUnvettedRecord %x", token)
	return g.updateRecord(token, mdAppend, mdOverwrite, filesAdd, filesDel,
		false)
}

// updateVettedMetadata updates metadata in the unvetted repo and pushes it
// upstream followed by a rebase.  Record is not updated.
// This function must be called with the lock held.
func (g *gitBackEnd) updateVettedMetadata(id, idTmp string, mdAppend []backend.MetadataStream, mdOverwrite []backend.MetadataStream) error {
	_ = g.gitBranchDelete(g.unvetted, idTmp) // Delete leftovers

	// Checkout temporary branch
	err := g.gitNewBranch(g.unvetted, idTmp)
	if err != nil {
		return err
	}

	// Update metadata changes
	err = g.updateMetadata(id, mdAppend, mdOverwrite)
	if err != nil {
		return err
	}

	// If there are no changes DO NOT update the record and reply with no
	// changes.
	if !g.gitHasChanges(g.unvetted) {
		return backend.ErrNoChanges
	}

	// Commit change
	err = g.gitCommit(g.unvetted, "Update record metadata "+id)
	if err != nil {
		return err
	}

	// create and rebase PR
	return g.rebasePR(idTmp)
}

// _updateVettedMetadata updates metadata in vetted record.  It goes through
// the normal stages of updating unvetted, pushing PR, merge PR, pull remote.
// Note that the content must have been validated before this call.  Record
// itself is not changed.
//
// This function must be called with the lock held.
func (g *gitBackEnd) _updateVettedMetadata(token []byte, mdAppend []backend.MetadataStream, mdOverwrite []backend.MetadataStream) error {
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

	// Check if temporary branch exists (should never be the case)
	id := hex.EncodeToString(token)
	idTmp := id + "_tmp"

	// Make sure vetted exists
	_, err = os.Stat(pijoin(g.unvetted, id))
	if err != nil {
		if os.IsNotExist(err) {
			return backend.ErrRecordNotFound
		}
	}

	// Make sure record is not locked.
	md, err := loadMD(g.unvetted, id, "")
	if err != nil {
		return err
	}
	if md.Status == backend.MDStatusArchived {
		return backend.ErrRecordArchived
	}

	log.Debugf("updating vetted metadata %x", token)

	// Do the work, if there is an error we must unwind git.
	err = g.updateVettedMetadata(id, idTmp, mdAppend, mdOverwrite)
	if err != nil {
		err2 := g.gitUnwindBranch(g.unvetted, idTmp)
		if err2 != nil {
			// We are in trouble! Consider a panic.
			log.Criticalf("updateVettedMetadata: %v", err2)
		}
		return err
	}

	return nil
}

// UpdateVettedMetadata updates metadata in vetted record.  It goes through the
// normal stages of updating unvetted, pushing PR, merge PR, pull remote.
// Record itself is not changed.
//
// This function must be called without the lock held.
func (g *gitBackEnd) UpdateVettedMetadata(token []byte, mdAppend []backend.MetadataStream, mdOverwrite []backend.MetadataStream) error {
	log.Debugf("UpdateVettedMetadata: %x", token)

	// Send in a single metadata array to verify there are no dups.
	allMD := append(mdAppend, mdOverwrite...)
	_, err := verifyContent(allMD, []backend.File{}, []string{})
	if err != nil {
		e, ok := err.(backend.ContentVerificationError)
		if !ok {
			return err
		}
		// Allow ErrorStatusEmpty
		if e.ErrorCode != pd.ErrorStatusEmpty {
			return err
		}
	}

	// Lock filesystem
	g.Lock()
	defer g.Unlock()
	if g.shutdown {
		return backend.ErrShutdown
	}

	return g._updateVettedMetadata(token, mdAppend, mdOverwrite)
}

// _updateReadme updates the README.md file in the unvetted repo, then
// does a commit. This function must be called WITH the lock
// held, and must be wrapped with a function that puts the repo
// into the proper state and unwinds it in case something goes wrong.
func (g *gitBackEnd) _updateReadme(content string) error {

	// Update readme file
	filename := pijoin(g.unvetted, "README.md")
	err := ioutil.WriteFile(filename, []byte(content), 0664)
	if err != nil {
		return err
	}

	// If there are no changes, do not continue
	if !g.gitHasChanges(g.unvetted) {
		return backend.ErrNoChanges
	}

	// Add readme file
	err = g.gitAdd(g.unvetted, "README.md")
	if err != nil {
		return err
	}

	// Commit change
	return g.gitCommit(g.unvetted, "Update README.md")
}

// updateReadme updates the README.md file in the unvetted repo
// then rebases the change and pushes it to the vetted repo. If
// anything goes wrong it unwinds the changes are returns the repo
// to master.
// This function must be called WITH the lock held.
func (g *gitBackEnd) updateReadme(content string) error {
	const tmpBranch = "updateReadmeTmp"

	// Delete old temporary branch if it exists
	g.gitBranchDelete(g.unvetted, tmpBranch)

	// Checkout temporary branch
	err := g.gitNewBranch(g.unvetted, tmpBranch)
	if err != nil {
		return err
	}

	err2 := g._updateReadme(content)
	if err2 != nil {
		// Unwind and complain
		err := g.gitUnwindBranch(g.unvetted, tmpBranch)
		if err != nil {
			// We are in trouble and should consider a panic
			log.Criticalf("updateReadme: %v", err)
		}
		return err2
	}

	// create and rebase PR
	return g.rebasePR(tmpBranch)
}

// UpdateReadme updates the README.md file in the unvetted repo,
// then rebases the change and pushes it to the vetted repo.
// This function must be called WITHOUT the lock held.
//
// UpdateReadme satisfies the backend interface.
func (g *gitBackEnd) UpdateReadme(content string) error {
	log.Debugf("UpdateReadme")

	// Lock filesystem
	g.Lock()
	defer g.Unlock()
	if g.shutdown {
		return backend.ErrShutdown
	}
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

	return g.updateReadme(content)
}

// getRecordLock is the generic implementation of GetUnvetted/GetVetted.  It
// returns a record record from the provided repo.
//
// This function must be called WITHOUT the lock held.
func (g *gitBackEnd) getRecordLock(token []byte, version, repo string, includeFiles bool) (*backend.Record, error) {
	// Lock filesystem
	g.Lock()
	defer g.Unlock()
	if g.shutdown {
		return nil, backend.ErrShutdown
	}

	return g.getRecord(token, version, repo, includeFiles)
}

// _getRecord loads a record from the current branch on the provided repo.
//
// This function must be called WITH the lock held.
func (g *gitBackEnd) _getRecord(id, version, repo string, includeFiles bool) (*backend.Record, error) {

	// Use latestVersion if version isn't specified
	if version == "" {
		latestVersion, err := getLatest(pijoin(repo, id))
		if err != nil {
			return nil, err
		}
		version = latestVersion
	}

	// load MD
	brm, err := loadMD(repo, id, version)
	if err != nil {
		return nil, err
	}

	// load metadata streams
	mds, err := loadMDStreams(repo, id, version)
	if err != nil {
		return nil, err
	}

	var files []backend.File
	if includeFiles {
		// load files
		files, err = loadRecord(repo, id, version)
		if err != nil {
			return nil, err
		}
	}

	return &backend.Record{
		RecordMetadata: *brm,
		Version:        version,
		Metadata:       mds,
		Files:          files,
	}, nil
}

// getRecord is the generic implementation of GetUnvetted/GetVetted.  It
// returns a record record from the provided repo.
//
// This function must be called WITH the lock held.
func (g *gitBackEnd) getRecord(token []byte, version, repo string, includeFiles bool) (*backend.Record, error) {
	log.Tracef("getRecord: %x", token)

	id := hex.EncodeToString(token)
	if repo == g.unvetted {
		// git checkout id
		err := g.gitCheckout(repo, id)
		if err != nil {
			return nil, backend.ErrRecordNotFound
		}
		branchNow, err := g.gitBranchNow(repo)
		if err != nil || branchNow != id {
			return nil, backend.ErrRecordNotFound
		}
	}
	defer func() {
		// git checkout master
		err := g.gitCheckout(repo, "master")
		if err != nil {
			log.Errorf("could not switch to master: %v", err)
		}
	}()

	return g._getRecord(id, version, repo, includeFiles)
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

	var seenAnchor bool
	// gitDigests is an index of all git digests to verify with dcrtime
	gitDigests := make(map[string]struct{})
	// confirmedAnchors keeps track of anchors that were timestamped with dcrtime but not verified,
	// since periodicAnchorChecker only checks recent unconfirmed anchors and ignores older ones
	confirmedAnchors := make(map[string]struct{})
	var unconfirmedAnchors []string
	for _, v := range out {
		if regexAnchorConfirmation.MatchString(v) {
			// Store confirmed anchor merkle roots to look up later
			merkleRoot := regexAnchorConfirmation.FindStringSubmatch(v)[1]
			confirmedAnchors[merkleRoot] = struct{}{}
			continue
		} else if regexAnchor.MatchString(v) {
			// We now have seen an Anchor commit. The following digests are now precious.
			seenAnchor = true
			// We should have seen its confirmation already, since we're parsing top to bottom
			// If we didn't, save the anchor key to verify with dcrtime later
			merkleRoot := regexAnchor.FindStringSubmatch(v)[1]
			_, confirmed := confirmedAnchors[merkleRoot]
			if !confirmed {
				unconfirmedAnchors = append(unconfirmedAnchors, merkleRoot)
			}
			continue
		}
		if !seenAnchor {
			// We have not seen an Anchor yet so this digest is not
			// precious.
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

	// Verify the unconfirmed anchors
	vrs := make([]v1.VerifyDigest, 0, len(unconfirmedAnchors))
	for _, merkleRoot := range unconfirmedAnchors {
		vr, err := g.verifyAnchor(merkleRoot)
		if err != nil {
			log.Errorf("Error verifying anchor during fsck: %v", err)
			continue
		} else {
			vrs = append(vrs, *vr)
		}
	}

	err = g.afterAnchorVerify(vrs)
	if err != nil {
		return err
	}

	// Now we should be able to verify all the precious git digests
	digests := make([]string, 0, len(gitDigests))
	for d := range gitDigests {
		digests = append(digests, d)
	}
	vr, err := util.Verify("politeia", g.dcrtimeHost, digests)
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

	return nil
}

// GetUnvetted checks out branch token and returns the content of
// unvetted/token directory.
//
// GetUnvetted satisfies the backend interface.
func (g *gitBackEnd) GetUnvetted(token []byte) (*backend.Record, error) {
	log.Debugf("GetUnvetted %x", token)
	return g.getRecordLock(token, "", g.unvetted, true)
}

// GetVetted returns the content of vetted/token directory.
//
// GetVetted satisfies the backend interface.
func (g *gitBackEnd) GetVetted(token []byte, version string) (*backend.Record, error) {
	log.Debugf("GetVetted %x", token)
	return g.getRecordLock(token, version, g.vetted, true)
}

// setUnvettedStatus takes various parameters to update a record metadata and
// status.  Note that this function must be wrapped by a function that delivers
// the call with the unvetted repo sitting in master.  The idea is that if this
// function fails we can simply unwind it by calling a git stash.
// Function must be called with the lock held.
func (g *gitBackEnd) setUnvettedStatus(token []byte, status backend.MDStatusT, mdAppend, mdOverwrite []backend.MetadataStream) (*backend.Record, error) {
	// git checkout id
	id := hex.EncodeToString(token)
	err := g.gitCheckout(g.unvetted, id)
	if err != nil {
		return nil, backend.ErrRecordNotFound
	}

	// Load record
	record, err := g._getRecord(id, "", g.unvetted, false)
	if err != nil {
		return nil, err
	}

	// We only allow a transition from unvetted to vetted or censored
	switch {
	case (record.RecordMetadata.Status == backend.MDStatusUnvetted ||
		record.RecordMetadata.Status == backend.MDStatusIterationUnvetted) &&
		status == backend.MDStatusVetted:

		// unvetted -> vetted

		// Update MD first
		record.RecordMetadata.Status = backend.MDStatusVetted
		record.RecordMetadata.Iteration += 1
		record.RecordMetadata.Timestamp = time.Now().Unix()
		err = updateMD(g.unvetted, id, &record.RecordMetadata)
		if err != nil {
			return nil, err
		}

		// Handle metadata
		err = g.updateMetadata(id, mdAppend, mdOverwrite)
		if err != nil {
			return nil, err
		}

		// Commit brm
		err = g.commitMD(g.unvetted, id, "published")
		if err != nil {
			return nil, err
		}

		// Create and rebase PR
		err = g.rebasePR(id)
		if err != nil {
			return nil, err
		}

	case (record.RecordMetadata.Status == backend.MDStatusUnvetted ||
		record.RecordMetadata.Status == backend.MDStatusIterationUnvetted) &&
		status == backend.MDStatusCensored:
		// unvetted -> censored
		record.RecordMetadata.Status = backend.MDStatusCensored
		record.RecordMetadata.Iteration += 1
		record.RecordMetadata.Timestamp = time.Now().Unix()
		err = updateMD(g.unvetted, id, &record.RecordMetadata)
		if err != nil {
			return nil, err
		}

		// Handle metadata
		err = g.updateMetadata(id, mdAppend, mdOverwrite)
		if err != nil {
			return nil, err
		}

		// Commit brm
		err = g.commitMD(g.unvetted, id, "censored")
		if err != nil {
			return nil, err
		}
	default:
		return nil, backend.StateTransitionError{
			From: record.RecordMetadata.Status,
			To:   status,
		}
	}

	return g._getRecord(id, "", g.unvetted, false)
}

// SetUnvettedStatus tries to update the status for an unvetted record. It
// returns the updated record if successful but without the Files component.
//
// SetUnvettedStatus satisfies the backend interface.
func (g *gitBackEnd) SetUnvettedStatus(token []byte, status backend.MDStatusT, mdAppend, mdOverwrite []backend.MetadataStream) (*backend.Record, error) {
	// Lock filesystem
	g.Lock()
	defer g.Unlock()
	if g.shutdown {
		return nil, backend.ErrShutdown
	}

	log.Debugf("setting status %v (%v) -> %x", status,
		backend.MDStatus[status], token)
	record, err := g.setUnvettedStatus(token, status, mdAppend, mdOverwrite)
	if err != nil {
		// XXX this needs to call the unwind function instead
		// git stash
		err2 := g.gitUnwind(g.unvetted)
		if err2 != nil {
			log.Criticalf("SetUnvettedStatus: unwind %v", err2)
		}
		err2 = g.gitCheckout(g.unvetted, "master")
		if err2 != nil {
			log.Criticalf("SetUnvettedStatus: checkout %v", err2)
		}
		return nil, err
	}

	// git checkout master
	err = g.gitCheckout(g.unvetted, "master")
	if err != nil {
		return nil, err
	}

	return record, nil
}

// setVettedStatus takes various parameters to update a record metadata and
// status.  It goes through the normal stages of updating unvetted, pushing PR,
// merge PR, pull remote. Note that this function must be wrapped by a function
// that delivers the call with the unvetted repo sitting in master.  The idea
// is that if this function fails we can simply unwind it.
//
// setVettedStatus must be called with the lock held.
func (g *gitBackEnd) _setVettedStatus(token []byte, status backend.MDStatusT, mdAppend, mdOverwrite []backend.MetadataStream) (*backend.Record, error) {
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

	// Make sure vetted exists
	id := hex.EncodeToString(token)
	_, err = os.Stat(pijoin(g.unvetted, id))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, backend.ErrRecordNotFound
		}
	}

	// Make sure record is not locked.
	md, err := loadMD(g.unvetted, id, "")
	if err != nil {
		return nil, err
	}
	if md.Status == backend.MDStatusArchived {
		return nil, backend.ErrRecordArchived
	}

	// Load record
	record, err := g._getRecord(id, "", g.unvetted, false)
	if err != nil {
		return nil, err
	}

	// We only allow a transition from vetted to archived
	if record.RecordMetadata.Status != backend.MDStatusVetted ||
		status != backend.MDStatusArchived {
		return nil, backend.StateTransitionError{
			From: record.RecordMetadata.Status,
			To:   status,
		}
	}

	// Delete any leftover tmp branch. There shouldn't be one.
	idTmp := id + "_tmp"
	_ = g.gitBranchDelete(g.unvetted, idTmp)

	// Checkout temporary branch
	err = g.gitNewBranch(g.unvetted, idTmp)
	if err != nil {
		return nil, err
	}

	// Update MD first
	record.RecordMetadata.Status = backend.MDStatusArchived
	record.RecordMetadata.Iteration += 1
	record.RecordMetadata.Timestamp = time.Now().Unix()
	err = updateMD(g.unvetted, id, &record.RecordMetadata)
	if err != nil {
		return nil, err
	}

	// Handle metadata
	err = g.updateMetadata(id, mdAppend, mdOverwrite)
	if err != nil {
		return nil, err
	}

	// Commit changes
	err = g.commitMD(g.unvetted, id, "archived")
	if err != nil {
		return nil, err
	}

	// Create and rebase PR
	err = g.rebasePR(idTmp)
	if err != nil {
		return nil, err
	}

	return g._getRecord(id, "", g.unvetted, false)
}

// SetVettedStatus tries to update the status for a vetted record.  It returns
// the updated record if successful but without the Files component.
//
// SetVettedStatus satisfies the backend interface.
func (g *gitBackEnd) SetVettedStatus(token []byte, status backend.MDStatusT, mdAppend, mdOverwrite []backend.MetadataStream) (*backend.Record, error) {
	// Lock filesystem
	g.Lock()
	defer g.Unlock()
	if g.shutdown {
		return nil, backend.ErrShutdown
	}

	log.Debugf("setting status %v (%v) -> %x", status,
		backend.MDStatus[status], token)
	record, err := g._setVettedStatus(token, status, mdAppend, mdOverwrite)
	if err != nil {
		err2 := g.gitUnwind(g.unvetted)
		if err2 != nil {
			log.Debugf("SetVettedStatus: unwind %v", err2)
		}
		err2 = g.gitCheckout(g.unvetted, "master")
		if err2 != nil {
			log.Criticalf("SetVettedStatus: checkout %v", err2)
		}
		return nil, err
	}

	// git checkout master
	err = g.gitCheckout(g.unvetted, "master")
	if err != nil {
		return nil, err
	}

	return record, nil
}

// Inventory returns an inventory of vetted and unvetted records.  If
// includeFiles is set the content is also returned.
func (g *gitBackEnd) Inventory(vettedCount, branchCount uint, includeFiles, allVersions bool) ([]backend.Record, []backend.Record, error) {
	log.Debugf("Inventory: %v %v %v", vettedCount, branchCount, includeFiles)

	// Lock filesystem
	g.Lock()
	defer g.Unlock()
	if g.shutdown {
		return nil, nil, backend.ErrShutdown
	}

	// Walk vetted, we can simply take the vetted directory and sort the
	// entries by time.
	files, err := ioutil.ReadDir(g.vetted)
	if err != nil {
		return nil, nil, err
	}

	// Strip non record directories
	pr := make([]backend.Record, 0, len(files))
	for _, v := range files {
		id := v.Name()
		if !util.IsDigest(id) {
			continue
		}

		ids, err := hex.DecodeString(id)
		if err != nil {
			return nil, nil, err
		}
		prv, err := g.getRecord(ids, "", g.vetted, includeFiles)
		if err != nil {
			return nil, nil, err
		}
		pr = append(pr, *prv)

		if allVersions {
			// Include all versions of the proposal
			latest, err := strconv.Atoi(prv.Version)
			if err != nil {
				return nil, nil, err
			}
			for i := 1; i < latest; i++ {
				r, err := g.getRecord(ids, strconv.Itoa(i), g.vetted, includeFiles)
				if err != nil {
					return nil, nil, err
				}
				pr = append(pr, *r)
			}
		}
	}

	// Walk Branches on unvetted
	branches, err := g.gitBranches(g.unvetted)
	if err != nil {
		return nil, nil, err
	}
	br := make([]backend.Record, 0, len(branches))
	for _, id := range branches {
		if !util.IsDigest(id) {
			continue
		}

		ids, err := hex.DecodeString(id)
		if err != nil {
			return nil, nil, err
		}
		pru, err := g.getRecord(ids, "", g.unvetted, includeFiles)
		if err != nil {
			// We probably should not fail the entire call
			return nil, nil, err
		}
		br = append(br, *pru)
	}

	return pr, br, nil
}

// GetPlugins returns a list of currently supported plugins and their settings.
//
// GetPlugins satisfies the backend interface.
func (g *gitBackEnd) GetPlugins() ([]backend.Plugin, error) {
	log.Debugf("GetPlugins")
	return g.plugins, nil
}

// Plugin send a passthrough command. The return values are: incomming command
// identifier, encoded command result and an error if the command failed to
// execute.
//
// Plugin satisfies the backend interface.
func (g *gitBackEnd) Plugin(command, payload string) (string, string, error) {
	log.Debugf("Plugin: %v", command)
	switch command {
	case decredplugin.CmdAuthorizeVote:
		payload, err := g.pluginAuthorizeVote(payload)
		return decredplugin.CmdAuthorizeVote, payload, err
	case decredplugin.CmdStartVote:
		payload, err := g.pluginStartVote(payload)
		return decredplugin.CmdStartVote, payload, err
	case decredplugin.CmdBallot:
		payload, err := g.pluginBallot(payload)
		return decredplugin.CmdBallot, payload, err
	case decredplugin.CmdProposalVotes:
		payload, err := g.pluginProposalVotes(payload)
		return decredplugin.CmdProposalVotes, payload, err
	case decredplugin.CmdBestBlock:
		payload, err := g.pluginBestBlock()
		return decredplugin.CmdBestBlock, payload, err
	case decredplugin.CmdNewComment:
		payload, err := g.pluginNewComment(payload)
		return decredplugin.CmdNewComment, payload, err
	case decredplugin.CmdLikeComment:
		payload, err := g.pluginLikeComment(payload)
		return decredplugin.CmdLikeComment, payload, err
	case decredplugin.CmdCensorComment:
		payload, err := g.pluginCensorComment(payload)
		return decredplugin.CmdCensorComment, payload, err
	case decredplugin.CmdGetComments:
		payload, err := g.pluginGetComments(payload)
		return decredplugin.CmdGetComments, payload, err
	case decredplugin.CmdProposalCommentsLikes:
		payload, err := g.pluginGetProposalCommentsLikes(payload)
		return decredplugin.CmdProposalCommentsLikes, payload, err
	case decredplugin.CmdInventory:
		payload, err := g.pluginInventory()
		return decredplugin.CmdInventory, payload, err
	case decredplugin.CmdLoadVoteResults:
		payload, err := g.pluginLoadVoteResults()
		return decredplugin.CmdLoadVoteResults, payload, err
	}
	return "", "", fmt.Errorf("invalid payload command") // XXX this needs to become a type error
}

// Close shuts down the backend.  It obtains the lock and sets the shutdown
// boolean to true.  All interface functions MUST return with errShutdown if
// the backend is shutting down.
//
// Close satisfies the backend interface.
func (g *gitBackEnd) Close() {
	log.Debugf("Close")

	g.Lock()
	defer g.Unlock()

	g.shutdown = true
	close(g.exit)
}

// newLocked runs the portion of new that has to be locked.
func (g *gitBackEnd) newLocked() error {
	g.Lock()
	defer g.Unlock()

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

	// Fsck _o/
	log.Infof("Running git fsck on vetted repository")
	_, err = g.gitFsck(g.vetted)
	if err != nil {
		return err
	}
	log.Infof("Running git fsck on unvetted repository")
	_, err = g.gitFsck(g.unvetted)
	return err
}

// rebasePR pushes branch id into upstream (vetted repo) and rebases it onto
// master followed by replaying the rebase into origin (unvetted repo).
// This function must be called with the lock held.
func (g *gitBackEnd) rebasePR(id string) error {
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
	err := g.gitCheckout(g.unvetted, "master")
	if err != nil {
		return err
	}

	// git pull --ff-only --rebase
	err = g.gitPull(g.unvetted, true)
	if err != nil {
		return err
	}

	// git checkout id
	err = g.gitCheckout(g.unvetted, id)
	if err != nil {
		return backend.ErrRecordNotFound
	}

	// git rebase master
	err = g.gitRebase(g.unvetted, "master")
	if err != nil {
		return err
	}

	// git push --set-upstream origin id
	err = g.gitPush(g.unvetted, "origin", id, true)
	if err != nil {
		return err
	}

	//
	// VETTED REPO REPLAY BRANCH
	//

	// git rebase id
	err = g.gitRebase(g.vetted, id)
	if err != nil {
		return err
	}

	// git branch -D id
	err = g.gitBranchDelete(g.vetted, id)
	if err != nil {
		return err
	}

	//
	// UNVETTED REPO SYNC
	//

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

	// git branch -D id
	return g.gitBranchDelete(g.unvetted, id)
}

// New returns a gitBackEnd context.  It verifies that git is installed.
func New(anp *chaincfg.Params, root string, dcrtimeHost string, gitPath string, id *identity.FullIdentity, gitTrace bool) (*gitBackEnd, error) {
	// Default to system git
	if gitPath == "" {
		gitPath = "git"
	}

	g := &gitBackEnd{
		activeNetParams: anp,
		root:            root,
		cron:            cron.New(),
		unvetted:        filepath.Join(root, DefaultUnvettedPath),
		vetted:          filepath.Join(root, DefaultVettedPath),
		journals:        filepath.Join(root, DefaultJournalsPath),
		gitPath:         gitPath,
		dcrtimeHost:     dcrtimeHost,
		gitTrace:        gitTrace,
		exit:            make(chan struct{}),
		checkAnchor:     make(chan struct{}),
		testAnchors:     make(map[string]bool),
		plugins:         []backend.Plugin{getDecredPlugin(anp.Name != "mainnet")},
	}
	idJSON, err := id.Marshal()
	if err != nil {
		return nil, err
	}
	setDecredPluginSetting(decredPluginIdentity, string(idJSON))
	setDecredPluginSetting(decredPluginJournals, g.journals)
	setDecredPluginHook(PluginPostHookEdit, g.decredPluginPostEdit)

	// Create jounals path
	// XXX this needs to move into plugin init
	log.Infof("Journals directory: %v", g.journals)
	err = os.MkdirAll(g.journals, 0760)
	if err != nil {
		return nil, err
	}

	g.journal = NewJournal()

	// this function must be called after g.journal is created
	err = g.initDecredPluginJournals()
	if err != nil {
		return nil, err
	}

	err = g.newLocked()
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
		// Flush journals
		g.decredPluginJournalFlusher()

		// Anchor commit
		g.anchorAllReposCronJob()
	})
	if err != nil {
		return nil, err
	}
	g.cron.Start()

	// Message user
	log.Infof("Timestamp host: %v", g.dcrtimeHost)

	log.Infof("Running dcrtime fsck on vetted repository")
	err = g.fsck(g.vetted)
	if err != nil {
		// Log error but continue
		log.Errorf("fsck: dcrtime %v", err)
	}

	return g, nil
}
