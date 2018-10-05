// Copyright (c) 2017-2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package gitbe

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/decred/dcrtime/merkle"
)

// An anchor corresponds to a set of git commit hashes, along with their
// merkle root, that get checkpointed in dcrtime. This provides censorship
// resistance by anchoring activity on politeia to the blockchain.
//
// To help process anchors, we need to look up the last anchor and unconfirmed anchors that
// have not been checkpointed in dcrtime yet. To identify these, we parse the
// git log, which keeps a record of all anchors dropped and anchors confirmed.

// AnchorType discriminates between the various Anchor record types.
type AnchorType uint32

const (
	AnchorInvalid    AnchorType = 0 // Invalid anchor
	AnchorUnverified AnchorType = 1 // Unverified anchor
	AnchorVerified   AnchorType = 2 // Verified anchor
)

type Anchor struct {
	Type     AnchorType // Type of anchor this record represents
	Time     int64      // OS time when record was created
	Digests  [][]byte   // All digests that were merkled to get to key of record
	Messages []string   // All one-line Commit messages
	// len(Digests) == len(Messages) and index offsets are linked. e.g. Digests[15]
	// commit messages is in Messages[15].
}

// LastAnchor stores the last commit anchored in dcrtime.
type LastAnchor struct {
	Last   []byte // Last git digest that was anchored
	Time   int64  // OS time when record was created
	Merkle []byte // Merkle root that points to Anchor record, if valid
}

// UnconfirmedAnchor stores Merkle roots of anchors that have not been confirmed
// yet by dcrtime.
type UnconfirmedAnchor struct {
	Merkles [][]byte // List of Merkle root that points to Anchor records
}

// newAnchorRecord creates an Anchor Record and the Merkle Root from the
// provided pieces.  Note that the merkle root is of the git digests!
func newAnchorRecord(t AnchorType, digests []*[sha256.Size]byte, messages []string) (*Anchor, *[sha256.Size]byte, error) {
	if len(digests) != len(messages) {
		return nil, nil, fmt.Errorf("invalid digest and messages length")
	}

	if t == AnchorInvalid {
		return nil, nil, fmt.Errorf("invalid anchor type")
	}

	a := Anchor{
		Type:     t,
		Messages: messages,
		Digests:  make([][]byte, 0, len(digests)),
		Time:     time.Now().Unix(),
	}

	for _, digest := range digests {
		d := make([]byte, sha256.Size)
		copy(d, digest[:])
		a.Digests = append(a.Digests, d)
	}

	return &a, merkle.Root(digests), nil
}

type GitCommit struct {
	Hash    string
	Time    int64
	Message []string
	Error   error
}

var (
	regexCommitHash           = regexp.MustCompile(`^commit\s+(\S+)`)
	regexCommitDate           = regexp.MustCompile(`^Date:\s+(.+)`)
	anchorConfirmationPattern = fmt.Sprintf(`\s*%s\s*(\S*)`, markerAnchorConfirmation)
	regexAnchorConfirmation   = regexp.MustCompile(anchorConfirmationPattern)
	anchorPattern             = fmt.Sprintf(`\s*%s\s*(\S*)`, markerAnchor)
	regexAnchor               = regexp.MustCompile(anchorPattern)
)

const (
	gitDateTemplate = "Mon Jan 2 15:04:05 2006 -0700"
)

// extractCommit takes a slice of a git log and parses the next commit into a GitCommit struct.
func extractCommit(logSlice []string) (*GitCommit, int, error) {
	var commit GitCommit

	// Make sure we're at the start of a new commit
	firstLine := logSlice[0]
	if !regexCommitHash.MatchString(firstLine) {
		return nil, 0, fmt.Errorf("Error parsing git log. Commit expected, found %q instead", firstLine)
	}
	commit.Hash = regexCommitHash.FindStringSubmatch(logSlice[0])[1]

	// Skip the next line, which has the commit author

	dateLine := logSlice[2]
	if !regexCommitDate.MatchString(dateLine) {
		return nil, 0, fmt.Errorf("Error parsing git log. Date expected, found %q instead", dateLine)
	}
	dateStr := regexCommitDate.FindStringSubmatch(logSlice[2])[1]
	commitTime, err := time.Parse(gitDateTemplate, dateStr)
	if err != nil {
		return nil, 0, fmt.Errorf("Error parsing git log. Unable to parse date: %v", err)
	}
	commit.Time = commitTime.Unix()

	// The first three lines are the commit hash, the author, and the date.
	// The fourth is a blank line. Start accumulating the message at the 5th line.
	// Append message lines until the start of the next commit is found.
	for _, line := range logSlice[4:] {
		if regexCommitHash.MatchString(line) {
			break
		}

		commit.Message = append(commit.Message, line)
	}

	// In total, we used 4 lines initially, plus the number of lines in the message.
	return &commit, len(commit.Message) + 4, nil
}

// Some helper functions to navigate git commit message bodies

// anchorConfirmationMerkle extracts the Merkle Root from an anchor confirmation commit.
func anchorConfirmationMerkle(commit *GitCommit) string {
	anchorConfirmations := regexAnchorConfirmation.FindStringSubmatch(commit.Message[0])
	if len(anchorConfirmations) < 2 {
		return ""
	}
	return anchorConfirmations[1]
}

// anchorConfirmationMerkle extracts the Merkle Root from an anchor commit.
func anchorCommitMerkle(commit *GitCommit) string {
	return regexAnchor.FindStringSubmatch(commit.Message[0])[1]
}

// parseAnchorCommit returns a list of digest bytes from an anchor GitCommit,
// as well as a list of commit messages for what was commited.
func parseAnchorCommit(commit *GitCommit) ([][]byte, []string, error) {
	// Make sure it is an anchor commit
	firstLine := commit.Message[0]
	if !regexAnchor.MatchString(firstLine) {
		return nil, nil, fmt.Errorf("Error parsing git log. Expected an anchor commit. Instead got %q", firstLine)
	}

	// Hashes are listed starting from the 3rd line in the commit message
	// The hash is the first word in the line. The commit message is the rest.
	// Ignore the last blank line
	var digests [][]byte
	var messages []string
	for _, line := range commit.Message[2 : len(commit.Message)-1] {
		// The first word is the commit hash. The rest is the one-line commit message.
		lineParts := strings.SplitN(line, " ", 2)
		digest, err := hex.DecodeString(lineParts[0])
		if err != nil {
			return nil, nil, err
		}
		digests = append(digests, digest)
		messages = append(messages, lineParts[1])
	}

	return digests, messages, nil
}

// readAnchorRecord matches an anchor by its Merkle root and retrieves it from the git log.
func (g *gitBackEnd) readAnchorRecord(key [sha256.Size]byte) (*Anchor, error) {
	// Get the git log
	gitLog, err := g.gitLog(g.vetted)
	if err != nil {
		return nil, err
	}

	// Iterate over commits to find the target anchor
	keyStr := hex.EncodeToString(key[:])
	anchorConfirmed := AnchorUnverified
	currLine := 0
	for currLine < len(gitLog) {
		commit, linesUsed, err := extractCommit(gitLog[currLine:])
		if err != nil {
			return nil, err
		}
		currLine = currLine + linesUsed

		// Check the first line to see if the commit matches the target
		firstLine := commit.Message[0]
		// If it is an anchor confirmation, mark the anchor as verified but
		// keep looking for the main anchor commit
		if regexAnchorConfirmation.MatchString(firstLine) &&
			keyStr == anchorConfirmationMerkle(commit) {
			anchorConfirmed = AnchorVerified
		} else if regexAnchor.MatchString(firstLine) &&
			keyStr == anchorCommitMerkle(commit) {
			// Found the anchor
			digests, messages, err := parseAnchorCommit(commit)
			if err != nil {
				return nil, err
			}
			return &Anchor{
				Type:     anchorConfirmed,
				Time:     commit.Time,
				Digests:  digests,
				Messages: messages,
			}, nil
		}
	}

	// Anchor wasn't found
	return nil, fmt.Errorf("Anchor not found for key %v", key)
}

// readLastAnchorRecord retrieves the last anchor record.
func (g *gitBackEnd) readLastAnchorRecord() (*LastAnchor, error) {
	// Get the git log
	gitLog, err := g.gitLog(g.vetted)
	if err != nil {
		return nil, err
	}

	// Iterate over commits to find the last anchor
	var found bool
	var la LastAnchor
	var lastAnchorCommit *GitCommit
	currLine := 0
	for currLine < len(gitLog) {
		commit, linesUsed, err := extractCommit(gitLog[currLine:])
		if err != nil {
			return nil, err
		}
		currLine = currLine + linesUsed

		// Check the first line of the commit message
		// Make sure it is an anchor, not an anchor confirmation
		if !regexAnchorConfirmation.MatchString(commit.Message[0]) &&
			regexAnchor.MatchString(commit.Message[0]) {
			found = true
			lastAnchorCommit = commit
			break
		}
	}
	// If not found, return a blank last anchor
	if !found {
		return &la, nil
	}

	merkleStr := anchorCommitMerkle(lastAnchorCommit)
	merkleBytes, err := hex.DecodeString(merkleStr)
	if err != nil {
		return nil, err
	}
	la.Merkle = merkleBytes
	la.Time = lastAnchorCommit.Time

	hashBytes, err := hex.DecodeString(lastAnchorCommit.Hash)
	if err != nil {
		return nil, err
	}
	la.Last = extendSHA1(hashBytes)

	return &la, nil
}

// readUnconfirmedAnchorRecord retrieves the unconfirmed anchor record.
func (g *gitBackEnd) readUnconfirmedAnchorRecord() (*UnconfirmedAnchor, error) {
	// Get the git log
	gitLog, err := g.gitLog(g.vetted)
	if err != nil {
		return nil, err
	}

	// Look for unconfirmed commits and store their Merkle roots
	// Stop looking at the latest confirmed commit
	var ua UnconfirmedAnchor
	currLine := 0
	for currLine < len(gitLog) {
		commit, linesUsed, err := extractCommit(gitLog[currLine:])
		if err != nil {
			return nil, err
		}
		currLine = currLine + linesUsed

		// Check the first line of the commit message to see if it is an
		// anchor confirmation or an anchor.
		firstLine := commit.Message[0]
		if regexAnchorConfirmation.MatchString(firstLine) {
			// Found the latest confirmed anchor. Stop looking.
			break
		} else if regexAnchor.MatchString(firstLine) {
			merkleStr := anchorCommitMerkle(commit)
			merkleBytes, err := hex.DecodeString(merkleStr)
			if err != nil {
				return nil, err
			}
			ua.Merkles = append(ua.Merkles, merkleBytes)
		}
	}

	return &ua, nil
}
