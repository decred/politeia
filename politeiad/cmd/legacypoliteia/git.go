// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/decred/politeia/politeiad/cmd/legacypoliteia/gitbe"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
)

var (
	// Regular expression that matches the git proposal token from a proposal
	// parent directory.
	expGitProposalToken   = `[0-9a-f]{64}`
	regexGitProposalToken = regexp.MustCompile(expGitProposalToken)
)

// gitProposalToken takes a git repo path and returns the proposal token from
// the path if the path corresponds to the proposal parent directory.
//
// Input:
// "fdd68c87961549750adf29e178128210cb310294080211cf6a35792aa1bb7f63.json"
// Output:
// "fdd68c87961549750adf29e178128210cb310294080211cf6a35792aa1bb7f63", true
//
// Input:
// "mainnet/fdd68c87961549750adf29e178128210cb310294080211cf6a35792aa1bb7f63/1"
// Output:
// "fdd68c87961549750adf29e178128210cb310294080211cf6a35792aa1bb7f63", true
func gitProposalToken(path string) (string, bool) {
	var (
		gitToken = regexGitProposalToken.FindString(path)
		ok       = (gitToken != "")
	)
	return gitToken, ok
}

// gitProposalTokens recursively walks the provided directory and returns an
// inventory of all git proposal tokens found in file paths.
func gitProposalTokens(dirPath string) (map[string]struct{}, error) {
	tokens := make(map[string]struct{}, 256)
	err := filepath.WalkDir(dirPath,
		func(path string, d fs.DirEntry, err error) error {
			// We only care about directories
			if !d.IsDir() {
				return nil
			}

			// Get the token from the path
			token, ok := gitProposalToken(path)
			if ok {
				tokens[token] = struct{}{}
				return nil
			}

			return nil
		})
	if err != nil {
		return nil, err
	}
	return tokens, nil
}

// latestVersion returns the latest version of a legacy git proposal. The
// version number is parsed from the directory structure.
func latestVersion(gitRepo, token string) (uint64, error) {
	// Compile a list of all directories. The version numbers
	// are the directory name.
	dirs := make(map[string]struct{}, 64)
	err := filepath.WalkDir(filepath.Join(gitRepo, token),
		func(path string, d fs.DirEntry, err error) error {
			if !d.IsDir() {
				return nil
			}
			dirs[d.Name()] = struct{}{}
			return nil
		})
	if err != nil {
		return 0, err
	}

	// Parse the version number from the directory name
	versions := make(map[uint64]struct{}, 64)
	for dirname := range dirs {
		u, err := strconv.ParseUint(dirname, 10, 32)
		if err != nil {
			// Not a version directory
			continue
		}
		versions[u] = struct{}{}
	}
	if err != nil {
		return 0, err
	}

	// Find the most recent version
	var latest uint64
	for version := range versions {
		if version > latest {
			latest = version
		}
	}
	if latest == 0 {
		return 0, fmt.Errorf("latest version not found for %v", token)
	}

	return latest, nil
}

var (
	// Regular expersion that matches the token and version number from a
	// proposal directory path.
	expProposalVersion   = `[0-9a-f]{64}\/[0-9]{1,}`
	regexProposalVersion = regexp.MustCompile(expProposalVersion)
)

// proposalVersion parses the version number for the proposal directory path
// and returns it.
func proposalVersion(proposalDir string) (uint32, error) {
	var (
		subPath    = regexProposalVersion.FindString(proposalDir)
		versionStr = filepath.Base(subPath)
	)
	u, err := strconv.ParseUint(versionStr, 10, 32)
	if err != nil {
		return 0, err
	}

	return uint32(u), nil
}

// proposalAttachmentFiles returns the filesnames of all proposal attachment
// files. This function does NOT return the file path, just the file name. The
// proposal index file and proposal metadata file are not considered to be
// attachments.
func proposalAttachmentFilenames(proposalDir string) ([]string, error) {
	var (
		notAnAttachmentFile = map[string]struct{}{
			gitbe.IndexFilename:            {},
			gitbe.ProposalMetadataFilename: {},
		}

		payloadDir = payloadDirPath(proposalDir)
		filenames  = make([]string, 0, 64)
	)

	// Walk the payload directory
	err := filepath.WalkDir(payloadDir,
		func(path string, d fs.DirEntry, err error) error {
			// There shouldn't be any nested directories
			// in the payload directory, but check just
			// in case.
			if d.IsDir() {
				return nil
			}

			if _, ok := notAnAttachmentFile[d.Name()]; ok {
				// Not an attachment; skip
				return nil
			}

			// This is an attachment file
			filenames = append(filenames, d.Name())

			return nil
		})
	if err != nil {
		return nil, err
	}

	return filenames, nil
}

// parseVoteTimestamps parses the cast vote timestamps from the git command for
// the provided git record repository path. It returns a map of the form:
// [ticket]timestamp.
func parseVoteTimestamps(proposalDir string, voteDetails *ticketvote.VoteDetails, filteredHashes []string) (map[string]int64, error) {
	if voteDetails == nil {
		// Noting to do
		return nil, nil
	}

	fmt.Printf("  Fetching git timestamps, this might take a while...\n")
	args := []string{"log", "--reverse", "-p"}

	cmd := exec.Command("git", args...)
	cmd.Dir = proposalDir

	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}
	fmt.Printf("  Fetched git log, parsing commits history...\n")

	data := strings.Split(string(out), "commit")
	var items []*History
	for _, entry := range data {
		// Skip if entry is whitespace.
		if len(strings.TrimSpace(entry)) == 0 {
			continue
		}

		var h History
		if err = CustomUnmashaller(&h, entry); err != nil {
			return nil, fmt.Errorf("CustomUnmashaller failed: %v", err)
		}

		// Do not store any empty history data, which may occur with the custom
		// unmarshaller.
		if len(h.Patch) == 0 || h.Author == "" || h.CommitSHA == "" {
			continue
		}

		items = append(items, &h)
	}

	results := make(map[string]int64) // [token][ticket]timestamp
	for _, i := range items {
		for _, f := range i.Patch {
			for _, v := range f.VotesInfo {
				// If tickets are limited, filter out irrelevant hashes
				if len(filteredHashes) > 0 &&
					!isTicketHashFound(v.Ticket, filteredHashes) {
					continue
				}

				results[v.Ticket] = i.Date.Unix()
			}
		}
	}

	return results, nil
}

// isTicketHashFound returns whether the given ticket hash found in the
// given ticket hashes slice.
func isTicketHashFound(hash string, hashes []string) bool {
	for _, h := range hashes {
		if h == hash {
			return true
		}
	}

	return false
}

// This code is based on go-piparser package.

// History defines the standard single commit history contents to be shared
// with the outside world.
type History struct {
	Author    string
	CommitSHA string
	Date      time.Time
	Patch     []*File
}

type File struct {
	Token     string
	VotesInfo []CastVoteData
}

type Votes []CastVoteData

// CastVoteData defines the struct of a cast vote and the receipt response.
type CastVoteData struct {
	*PiVote `json:"castvote"`
	Receipt string `json:"receipt"`
}

// PiVote defines the ticket hash and vote bit type details about a vote.
type PiVote struct {
	Token     string `json:"token"`
	Ticket    string `json:"ticket"`
	VoteBit   string `json:"votebit"`
	Signature string `json:"signature"`
}

func CustomUnmashaller(h *History, str string) error {
	// If no votes data detected, ignore the current str payload.
	if isMatched := IsMatching(str, DefaultVotesCommitMsg); !isMatched {
		return nil
	}

	date, err := RetrieveCMDDate(str)
	if err != nil {
		return err // Missing Date
	}

	commit, err := RetrieveCMDCommit(str)
	if err != nil {
		return err // Missing commit SHA
	}

	author, err := RetrieveCMDAuthor(str)
	if err != nil {
		return err // Missing Author
	}

	var changes []*File
	for _, filePatch := range strings.Split(str, commitDiff) {

		// If the proposal token has been set, check if this payload has the
		// required proposal token data. If it exists proceed otherwise ignore it.
		if isMatched := IsMatching(filePatch, VotesJSONSignature()); !isMatched {
			continue
		}

		proposalToken, err := RetrieveProposalToken(filePatch)
		if err != nil {
			return err // Missing proposal token
		}

		filePatch = RetrieveAllPatchSelection(filePatch)

		filePatch = ReplaceJournalSelection(filePatch, "")

		// Drop any special characters left.
		filePatch = ReplaceAny(filePatch, `\s`, "")

		// Add the square brackets and commas to complete the JSON string array
		// format.
		filePatch = "[" + ReplaceAny(filePatch, "}{", "},{") + "]"

		var v Votes

		if err = json.Unmarshal([]byte(filePatch), &v); err != nil {
			panic(err)
		}

		// If votes data was found, append it the File patch data else ignore it.
		if len(v) > 0 {
			changes = append(changes, &File{proposalToken, v})
		}
	}

	if len(changes) == 0 {
		return nil
	}

	h.Author = author
	h.CommitSHA = commit
	h.Date = date
	h.Patch = changes

	return nil
}

// VotesJSONSignature defines a part of the json string signature that matches
// the commit patch string required. The matched commit patch string contains
// the needed votes data.
func VotesJSONSignature() string {
	return fmt.Sprintf(`{"castvote":{"token":"%s",`, anyTokenSelection)
}

// REGEX functions
// This code is based on go-piparser package.

type PiRegExp string

const (
	// DefaultVotesCommitMsg defines the message of the commits that holds
	// the votes data for the various proposal token(s).
	DefaultVotesCommitMsg = "Flush vote journals"

	// CmdDateFormat defines the date format of the time returned by git
	// commandline interface. Time format is known as RFC2822.
	CmdDateFormat = "Mon Jan 2 15:04:05 2006 -0700"

	// journalActionFormat is the format of the journal action struct appended
	// to all votes. Its a struct with the version and the journal action.
	journalActionFormat = `{"version":"[[:digit:]]*","action":"(add)?(del)?(addlike)?"}`
)

var (
	// cmdAuthorSelection matches a text line that starts with 'Author' and ends
	// with line ending character(s) or its the actual end of the line.
	cmdAuthorSelection PiRegExp = `Author[:\s]*(.*)`

	// cmdCommitSelection matches a text line that starts with 'commit' or a
	// white space character and ends with line ending character(s) or its the
	// actual end of the line. The commit SHA part will always be the start of
	// the commit message after the whole git cmd history string is split into
	// individual messages.
	cmdCommitSelection PiRegExp = `[(^ )commit]*[:\s]*(.*)`

	// cmdDateSelection matches a text line that starts with 'Date' and ends with
	// line ending character(s) or its the actual end of the line.
	cmdDateSelection PiRegExp = `Date[:\s]*(.*)`

	// journalSelection matches the vote journal text line that takes the format,
	// +{"version":"\d","action":"(add|del|addlike)"} e.g +{"version":"1","action":"add"}
	// This journal section is appended to every individual vote cast result.
	journalSelection = func() PiRegExp {
		return PiRegExp(`[+]` + journalActionFormat)
	}

	// patchSelection matches the flushed votes changes pushed for the current
	// commit SHA. It matches all valid votes for the current time and commit.
	// It starts where the journalSelection on a text line matches and ends where
	// the line ending characters at matched at on the same text line.
	patchSelection = func() PiRegExp {
		return `(` + journalSelection() + `[[:ascii:]]*(}\n?))`
	}

	// anyTokenSelection matches any proposal token. A proposal token is
	// defined by 64 alphanumeric characters which can be upper case or lower
	// case of any letter, exclusive of punctuations and white space characters.
	anyTokenSelection = `[A-z0-9]{64}`

	// In a git commit history, the changes made per file always start with
	// "diff --git a". commitDiff is therefore used to split the single commit
	// string into file changes in an array. "diff --git a" is documented here:
	// https://github.com/git/git/blob/b58f23b38a9a9f28d751311353819d3cdf6a86da/t/t4000-diff-format.sh#L29-L46
	commitDiff = `diff --git a`

	// gitVersionSelection selects the underlying platform git semantic version.
	gitVersionSelection PiRegExp = "([[:digit:]]+).([[:digit:]]+).([[:digit:]]+)"
)

// exp compiles the PiRegExp regex expression type.
func (e PiRegExp) exp() *regexp.Regexp { return regexp.MustCompile(string(e)) }

// IsMatching returns boolean true if the matchRegex can be matched in the
// parent string.
func IsMatching(parent, matchRegex string) bool {
	isMatched, err := regexp.MatchString(matchRegex, parent)
	if !isMatched || err != nil {
		return false
	}
	return true
}

// RetrieveAllPatchSelection uses patchSelection regex expression to fetch all
// individual matching lines from the provided parent string.
func RetrieveAllPatchSelection(parent string) string {
	matches := patchSelection().exp().FindAllString(parent, -1)
	return strings.Join(matches, "")
}

// RetrieveProposalToken uses the anyTokenSelection regex to build a regex
// expression used to select the proposal token from the parent string.
func RetrieveProposalToken(parent string) (string, error) {
	regex := fmt.Sprintf(`"token":"(%s)`, anyTokenSelection)
	data := PiRegExp(regex).exp().FindStringSubmatch(parent)
	if len(data) > 1 && data[1] != "" {
		return data[1], nil
	}

	return "", fmt.Errorf("missing token from the parsed string")
}

// RetrieveCMDAuthor uses cmdAuthorSelection regex expression to retrieve the
// Author value in the provided parent string.
func RetrieveCMDAuthor(parent string) (string, error) {
	data := cmdAuthorSelection.exp().FindStringSubmatch(parent)
	if len(data) > 1 && data[1] != "" {
		return data[1], nil
	}
	return "", fmt.Errorf("missing Author from the parsed string")
}

// RetrieveCMDDate uses cmdDateSelection regex expression to retrieve the Date
// value in the provided parent string. The fetched date string is converted
// into a time.Time objected using "Mon Jan 2 15:04:05 2006 -0700" date format.
func RetrieveCMDDate(parent string) (time.Time, error) {
	data := cmdDateSelection.exp().FindStringSubmatch(parent)
	if len(data) > 1 && data[1] != "" {
		return time.Parse(CmdDateFormat, data[1])
	}
	return time.Time{}, fmt.Errorf("missing Date from the parsed string")
}

// RetrieveCMDCommit uses cmdCommitSelection to retrieve the commit SHA value
// from the provided parent string.
func RetrieveCMDCommit(parent string) (string, error) {
	data := cmdCommitSelection.exp().FindStringSubmatch(parent)
	if len(data) > 1 && data[1] != "" {
		return data[1], nil
	}
	return "", fmt.Errorf("missing commit from the parsed string")
}

// ReplaceJournalSelection uses journalSelection regex expression to replace
// the journal action in the provided parent string using the provided
// replacement.
func ReplaceJournalSelection(parent, with string) string {
	return journalSelection().exp().ReplaceAllLiteralString(parent, with)
}

// ReplaceAny replaces the all occurrence of "regex" in string "parent" with
// replacement "with" for all the possible occurrences.
func ReplaceAny(parent, regex, with string) string {
	r := regexp.MustCompile(regex)
	return r.ReplaceAllLiteralString(parent, with)
}
