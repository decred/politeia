package main

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// parseVoteTimestamps parses the cast vote timestamps from the git command for
// the provided git record repository path. It returns a double map of the form
// [legacyToken][ticket]timestamp.
func parseVoteTimestamps(path string) (map[string]map[string]int64, error) {
	args := []string{"log", "--reverse", "-p"}

	cmd := exec.Command("git", args...)
	cmd.Dir = path

	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

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

	results := make(map[string]map[string]int64) // [token][ticket]timestamp
	for _, i := range items {

		for _, f := range i.Patch {

			if _, ok := results[f.Token]; !ok {
				results[f.Token] = make(map[string]int64)
			}
			for _, v := range f.VotesInfo {
				results[f.Token][v.Ticket] = i.Date.Unix()
			}
		}
	}

	return results, nil
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
	// Receipt string `json:"receipt"`
}

// PiVote defines the ticket hash and vote bit type details about a vote.
type PiVote struct {
	// Token     string  `json:"token"`
	Ticket  string `json:"ticket"`
	VoteBit string `json:"votebit"`
	// Signature string  `json:"signature"`
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

		// If the proposal token has been set, check if this payload has the required
		// proposal token data. If it exists proceed otherwise ignore it.
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

		// Add the square brackets and commas to complete the JSON string array format.
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
	// DefaultRepo is the default github repository name where Politea Votes
	// are stored.
	DefaultRepo = "mainnet"

	// DefaultRepoOwner is the owner of the default github repository where
	// Politeia votes are stored.
	DefaultRepoOwner = "decred-proposals"

	// DefaultVotesCommitMsg defines the message of the commits that holds
	// the votes data for the various proposal token(s).
	DefaultVotesCommitMsg = "Flush vote journals"

	// CmdDateFormat defines the date format of the time returned by git commandline
	// interface. Time format is known as RFC2822.
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
		return PiRegExp(`(` + journalSelection() + `[[:ascii:]]*(}\n?))`)
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

// IsMatching returns boolean true if the matchRegex can be matched in the parent
// string.
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
// value in the provided parent string. The fetched date string is converted into
// a time.Time objected using "Mon Jan 2 15:04:05 2006 -0700" date format.
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

// ReplaceJournalSelection uses journalSelection regex expression to replace the
// journal action in the provided parent string using the provided replacement.
func ReplaceJournalSelection(parent, with string) string {
	return journalSelection().exp().ReplaceAllLiteralString(parent, with)
}

// ReplaceAny replaces the all occurrence of "regex" in string "parent" with
// replacement "with" for all the possible occurrences.
func ReplaceAny(parent, regex, with string) string {
	r := regexp.MustCompile(regex)
	return r.ReplaceAllLiteralString(parent, with)
}
