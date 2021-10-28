package main

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

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

// ReplaceAny replaces the all occurence of "regex" in string "parent" with
// replacement "with" for all the possible occurences.
func ReplaceAny(parent, regex, with string) string {
	r := regexp.MustCompile(regex)
	return r.ReplaceAllLiteralString(parent, with)
}
