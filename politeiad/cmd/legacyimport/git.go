package main

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

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

// CastVoteData defines the struct of a cast vote and the reciept response.
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

func gitData(path string) (map[string]map[string]int64, error) {
	args := []string{"log", "--reverse", "-p"}

	cmd := exec.Command("git", args...)
	cmd.Dir = "/Users/thiagofigueiredo/go/src/github.com/decred/mainnet"

	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

	data := strings.Split(string(out), "commit")
	var items []*History
	for _, entry := range data {
		// Skip if entry is a whitespace.
		if len(strings.TrimSpace(entry)) == 0 {
			continue
		}

		var h History

		if err = CustomUnmashaller(&h, entry); err != nil {
			return nil, fmt.Errorf("CustomUnmashaller failed: %v", err)
		}

		// Do not store any empty history data.
		if len(h.Patch) == 0 || h.Author == "" || h.CommitSHA == "" {
			continue
		}

		items = append(items, &h)
	}

	results := make(map[string]map[string]int64) // [token][ticket]timestmap
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
