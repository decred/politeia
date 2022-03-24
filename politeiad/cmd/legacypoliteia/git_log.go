// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/decred/politeia/politeiad/cmd/legacypoliteia/gitbe"
)

// git_log.go contains the code that runs the git log command and parses
// its output.

// parseVoteTimestamps parses the git commit log and returns the vote
// timestamps for each of the cast votes in a proposal's ballot journal. The
// timestamps are not actually the exact timestamp of when the vote was cast,
// but rather the timestamp of the git commit that added the vote to the git
// repo.
//
// Note, it's possible for a commit to contain the ballot journal updates from
// multiple proposal votes when the votes occur at the same time. This is fine.
// It just means that the returned map may contain additional vote timestamps.
// The caller should not assume that only the vote timestamps being returned
// are for the specified proposal.
func parseVoteTimestamps(proposalDir string) (map[string]int64, error) {
	fmt.Printf("    Parsing the vote timestamps from the git logs...\n")

	// The following command is run from the decred plugin directory
	// for the proposal.
	//
	// $ /usr/bin/git log --reverse -p ballot.journal
	//
	// Decred plugin dir: /[token]/[version]/plugins/decred
	//
	// This command logs the commits that touched the ballot.journal.
	// The commit details and full diff are logged. We parse these logs
	// to find when each vote was committed to the ballot journal and
	// associate the vote with the timestamp of the commit that added
	// it.
	//
	// See sample_commit.txt for an example of what a commit will look
	// like. The output will contain all commits that touched the
	// ballots journal file.
	var (
		decredPluginDir = filepath.Join(proposalDir, gitbe.DecredPluginPath)

		args = []string{"log", "--reverse", "-p", gitbe.BallotJournalFilename}
		cmd  = exec.Command("git", args...)
	)
	cmd.Dir = decredPluginDir

	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	// Split the output into individual commits. A commit
	// will start with "commit [commitHash]".
	//
	// Ex: "commit b09912047e9ffc82c944f9f82d2384bc23b4b3b9"
	rawCommits := strings.Split(string(out), "commit")

	// Parse the commit timestamp and ticket hashes from the
	// raw commit text and associate each ticket hash with a
	// commit timestamp.
	voteTimestamps := make(map[string]int64, 40960) // [ticket]unixTime
	for i, rawCommit := range rawCommits {
		s := fmt.Sprintf("    Parsing ballot journal commit %v/%v",
			i+1, len(rawCommits))
		printInPlace(s)

		// Skip empty entries
		rawCommit = strings.TrimSpace(rawCommit)
		if len(rawCommit) == 0 {
			continue
		}

		// Parse the commit date
		t, err := parseCommitDate(rawCommit)
		if err != nil {
			return nil, err
		}

		// Parse the votes
		castVotes, err := parseCastVotes(rawCommit)
		if err != nil {
			return nil, err
		}

		// Associate each vote in the commit with the
		// commit timestamp.
		for _, cv := range castVotes {
			voteTimestamps[cv.Ticket] = t.Unix()
		}
	}

	fmt.Printf("\n")
	fmt.Printf("    %v vote timestamps found\n", len(voteTimestamps))

	return voteTimestamps, nil
}

var (
	// dateLineRegExp matches the date line from a git commit log message.
	//
	// Ex: "Date:   Sun Apr 11 18:58:01 2021 +0000"
	dateLineRegExp = regexp.MustCompile(`Date[:\s]*(.*)`)

	// commitDateLayout is the date layout that is used in a git commit log
	// message.
	commitDateLayout = "Mon Jan 2 15:04:05 2006 -0700"
)

// parseCommitDate parses the date line from a git commit log message and
// returns a Time representation of it.
//
// Ex: "Date:   Sun Apr 11 18:58:01 2021 +0000" is parsed from the git commit
// log message and converted to a Time type.
func parseCommitDate(commitLog string) (*time.Time, error) {
	// Parse the date line from the commit log message
	//
	// Ex: "Date:   Sun Apr 11 18:58:01 2021 +0000"
	dateStrs := dateLineRegExp.FindAllString(commitLog, -1)
	if len(dateStrs) != 1 {
		return nil, fmt.Errorf("found %v date strings, want 1", len(dateStrs))
	}
	dateStr := dateStrs[0]

	// Trim the prefix and whitespace
	dateStr = strings.TrimPrefix(dateStr, "Date:")
	dateStr = strings.TrimSpace(dateStr)

	// Convert the date string to a Time type
	t, err := time.Parse(commitDateLayout, dateStr)
	if err != nil {
		return nil, err
	}

	return &t, nil
}

var (
	// castVoteRegExp matches the gitbe CastVote JSON structure.
	//
	// Ex: {"token":"95a14094485c92ed3f578b650bd76c5f8c3fd6392650c16bd4ae37e6167c040d","ticket":"12a94af3ac7efe530abdb62c20d522f270b250f1a9e050ee63b796936abd4bed","votebit":"2","signature":"208b378e391e22802408dc26e65048cebc1245f2ff153cc4de85c73b07a5ae7f3679a4f2b55a3d28df60fa80b618b8aaebafbfe0d12ef18c4d63d954687c983637"}
	castVoteRE = `{"token":"[0-9a-f]{64}","ticket":"[0-9a-f]{64}",` +
		`"votebit":"[0-9]","signature":"[0-9a-f]{130}"}`
	castVoteRegExp = regexp.MustCompile(castVoteRE)
)

// parseCastVotes parses the JSON encoded gitbe CastVote structures from the
// provided string and returns the decoded JSON.
func parseCastVotes(s string) ([]gitbe.CastVote, error) {
	var (
		castVotesJSON = castVoteRegExp.FindAll([]byte(s), -1)
		castVotes     = make([]gitbe.CastVote, 0, len(castVotesJSON))
	)
	for _, b := range castVotesJSON {
		var cv gitbe.CastVote
		err := json.Unmarshal(b, &cv)
		if err != nil {
			return nil, err
		}
		castVotes = append(castVotes, cv)
	}
	return castVotes, nil
}
