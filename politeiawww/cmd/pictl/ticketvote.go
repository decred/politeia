// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"sort"
	"strings"

	tkv1 "github.com/decred/politeia/politeiawww/api/ticketvote/v1"
)

func printAuthDetails(a tkv1.AuthDetails) {
	printf("Token    : %v\n", a.Token)
	printf("Action   : %v\n", a.Action)
	printf("Timestamp: %v\n", timestampFromUnix(a.Timestamp))
	printf("Receipt  : %v\n", a.Receipt)
}

func printVoteDetails(v tkv1.VoteDetails) {
	printf("Token             : %v\n", v.Params.Token)
	printf("Type              : %v\n", tkv1.VoteTypes[v.Params.Type])
	if v.Params.Type == tkv1.VoteTypeRunoff {
		printf("Parent            : %v\n", v.Params.Parent)
	}
	printf("Pass Percentage   : %v%%\n", v.Params.PassPercentage)
	printf("Quorum Percentage : %v%%\n", v.Params.QuorumPercentage)
	printf("Duration          : %v blocks\n", v.Params.Duration)
	printf("Start Block Hash  : %v\n", v.StartBlockHash)
	printf("Start Block Height: %v\n", v.StartBlockHeight)
	printf("End Block Height  : %v\n", v.EndBlockHeight)
	printf("Vote options\n")
	for _, v := range v.Params.Options {
		printf("  %v %v %v\n", v.Bit, v.ID, v.Description)
	}
}

func printVoteResults(votes []tkv1.CastVoteDetails) {
	if len(votes) == 0 {
		return
	}

	// Tally results
	results := make(map[string]int)
	for _, v := range votes {
		results[v.VoteBit]++
	}

	// Order results
	r := make([]string, 0, len(results))
	for k := range results {
		r = append(r, k)
	}
	sort.SliceStable(r, func(i, j int) bool {
		return r[i] < r[j]
	})

	// Print results
	printf("Token: %v\n", votes[0].Token)
	printf("Results\n")
	for _, v := range r {
		printf("  %v: %v\n", v, results[v])
	}
}

// voteSummaryString returns a string that contains the pretty printed vote
// summary.
//
// Example output:
// Token             : db9b06f36c21991c
// Status            : rejected
// Type              : standard
// Quorum Percentage : 1% of eligible votes (46 votes)
// Pass Percentage   : 50% of cast votes (30 votes)
// Duration          : 1 blocks
// Start Block Hash  : 000000007f1cacdef29710d0f95457364a9e4649904a0655d6ae9cec
// Start Block Height: 800034
// End Block Height  : 800051
// Eligible Tickets  : 4638 tickets
// Best Block        : 800051
// Results
//   1 yes 0 votes
//   2 no  60 votes
//
// The indent argument can be used to add indentation to each line of the
// string. An empty string will result in no indentation.
func voteSummaryString(token string, s tkv1.Summary, indent string) string {
	// Declare here to prevent goto errors
	var (
		sb strings.Builder

		total  uint64 // Total votes cast
		quorum int    // Votes required to reach a quorum
		pass   int    // Votes required to pass
	)

	sb.WriteString(fmt.Sprintf("Token             : %v\n",
		token))
	sb.WriteString(fmt.Sprintf("Status            : %v\n",
		tkv1.VoteStatuses[s.Status]))
	switch s.Status {
	case tkv1.VoteStatusUnauthorized, tkv1.VoteStatusAuthorized,
		tkv1.VoteStatusIneligible:
		// Nothing else to print
		goto addIndent
	}

	for _, v := range s.Results {
		total += v.Votes
	}
	quorum = int(float64(s.QuorumPercentage) / 100 * float64(s.EligibleTickets))
	pass = int(float64(s.PassPercentage) / 100 * float64(total))

	sb.WriteString(fmt.Sprintf("Type              : %v\n",
		tkv1.VoteTypes[s.Type]))
	sb.WriteString(fmt.Sprintf("Quorum Percentage : %v%% of eligible votes "+
		"(%v votes)\n",
		s.QuorumPercentage, quorum))
	sb.WriteString(fmt.Sprintf("Pass Percentage   : %v%% of cast votes "+
		"(%v votes)\n",
		s.PassPercentage, pass))
	sb.WriteString(fmt.Sprintf("Duration          : %v blocks\n",
		s.Duration))
	sb.WriteString(fmt.Sprintf("Start Block Hash  : %v\n",
		s.StartBlockHash))
	sb.WriteString(fmt.Sprintf("Start Block Height: %v\n",
		s.StartBlockHeight))
	sb.WriteString(fmt.Sprintf("End Block Height  : %v\n",
		s.EndBlockHeight))
	sb.WriteString(fmt.Sprintf("Eligible Tickets  : %v tickets\n",
		s.EligibleTickets))
	sb.WriteString(fmt.Sprintf("Best Block        : %v\n",
		s.BestBlock))
	sb.WriteString("Results\n")
	for _, v := range s.Results {
		sb.WriteString(fmt.Sprintf("  %v %-3v %v votes\n",
			v.VoteBit, v.ID, v.Votes))
	}

addIndent:
	// Add in indentation after each new line
	r := strings.NewReplacer("\n", "\n"+indent)
	ss := r.Replace(sb.String())

	// Remove trailing spaces
	ss = strings.TrimSpace(ss)

	// Add indent to the first line
	ss = indent + ss

	return ss
}
