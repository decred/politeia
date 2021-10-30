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
func voteSummaryString(token, indent string, s tkv1.Summary) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%vToken             : %v\n", indent, token))
	sb.WriteString(fmt.Sprintf("%vStatus            : %v\n",
		indent, tkv1.VoteStatuses[s.Status]))
	switch s.Status {
	case tkv1.VoteStatusUnauthorized, tkv1.VoteStatusAuthorized,
		tkv1.VoteStatusIneligible:
		// Nothing else to print
		return sb.String()
	}
	var total uint64
	for _, v := range s.Results {
		total += v.Votes
	}
	quorum := int(float64(s.QuorumPercentage) / 100 * float64(s.EligibleTickets))
	pass := int(float64(s.PassPercentage) / 100 * float64(total))
	sb.WriteString(fmt.Sprintf("%vType              : %v\n",
		indent, tkv1.VoteTypes[s.Type]))
	sb.WriteString(fmt.Sprintf("%vQuorum Percentage : %v%% of eligible votes "+
		"(%v votes)\n", indent, s.QuorumPercentage, quorum))
	sb.WriteString(fmt.Sprintf("%vPass Percentage   : %v%% of cast votes "+
		" (%v votes)\n", indent, s.PassPercentage, pass))
	sb.WriteString(fmt.Sprintf("%vDuration          : %v blocks\n",
		indent, s.Duration))
	sb.WriteString(fmt.Sprintf("%vStart Block Hash  : %v\n",
		indent, s.StartBlockHash))
	sb.WriteString(fmt.Sprintf("%vStart Block Height: %v\n",
		indent, s.StartBlockHeight))
	sb.WriteString(fmt.Sprintf("%vEnd Block Height  : %v\n",
		indent, s.EndBlockHeight))
	sb.WriteString(fmt.Sprintf("%vEligible Tickets  : %v tickets\n",
		indent, s.EligibleTickets))
	sb.WriteString(fmt.Sprintf("%vBest Block        : %v\n", indent,
		s.BestBlock))
	sb.WriteString(fmt.Sprintf("%vResults\n", indent))
	for _, v := range s.Results {
		sb.WriteString(fmt.Sprintf("%v %v %-3v %v votes\n", indent, v.VoteBit,
			v.ID, v.Votes))
	}

	return sb.String()
}
