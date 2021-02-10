// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"sort"

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
	printf("Type              : %v\n", v.Params.Type)
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

func printVoteSummary(token string, s tkv1.Summary) {
	printf("Token             : %v\n", token)
	printf("Status            : %v\n", tkv1.VoteStatuses[s.Status])
	switch s.Status {
	case tkv1.VoteStatusUnauthorized, tkv1.VoteStatusAuthorized:
		// Nothing else to print
		return
	}
	pass := int(float64(s.PassPercentage) / 100 * float64(s.EligibleTickets))
	quorum := int(float64(s.QuorumPercentage) / 100 * float64(s.EligibleTickets))
	printf("Type              : %v\n", tkv1.VoteTypes[s.Type])
	printf("Pass Percentage   : %v%% (%v votes)\n", s.PassPercentage, pass)
	printf("Quorum Percentage : %v%% (%v votes)\n", s.QuorumPercentage, quorum)
	printf("Duration          : %v blocks\n", s.Duration)
	printf("Start Block Hash  : %v\n", s.StartBlockHash)
	printf("Start Block Height: %v\n", s.StartBlockHeight)
	printf("End Block Height  : %v\n", s.EndBlockHeight)
	printf("Eligible Tickets  : %v tickets\n", s.EligibleTickets)
	printf("Best Block        : %v\n", s.BestBlock)
	printf("Results\n")
	for _, v := range s.Results {
		printf(" %v %-3v %v votes\n", v.VoteBit, v.ID, v.Votes)
	}
}
