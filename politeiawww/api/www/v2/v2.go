// Copyright (c) 2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v2

import (
	"fmt"

	v1 "github.com/decred/politeia/politeiawww/api/www/v1"
)

type VoteT int

const (
	APIVersion = 2

	RouteStartVote   = "/vote/start"
	RouteVoteDetails = "/vote/{token:[A-z0-9]{64}}"
	RouteVoteResults = "/vote/{token:[A-z0-9]{64}}/results"

	// Vote types
	//
	// VoteTypeStandard...
	VoteTypeInvalid  VoteT = 0
	VoteTypeStandard VoteT = 1
)

var (
	// APIRoute is the prefix to the v2 API routes
	APIRoute = fmt.Sprintf("/v%v", APIVersion)
)

// Vote represents the vote params and vote options for a proposal vote.
//
// QuorumPercentage is the percent of eligible votes required for a quorum.
// PassPercentage is the percent of total votes required for the proposal to
// be considered approved.
//
// Differences between v1 and v2:
// * Added the Type field that specifies the vote type. All votes that were
//   started using a v1 Vote will have a vote type of VoteTypeStandard. This
//   field was not explicity specified for v1 Votes, but it is the only vote
//   type that existed for v1 Votes.
type Vote struct {
	Token            string          `json:"token"`            // Proposal token
	Type             VoteT           `json:"type"`             // Type of vote
	Mask             uint64          `json:"mask"`             // Valid votebits
	Duration         uint32          `json:"duration"`         // Duration in blocks
	QuorumPercentage uint32          `json:"quorumpercentage"` // Quorum requirement
	PassPercentage   uint32          `json:"passpercentage"`   // Approval requirement
	Options          []v1.VoteOption `json:"options"`          // Vote options
}

// StartVote starts the voting period on the given proposal.
//
// Signature is a signature of the hex encoded SHA256 digest of the JSON
// encoded v2 Vote struct.
//
// Differences between v1 and v2:
// * Signature has been updated to be a signature of the Vote hash. It was
//   previously a signature of just the proposal token.
// * Vote now contains a Type field that specifies the vote type.
type StartVote struct {
	Vote      Vote   `json:"vote"`
	PublicKey string `json:"publickey"` // Key used for signature
	Signature string `json:"signature"` // Signature of Vote hash
}

// StartVoteReply is the reply to the StartVote command.
//
// Differences between v1 and v2:
// * StartBlockHeight was changed from a string to a uint32.
// * EndBlockHeight was changed from a string to a uint32. It was also renamed
//   from EndHeight to EndBlockHeight to be consistent with StartBlockHeight.
type StartVoteReply struct {
	StartBlockHeight uint32   `json:"startblockheight"` // Block height of vote start
	StartBlockHash   string   `json:"startblockhash"`   // Block hash of vote start
	EndBlockHeight   uint32   `json:"endblockheight"`   // Block height of vote end
	EligibleTickets  []string `json:"eligibletickets"`  // Valid voting tickets
}

// VoteDetails returns the votes details for the specified proposal.
//
// This route is expensive due to it returning the full eligible tickets
// snapshot. If the eligble tickets snapshot is not needed, the v1
// BatchVoteSummary route can likely be used instead.
type VoteDetails struct {
	Token string `json:"token"` // Proposal token
}

// VoteDetailsReply is the reply to the VoteDetails command.
//
// Version specifies the StartVote version that was used to initiate the
// proposal vote. See the StartVote comment for details on the differences
// between the StartVote versions.
type VoteDetailsReply struct {
	Version          uint32   `json:"version"`          // StartVote version
	Vote             Vote     `json:"vote"`             // Vote params and options
	PublicKey        string   `json:"publickey"`        // Key used for signature
	Signature        string   `json:"signature"`        // Signature (version dependent)
	StartBlockHeight uint32   `json:"startblockheight"` // Block height
	StartBlockHash   string   `json:"startblockhash"`   // Block hash
	EndBlockHeight   uint32   `json:"endblockheight"`   // Height of vote end
	EligibleTickets  []string `json:"eligibletickets"`  // Valid voting ticket
}

// VoteResults...
//
// Differences between v1 and v2:
// * The v1 VoteResults route has been broken up into the VoteDetails and
//   VoteResults routes for v2. This is because the StartVote and the
//   StartVoteReply data only ever need to be fetched a single time, but the
//   CastVote data may need to be fetched multiple times if the vote is ongoing
//   since new cast votes will be continuously rolling in. There is no need to
//   send the full EligibleTickets snapshot, which is a large amount of data,
//   in these requests when only the CastVote data is needed.
type VoteResults struct{}

// VoteResultsReply is the reply to the VoteResults command.
type VoteResultsReply struct {
	CastVotes []v1.CastVote `json:"castvotes"`
}
