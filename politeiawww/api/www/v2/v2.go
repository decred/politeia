// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v2

import (
	"fmt"
)

type VoteT int

const (
	APIVersion = 2

	RouteStartVote   = "/vote/start"
	RouteVoteDetails = "/vote/{token:[A-z0-9]{64}}"

	// Vote types
	//
	// VoteTypeStandard is used to indicate a simple approve or reject
	// proposal vote where the winner is the voting option that has met
	// the specified pass and quorum requirements.
	VoteTypeInvalid  VoteT = 0
	VoteTypeStandard VoteT = 1
)

var (
	// APIRoute is the prefix to the v2 API routes
	APIRoute = fmt.Sprintf("/v%v", APIVersion)
)

// VoteOption describes a single vote option.
type VoteOption struct {
	Id          string `json:"id"`          // Single unique word identifying vote (e.g. yes)
	Description string `json:"description"` // Longer description of the vote.
	Bits        uint64 `json:"bits"`        // Bits used for this option
}

// Vote represents the vote params and vote options for a proposal vote.
//
// QuorumPercentage is the percent of eligible votes required for a quorum.
// PassPercentage is the percent of total votes required for the proposal to
// be considered approved.
//
// Differences between v1 and v2:
// * Added the Version field that specifies the version of the proposal that is
//   being voted on. This was added so that the proposal version is included in
//   the StartVote signature.
// * Added the Type field that specifies the vote type.
type Vote struct {
	Token            string       `json:"token"`            // Proposal token
	ProposalVersion  uint32       `json:"proposalversion"`  // Proposal version of vote
	Type             VoteT        `json:"type"`             // Type of vote
	Mask             uint64       `json:"mask"`             // Valid votebits
	Duration         uint32       `json:"duration"`         // Duration in blocks
	QuorumPercentage uint32       `json:"quorumpercentage"` // Quorum requirement
	PassPercentage   uint32       `json:"passpercentage"`   // Approval requirement
	Options          []VoteOption `json:"options"`          // Vote options
}

// StartVote starts the voting period on the given proposal.
//
// Signature is a signature of the hex encoded SHA256 digest of the JSON
// encoded v2 Vote struct.
//
// Differences between v1 and v2:
// * Signature has been updated to be a signature of the Vote hash. It was
//   previously a signature of just the proposal token.
// * Vote has been updated. See the Vote comment for more details.
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
type VoteDetails struct {
	Token string `json:"token"` // Proposal token
}

// VoteDetailsReply is the reply to the VoteDetails command. It contains all
// of the information from a StartVote and StartVoteReply.
//
// Version specifies the StartVote version that was used to initiate the
// proposal vote. See the StartVote comment for details on the differences
// between the StartVote versions.
//
// Vote contains a JSON encoded Vote and needs to be decoded according to the
// Version. See the Vote comment for details on the differences between the
// Vote versions.
type VoteDetailsReply struct {
	Version          uint32   `json:"version"`          // StartVote version
	Vote             string   `json:"vote"`             // JSON encoded Vote struct
	PublicKey        string   `json:"publickey"`        // Key used for signature
	Signature        string   `json:"signature"`        // Start vote signature
	StartBlockHeight uint32   `json:"startblockheight"` // Block height
	StartBlockHash   string   `json:"startblockhash"`   // Block hash
	EndBlockHeight   uint32   `json:"endblockheight"`   // Height of vote end
	EligibleTickets  []string `json:"eligibletickets"`  // Valid voting ticket
}
