package main

import (
	"github.com/decred/dcrd/chaincfg/v3"
	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
)

// parsedData holds the data needed by tlog to insert the legacy
// records on tstore.
type parsedData struct {
	files         []backend.File
	metadata      []backend.MetadataStream
	recordMd      *backend.RecordMetadata
	authDetailsMd *ticketvote.AuthDetails
	voteDetailsMd *ticketvote.VoteDetails
	commentsPath  string
	ballotPath    string
	legacyToken   string
}

// likeCommentV1 unmarshals the like action data from the gitbe's comments
// journal.
type likeCommentV1 struct {
	Token     string `json:"token"`     // Censorship token
	CommentID string `json:"commentid"` // Comment ID
	Action    string `json:"action"`    // Up or downvote (1, -1)
	Signature string `json:"signature"` // Client Signature of Token+CommentID+Action
	PublicKey string `json:"publickey"` // Pubkey used for Signature

	Receipt   string `json:"receipt,omitempty"`   // Signature of Signature
	Timestamp int64  `json:"timestamp,omitempty"` // Received UNIX timestamp
}

// proposalGeneralV1 is the former metadata stream from gitbe and unmarshals
// the 00.metadata.txt record file.
type proposalGeneralV1 struct {
	Version   int32  `json:"version"`
	Timestamp int32  `json:"timestamp"`
	Name      string `json:"name"`
	PublicKey string `json:"publickey"`
	Signature string `json:"signature"`
}

// castVoteJournal action payload
type castVoteJournalV1 struct {
	CastVote castVoteV1 `json:"castvote"` // Client side vote
	Receipt  string     `json:"receipt"`  // Signature of CastVote.Signature
}
type castVoteV1 struct {
	Token     string `json:"token"`     // Proposal ID
	Ticket    string `json:"ticket"`    // Ticket ID
	VoteBit   string `json:"votebit"`   // Vote bit that was selected, this is encode in hex
	Signature string `json:"signature"` // Signature of Token+Ticket+VoteBit
}

type authorizeVoteV1 struct {
	Version   uint   `json:"version"`   // Version of this structure
	Receipt   string `json:"receipt"`   // Server signature of client signature
	Timestamp int64  `json:"timestamp"` // Received UNIX timestamp

	Action    string `json:"action"`    // Authorize or revoke
	Token     string `json:"token"`     // Proposal censorship token
	Signature string `json:"signature"` // Signature of token+version+action
	PublicKey string `json:"publickey"` // Pubkey used for signature
}

type voteV1 struct {
	Token            string       `json:"token"`            // Token that identifies vote
	ProposalVersion  uint32       `json:"proposalversion"`  // Proposal version being voted on
	Type             int          `json:"type"`             // Type of vote
	Mask             uint64       `json:"mask"`             // Valid votebits
	Duration         uint32       `json:"duration"`         // Duration in blocks
	QuorumPercentage uint32       `json:"quorumpercentage"` // Percent of eligible votes required for quorum
	PassPercentage   uint32       `json:"passpercentage"`   // Percent of total votes required to pass
	Options          []voteOption `json:"options"`          // Vote option
}

type voteOption struct {
	Id          string `json:"id"`          // Single unique word identifying vote (e.g. yes)
	Description string `json:"description"` // Longer description of the vote
	Bits        uint64 `json:"bits"`        // Bits used for this option
}

type startVoteV1 struct {
	// decred plugin only data
	Version uint `json:"version"` // Version of this structure

	PublicKey string `json:"publickey"` // Key used for signature
	Vote      voteV1 `json:"vote"`      // Vote options and params
	Signature string `json:"signature"` // Signature of Vote hash
}

type voteDetailsV1 struct {
	// decred plugin only data
	Version uint `json:"version"` // Version of this structure

	// Shared data
	StartBlockHeight string   `json:"startblockheight"` // Block height
	StartBlockHash   string   `json:"startblockhash"`   // Block hash
	EndHeight        string   `json:"endheight"`        // Height of vote end
	EligibleTickets  []string `json:"eligibletickets"`  // Valid voting tickets
}

// Net params
type params struct {
	*chaincfg.Params
	WalletRPCServerPort string
}

// Types for pi API interaction
type user struct {
	ID       string `json:"id"`
	Email    string `json:"email,omitempty"`
	Username string `json:"username"`
}
type usersReply struct {
	TotalUsers   uint64 `json:"totalusers,omitempty"`
	TotalMatches uint64 `json:"totalmatches"`
	Users        []user `json:"users"`
}
