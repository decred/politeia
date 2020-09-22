// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package decredplugin

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/util"
)

type ErrorStatusT int
type VoteT int

// Plugin settings, kinda doesn;t go here but for now it is fine
const (
	Version               = "1"
	ID                    = "decred"
	CmdAuthorizeVote      = "authorizevote"
	CmdStartVote          = "startvote"
	CmdStartVoteRunoff    = "startvoterunoff"
	CmdBallot             = "ballot"
	CmdBestBlock          = "bestblock"
	CmdNewComment         = "newcomment"
	CmdCensorComment      = "censorcomment"
	CmdGetComments        = "getcomments"
	MDStreamAuthorizeVote = 13 // Vote authorization by proposal author
	MDStreamVoteBits      = 14 // Vote bits and mask
	MDStreamVoteSnapshot  = 15 // Vote tickets and start/end parameters

	// Vote duration requirements for proposal votes (in blocks)
	VoteDurationMinMainnet = 2016
	VoteDurationMaxMainnet = 4032
	VoteDurationMinTestnet = 0
	VoteDurationMaxTestnet = 4032

	// Authorize vote actions
	AuthVoteActionAuthorize = "authorize" // Authorize a proposal vote
	AuthVoteActionRevoke    = "revoke"    // Revoke a proposal vote authorization

	// Vote option IDs
	VoteOptionIDApprove = "yes"
	VoteOptionIDReject  = "no"

	// Vote types
	//
	// VoteTypeStandard is used to indicate a simple approve or reject
	// proposal vote where the winner is the voting option that has met
	// the specified pass and quorum requirements.
	//
	// VoteTypeRunoff specifies a runoff vote that multiple proposals compete in.
	// All proposals are voted on like normal, but there can only be one winner
	// in a runoff vote. The winner is the proposal that meets the quorum
	// requirement, meets the pass requirement, and that has the most net yes
	// votes. The winning proposal is considered approved and all other proposals
	// are considered rejected. If no proposals meet the quorum and pass
	// requirements then all proposals are considered rejected.
	// Note: in a runoff vote it is possible for a proposal to meet the quorum
	// and pass requirements but still be rejected if it does not have the most
	// net yes votes.
	VoteTypeInvalid  VoteT = 0
	VoteTypeStandard VoteT = 1
	VoteTypeRunoff   VoteT = 2

	// Versioning
	VersionStartVoteV1 = 1
	VersionStartVoteV2 = 2

	// Error status codes
	ErrorStatusInvalid          ErrorStatusT = 0
	ErrorStatusInternalError    ErrorStatusT = 1
	ErrorStatusProposalNotFound ErrorStatusT = 2
	ErrorStatusInvalidVoteBit   ErrorStatusT = 3
	ErrorStatusVoteHasEnded     ErrorStatusT = 4
	ErrorStatusDuplicateVote    ErrorStatusT = 5
	ErrorStatusIneligibleTicket ErrorStatusT = 6
)

var (
	// ErrorStatus converts error status codes to human readable text.
	ErrorStatus = map[ErrorStatusT]string{
		ErrorStatusInvalid:          "invalid error status",
		ErrorStatusInternalError:    "internal error",
		ErrorStatusProposalNotFound: "proposal not found",
		ErrorStatusInvalidVoteBit:   "invalid vote bit",
		ErrorStatusVoteHasEnded:     "vote has ended",
		ErrorStatusDuplicateVote:    "duplicate vote",
		ErrorStatusIneligibleTicket: "ineligbile ticket",
	}
)

// CastVote is a signed vote.
type CastVote struct {
	Token     string `json:"token"`     // Proposal ID
	Ticket    string `json:"ticket"`    // Ticket ID
	VoteBit   string `json:"votebit"`   // Vote bit that was selected, this is encode in hex
	Signature string `json:"signature"` // Signature of Token+Ticket+VoteBit
}

// Ballot is a batch of votes that are sent to the server.
type Ballot struct {
	Votes []CastVote `json:"votes"`
}

// EncodeCastVotes encodes CastVotes into a JSON byte slice.
func EncodeBallot(b Ballot) ([]byte, error) {
	return json.Marshal(b)
}

// DecodeCastVotes decodes a JSON byte slice into a CastVotes.
func DecodeBallot(payload []byte) (*Ballot, error) {
	var b Ballot

	err := json.Unmarshal(payload, &b)
	if err != nil {
		return nil, err
	}

	return &b, nil
}

// CastVoteReply contains the signature or error to a cast vote command. The
// Error and ErrorStatus fields will only be populated if something went wrong
// while attempting to cast the vote.
type CastVoteReply struct {
	ClientSignature string       `json:"clientsignature"`       // Signature that was sent in
	Signature       string       `json:"signature"`             // Signature of the ClientSignature
	Error           string       `json:"error"`                 // Error status message
	ErrorStatus     ErrorStatusT `json:"errorstatus,omitempty"` // Error status code
}

// EncodeCastVoteReply encodes CastVoteReply into a JSON byte slice.
func EncodeCastVoteReply(cvr CastVoteReply) ([]byte, error) {
	return json.Marshal(cvr)
}

// DecodeBallotReply decodes a JSON byte slice into a CastVotes.
func DecodeCastVoteReply(payload []byte) (*CastVoteReply, error) {
	var cvr CastVoteReply

	err := json.Unmarshal(payload, &cvr)
	if err != nil {
		return nil, err
	}

	return &cvr, nil
}

// BallotReply is a reply to a batched list of votes.
type BallotReply struct {
	Receipts []CastVoteReply `json:"receipts"`
}

// EncodeCastVoteReplies encodes CastVotes into a JSON byte slice.
func EncodeBallotReply(br BallotReply) ([]byte, error) {
	return json.Marshal(br)
}

// DecodeBallotReply decodes a JSON byte slice into a CastVotes.
func DecodeBallotReply(payload []byte) (*BallotReply, error) {
	var br BallotReply

	err := json.Unmarshal(payload, &br)
	if err != nil {
		return nil, err
	}

	return &br, nil
}

// AuthorizeVote is an MDStream that is used to indicate that a proposal has
// been finalized and is ready to be voted on.  The signature and public
// key are from the proposal author.  The author can revoke a previously sent
// vote authorization by setting the Action field to revoke.
const VersionAuthorizeVote = 1

type AuthorizeVote struct {
	// Generated by decredplugin
	Version   uint   `json:"version"`   // Version of this structure
	Receipt   string `json:"receipt"`   // Server signature of client signature
	Timestamp int64  `json:"timestamp"` // Received UNIX timestamp

	// Generated by client
	Action    string `json:"action"`    // Authorize or revoke
	Token     string `json:"token"`     // Proposal censorship token
	Signature string `json:"signature"` // Signature of token+version+action
	PublicKey string `json:"publickey"` // Pubkey used for signature
}

// EncodeAuthorizeVote encodes AuthorizeVote into a JSON byte slice.
func EncodeAuthorizeVote(av AuthorizeVote) ([]byte, error) {
	return json.Marshal(av)
}

// DecodeAuthorizeVote decodes a JSON byte slice into an AuthorizeVote.
func DecodeAuthorizeVote(payload []byte) (*AuthorizeVote, error) {
	var av AuthorizeVote
	err := json.Unmarshal(payload, &av)
	if err != nil {
		return nil, err
	}
	return &av, nil
}

// AuthorizeVoteReply returns the authorize vote action that was executed and
// the receipt for the action.  The receipt is the server side signature of
// AuthorizeVote.Signature.
type AuthorizeVoteReply struct {
	Action        string `json:"action"`        // Authorize or revoke
	RecordVersion string `json:"recordversion"` // Version of record files
	Receipt       string `json:"receipt"`       // Server signature of client signature
	Timestamp     int64  `json:"timestamp"`     // Received UNIX timestamp
}

// EncodeAuthorizeVote encodes AuthorizeVoteReply into a JSON byte slice.
func EncodeAuthorizeVoteReply(avr AuthorizeVoteReply) ([]byte, error) {
	return json.Marshal(avr)
}

// DecodeAuthorizeVoteReply decodes a JSON byte slice into a AuthorizeVoteReply.
func DecodeAuthorizeVoteReply(payload []byte) (*AuthorizeVoteReply, error) {
	var avr AuthorizeVoteReply
	err := json.Unmarshal(payload, &avr)
	if err != nil {
		return nil, err
	}
	return &avr, nil
}

// StartVote instructs the plugin to commence voting on a proposal with the
// provided vote bits.
const VersionStartVote = 2

// StartVote contains a JSON encoded StartVote of the specified Version. This
// struct is never written to disk. It is used to pass around the various
// StartVote versions.
type StartVote struct {
	Version uint   `json:"version"` // Payload StartVote version
	Token   string `json:"token"`   // Proposal token
	Payload string `json:"payload"` // JSON encoded StartVote
}

// EncodeStartVote encodes a StartVote into a JSON byte slice.
func EncodeStartVote(sv StartVote) ([]byte, error) {
	return json.Marshal(sv)
}

// DecodeStartVote decodes a JSON byte slice into a StartVote.
func DecodeStartVote(b []byte) (*StartVote, error) {
	sv := make(map[string]interface{}, 4)

	err := json.Unmarshal(b, &sv)
	if err != nil {
		return nil, err
	}

	// Handle nested JSON
	vote := sv["vote"].(map[string]interface{})

	return &StartVote{
		Token:   vote["token"].(string),
		Version: uint(sv["version"].(float64)),
		Payload: string(b),
	}, nil
}

// VoteOption describes a single vote option.
type VoteOption struct {
	Id          string `json:"id"`          // Single unique word identifying vote (e.g. yes)
	Description string `json:"description"` // Longer description of the vote
	Bits        uint64 `json:"bits"`        // Bits used for this option
}

// VoteV1 represents the vote options and parameters for a StartVoteV1.
type VoteV1 struct {
	Token            string       `json:"token"`            // Token that identifies vote
	Mask             uint64       `json:"mask"`             // Valid votebits
	Duration         uint32       `json:"duration"`         // Duration in blocks
	QuorumPercentage uint32       `json:"quorumpercentage"` // Percent of eligible votes required for quorum
	PassPercentage   uint32       `json:"passpercentage"`   // Percent of total votes required to pass
	Options          []VoteOption `json:"options"`          // Vote option
}

// EncodeVoteV1 encodes VoteV1 into a JSON byte slice.
func EncodeVoteV1(v VoteV1) ([]byte, error) {
	return json.Marshal(v)
}

// DecodeVoteV1 decodes a JSON byte slice into a VoteV1.
func DecodeVoteV1(payload []byte) (*VoteV1, error) {
	var v VoteV1

	err := json.Unmarshal(payload, &v)
	if err != nil {
		return nil, err
	}

	return &v, nil
}

// StartVoteV1 was formerly used to start a proposal vote, but is not longer
// accepted. A StartVoteV2 must be used to start a proposal vote.
type StartVoteV1 struct {
	// decred plugin only data
	Version uint `json:"version"` // Version of this structure

	PublicKey string `json:"publickey"` // Key used for signature
	Vote      VoteV1 `json:"vote"`      // Vote + options
	Signature string `json:"signature"` // Signature of token
}

// VerifySignature verifies that the StartVoteV1 signature is correct.
func (s *StartVoteV1) VerifySignature() error {
	sig, err := util.ConvertSignature(s.Signature)
	if err != nil {
		return err
	}
	b, err := hex.DecodeString(s.PublicKey)
	if err != nil {
		return err
	}
	pk, err := identity.PublicIdentityFromBytes(b)
	if err != nil {
		return err
	}
	if !pk.VerifyMessage([]byte(s.Vote.Token), sig) {
		return fmt.Errorf("invalid signature")
	}
	return nil
}

// EncodeStartVoteV1 encodes a StartVoteV1 into a JSON byte slice.
func EncodeStartVoteV1(v StartVoteV1) ([]byte, error) {
	return json.Marshal(v)
}

// DecodeVotedecodes a JSON byte slice into a StartVoteV1.
func DecodeStartVoteV1(payload []byte) (*StartVoteV1, error) {
	var sv StartVoteV1

	err := json.Unmarshal(payload, &sv)
	if err != nil {
		return nil, err
	}

	return &sv, nil
}

// VoteV2 represents the vote options and vote parameters for a StartVoteV2.
//
// Differences between VoteV1 and VoteV2:
// * Added the ProposalVersion field that specifies the version of the proposal
//   that is being voted on. This was added so that the proposal version is
//   explicitly included in the StartVote signature.
// * Added a Type field in order to specify the vote type.
type VoteV2 struct {
	Token            string       `json:"token"`            // Token that identifies vote
	ProposalVersion  uint32       `json:"proposalversion"`  // Proposal version being voted on
	Type             VoteT        `json:"type"`             // Type of vote
	Mask             uint64       `json:"mask"`             // Valid votebits
	Duration         uint32       `json:"duration"`         // Duration in blocks
	QuorumPercentage uint32       `json:"quorumpercentage"` // Percent of eligible votes required for quorum
	PassPercentage   uint32       `json:"passpercentage"`   // Percent of total votes required to pass
	Options          []VoteOption `json:"options"`          // Vote option
}

// EncodeVoteV2 encodes a VoteV2 into a JSON byte slice.
func EncodeVoteV2(v VoteV2) ([]byte, error) {
	return json.Marshal(v)
}

// DecodeVotedecodes a JSON byte slice into a VoteV2.
func DecodeVoteV2(payload []byte) (*VoteV2, error) {
	var v VoteV2

	err := json.Unmarshal(payload, &v)
	if err != nil {
		return nil, err
	}

	return &v, nil
}

// StartVoteV2 is used to start a proposal vote.
//
// The message being signed is the SHA256 digest of the VoteV2 JSON byte slice.
//
// Differences between StartVoteV1 and StartVoteV2:
// * Signature is the signature of a hash of the Vote struct. It was
//   previously the signature of just the proposal token.
// * Vote is now a VoteV2. See the VoteV2 comment for more details.
type StartVoteV2 struct {
	// decred plugin only data
	Version uint `json:"version"` // Version of this structure

	PublicKey string `json:"publickey"` // Key used for signature
	Vote      VoteV2 `json:"vote"`      // Vote options and params
	Signature string `json:"signature"` // Signature of Vote hash
}

// VerifySignature verifies that the StartVoteV2 signature is correct.
func (s *StartVoteV2) VerifySignature() error {
	sig, err := util.ConvertSignature(s.Signature)
	if err != nil {
		return err
	}
	b, err := hex.DecodeString(s.PublicKey)
	if err != nil {
		return err
	}
	pk, err := identity.PublicIdentityFromBytes(b)
	if err != nil {
		return err
	}
	vb, err := json.Marshal(s.Vote)
	if err != nil {
		return err
	}
	msg := hex.EncodeToString(util.Digest(vb))
	if !pk.VerifyMessage([]byte(msg), sig) {
		return fmt.Errorf("invalid signature")
	}
	return nil
}

// EncodeStartVoteV2 encodes a StartVoteV2 into a JSON byte slice.
func EncodeStartVoteV2(v StartVoteV2) ([]byte, error) {
	return json.Marshal(v)
}

// DecodeVotedecodes a JSON byte slice into a StartVoteV2.
func DecodeStartVoteV2(payload []byte) (*StartVoteV2, error) {
	var sv StartVoteV2

	err := json.Unmarshal(payload, &sv)
	if err != nil {
		return nil, err
	}

	return &sv, nil
}

// StartVoteReply is the reply to StartVote.
const VersionStartVoteReply = 1

type StartVoteReply struct {
	// decred plugin only data
	Version uint `json:"version"` // Version of this structure

	// Shared data
	StartBlockHeight string   `json:"startblockheight"` // Block height
	StartBlockHash   string   `json:"startblockhash"`   // Block hash
	EndHeight        string   `json:"endheight"`        // Height of vote end
	EligibleTickets  []string `json:"eligibletickets"`  // Valid voting tickets
}

// EncodeStartVoteReply encodes StartVoteReply into a JSON byte slice.
func EncodeStartVoteReply(v StartVoteReply) ([]byte, error) {
	return json.Marshal(v)
}

// DecodeVoteReply decodes a JSON byte slice into a StartVoteReply.
func DecodeStartVoteReply(payload []byte) (*StartVoteReply, error) {
	var v StartVoteReply

	err := json.Unmarshal(payload, &v)
	if err != nil {
		return nil, err
	}

	return &v, nil
}

// StartVoteRunoff instructs the plugin to start a runoff vote using the given
// submissions. Each submission is required to have its own AuthorizeVote and
// StartVote.
type StartVoteRunoff struct {
	Token          string          `json:"token"`          // Token of RFP proposal
	AuthorizeVotes []AuthorizeVote `json:"authorizevotes"` // Submission auth votes
	StartVotes     []StartVoteV2   `json:"startvotes"`     // Submission start votes
}

// EncodeStartVoteRunoffencodes StartVoteRunoffinto a JSON byte slice.
func EncodeStartVoteRunoff(v StartVoteRunoff) ([]byte, error) {
	return json.Marshal(v)
}

// DecodeVotedecodes a JSON byte slice into a StartVoteRunoff.
func DecodeStartVoteRunoff(payload []byte) (*StartVoteRunoff, error) {
	var sv StartVoteRunoff

	err := json.Unmarshal(payload, &sv)
	if err != nil {
		return nil, err
	}

	return &sv, nil
}

// StartVoteRunoffReply is the reply to StartVoteRunoff. The StartVoteReply
// will be the same for all submissions so only one is returned. The individual
// AuthorizeVoteReply is returned for each submission where the token is the
// map key.
type StartVoteRunoffReply struct {
	AuthorizeVoteReplies map[string]AuthorizeVoteReply `json:"authorizevotereply"`
	StartVoteReply       StartVoteReply                `json:"startvotereply"`
}

// EncodeStartVoteRunoffReply encodes StartVoteRunoffReply into a JSON byte slice.
func EncodeStartVoteRunoffReply(v StartVoteRunoffReply) ([]byte, error) {
	return json.Marshal(v)
}

// DecodeVoteReply decodes a JSON byte slice into a StartVoteRunoffReply.
func DecodeStartVoteRunoffReply(payload []byte) (*StartVoteRunoffReply, error) {
	var v StartVoteRunoffReply

	err := json.Unmarshal(payload, &v)
	if err != nil {
		return nil, err
	}

	return &v, nil
}

// Comment is the structure that describes the full server side content.  It
// includes server side meta-data as well. Note that the receipt is the server
// side.
type Comment struct {
	// Data generated by client
	Token     string `json:"token"`     // Censorship token
	ParentID  string `json:"parentid"`  // Parent comment ID
	Comment   string `json:"comment"`   // Comment
	Signature string `json:"signature"` // Client Signature of Token+ParentID+Comment
	PublicKey string `json:"publickey"` // Pubkey used for Signature

	// Metadata generated by decred plugin
	CommentID   string `json:"commentid"`   // Comment ID
	Receipt     string `json:"receipt"`     // Server signature of the client Signature
	Timestamp   int64  `json:"timestamp"`   // Received UNIX timestamp
	TotalVotes  uint64 `json:"totalvotes"`  // Total number of up/down votes
	ResultVotes int64  `json:"resultvotes"` // Vote score
	Censored    bool   `json:"censored"`    // Has this comment been censored
}

// EncodeComment encodes Comment into a JSON byte slice.
func EncodeComment(c Comment) ([]byte, error) {
	return json.Marshal(c)
}

// DecodeComment decodes a JSON byte slice into a Comment
func DecodeComment(payload []byte) (*Comment, error) {
	var c Comment

	err := json.Unmarshal(payload, &c)
	if err != nil {
		return nil, err
	}

	return &c, nil
}

// NewComment sends a comment from a user to a specific proposal.  Note that
// the user is implied by the session.
type NewComment struct {
	Token     string `json:"token"`     // Censorship token
	ParentID  string `json:"parentid"`  // Parent comment ID
	Comment   string `json:"comment"`   // Comment
	Signature string `json:"signature"` // Signature of Token+ParentID+Comment
	PublicKey string `json:"publickey"` // Pubkey used for Signature
}

// EncodeNewComment encodes NewComment into a JSON byte slice.
func EncodeNewComment(nc NewComment) ([]byte, error) {
	return json.Marshal(nc)
}

// DecodeNewComment decodes a JSON byte slice into a NewComment
func DecodeNewComment(payload []byte) (*NewComment, error) {
	var nc NewComment

	err := json.Unmarshal(payload, &nc)
	if err != nil {
		return nil, err
	}

	return &nc, nil
}

// NewCommentReply returns the metadata generated by decred plugin for the new
// comment.
type NewCommentReply struct {
	CommentID string `json:"commentid"` // Comment ID
	Receipt   string `json:"receipt"`   // Server signature of the client Signature
	Timestamp int64  `json:"timestamp"` // Received UNIX timestamp
}

// EncodeNewCommentReply encodes NewCommentReply into a JSON byte slice.
func EncodeNewCommentReply(ncr NewCommentReply) ([]byte, error) {
	return json.Marshal(ncr)
}

// DecodeNewCommentReply decodes a JSON byte slice into a NewCommentReply.
func DecodeNewCommentReply(payload []byte) (*NewCommentReply, error) {
	var ncr NewCommentReply

	err := json.Unmarshal(payload, &ncr)
	if err != nil {
		return nil, err
	}

	return &ncr, nil
}

// CensorComment is a journal entry for a censored comment.  The signature and
// public key are from the admin that censored this comment.
type CensorComment struct {
	Token     string `json:"token"`     // Proposal censorship token
	CommentID string `json:"commentid"` // Comment ID
	Reason    string `json:"reason"`    // Reason comment was censored
	Signature string `json:"signature"` // Client signature of Token+CommentID+Reason
	PublicKey string `json:"publickey"` // Pubkey used for signature

	// Generated by decredplugin
	Receipt   string `json:"receipt,omitempty"`   // Server signature of client signature
	Timestamp int64  `json:"timestamp,omitempty"` // Received UNIX timestamp
}

// EncodeCensorComment encodes CensorComment into a JSON byte slice.
func EncodeCensorComment(cc CensorComment) ([]byte, error) {
	return json.Marshal(cc)
}

// DecodeCensorComment decodes a JSON byte slice into a CensorComment.
func DecodeCensorComment(payload []byte) (*CensorComment, error) {
	var cc CensorComment
	err := json.Unmarshal(payload, &cc)
	if err != nil {
		return nil, err
	}
	return &cc, nil
}

// CommentCensorReply returns the receipt for the censoring action. The
// receipt is the server side signature of CommentCensor.Signature.
type CensorCommentReply struct {
	Receipt string `json:"receipt"` // Server signature of client signature
}

// EncodeCensorCommentReply encodes CensorCommentReply into a JSON byte slice.
func EncodeCensorCommentReply(ccr CensorCommentReply) ([]byte, error) {
	return json.Marshal(ccr)
}

// DecodeCensorComment decodes a JSON byte slice into a CensorCommentReply.
func DecodeCensorCommentReply(payload []byte) (*CensorCommentReply, error) {
	var ccr CensorCommentReply
	err := json.Unmarshal(payload, &ccr)
	if err != nil {
		return nil, err
	}
	return &ccr, nil
}

// GetComments retrieve all comments for a given proposal. This call returns
// the cooked comments; deleted/censored comments are not returned.
type GetComments struct {
	Token string `json:"token"` // Proposal ID
}

// EncodeGetComments encodes GetCommentsReply into a JSON byte slice.
func EncodeGetComments(gc GetComments) ([]byte, error) {
	return json.Marshal(gc)
}

// DecodeGetComments decodes a JSON byte slice into a GetComments.
func DecodeGetComments(payload []byte) (*GetComments, error) {
	var gc GetComments

	err := json.Unmarshal(payload, &gc)
	if err != nil {
		return nil, err
	}

	return &gc, nil
}

// GetCommentsReply returns the provided number of comments.
type GetCommentsReply struct {
	Comments []Comment `json:"comments"` // Comments
}

// EncodeGetCommentsReply encodes GetCommentsReply into a JSON byte slice.
func EncodeGetCommentsReply(gcr GetCommentsReply) ([]byte, error) {
	return json.Marshal(gcr)
}

// DecodeGetCommentsReply decodes a JSON byte slice into a GetCommentsReply.
func DecodeGetCommentsReply(payload []byte) (*GetCommentsReply, error) {
	var gcr GetCommentsReply

	err := json.Unmarshal(payload, &gcr)
	if err != nil {
		return nil, err
	}

	return &gcr, nil
}

// BestBlock is a command to request the best block data.
type BestBlock struct{}

// EncodeBestBlock encodes an BestBlock into a JSON byte slice.
func EncodeBestBlock(bb BestBlock) ([]byte, error) {
	return json.Marshal(bb)
}

// DecodeBestBlock decodes a JSON byte slice into a BestBlock.
func DecodeBestBlock(payload []byte) (*BestBlock, error) {
	var bb BestBlock
	err := json.Unmarshal(payload, &bb)
	if err != nil {
		return nil, err
	}
	return &bb, nil
}

// BestBlockReply is the reply to the BestBlock command.
type BestBlockReply struct {
	Height uint32 `json:"height"`
}

// EncodeBestBlockReply encodes an BestBlockReply into a JSON byte slice.
func EncodeBestBlockReply(bbr BestBlockReply) ([]byte, error) {
	return json.Marshal(bbr)
}

// DecodeBestBlockReply decodes a JSON byte slice into a BestBlockReply.
func DecodeBestBlockReply(payload []byte) (*BestBlockReply, error) {
	var bbr BestBlockReply
	err := json.Unmarshal(payload, &bbr)
	if err != nil {
		return nil, err
	}
	return &bbr, nil
}
