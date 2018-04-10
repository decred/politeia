package decredplugin

import "encoding/json"

// Plugin settings, kinda doesn;t go here but for now it is fine
const (
	Version              = "1"
	ID                   = "decred"
	CmdStartVote         = "startvote"
	CmdCastVotes         = "castvotes"
	CmdBestBlock         = "bestblock"
	MDStreamVotes        = 13 // Votes
	MDStreamVoteBits     = 14 // Vote bits and mask
	MDStreamVoteSnapshot = 15 // Vote tickets and start/end parameters
)

// CastVote is a signed vote.
type CastVote struct {
	Token     string `json:"token"`     // Proposal ID
	Ticket    string `json:"ticket"`    // Ticket ID
	VoteBit   string `json:"votebit"`   // Vote bit that was selected, this is encode in hex
	Signature string `json:"signature"` // Signature of Token+Ticket+VoteBit
}

// EncodeCastVotes encodes CastVotes into a JSON byte slice.
func EncodeCastVotes(cv []CastVote) ([]byte, error) {
	b, err := json.Marshal(cv)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// DecodeCastVotes decodes a JSON byte slice into a CastVotes.
func DecodeCastVotes(payload []byte) ([]CastVote, error) {
	var cv []CastVote

	err := json.Unmarshal(payload, &cv)
	if err != nil {
		return nil, err
	}

	return cv, nil
}

// CastVoteReply is the answer to the CastVote command.
type CastVoteReply struct {
	ClientSignature string `json:"clientsignature"` // Signature that was sent in
	Signature       string `json:"signature"`       // Signature of the ClientSignature
	Error           string `json:"error"`           // Error if something wen't wrong during casting a vote
}

// EncodeCastVoteReplies encodes CastVotes into a JSON byte slice.
func EncodeCastVoteReplies(cvr []CastVoteReply) ([]byte, error) {
	b, err := json.Marshal(cvr)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// DecodeCastVoteReplies decodes a JSON byte slice into a CastVotes.
func DecodeCastVoteReplies(payload []byte) ([]CastVoteReply, error) {
	var cvr []CastVoteReply

	err := json.Unmarshal(payload, &cvr)
	if err != nil {
		return nil, err
	}

	return cvr, nil
}

// VoteOption describes a single vote option.
type VoteOption struct {
	Id          string `json:"id"`          // Single unique word identifying vote (e.g. yes)
	Description string `json:"description"` // Longer description of the vote.
	Bits        uint64 `json:"bits"`        // Bits used for this option
}

// Vote represents the vote options for vote that is identified by its token.
type Vote struct {
	Token   string `json:"token"` // Token that identifies vote
	Mask    uint64 `json:"mask"`  // Valid votebits
	Options []VoteOption
}

// EncodeVote encodes Vote into a JSON byte slice.
func EncodeVote(v Vote) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// DecodeVote decodes a JSON byte slice into a Vote.
func DecodeVote(payload []byte) (*Vote, error) {
	var v Vote

	err := json.Unmarshal(payload, &v)
	if err != nil {
		return nil, err
	}

	return &v, nil
}

// StartVote instructs the plugin to commence voting on a proposal with the
// provided vote bits.
type StartVote struct {
	Vote Vote `json:"vote"` // Vote + options
}

// StartVoteReply is the reply to StartVote.
type StartVoteReply struct {
	StartBlockHeight string   `json:"startblockheight"` // Block height
	StartBlockHash   string   `json:"startblockhash"`   // Block hash
	EndHeight        string   `json:"endheight"`        // Height of vote end
	EligibleTickets  []string `json:"eligibletickets"`  // Valid voting tickets
}

// EncodeStartVoteReply encodes StartVoteReply into a JSON byte slice.
func EncodeStartVoteReply(v StartVoteReply) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	return b, nil
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
