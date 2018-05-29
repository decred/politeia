package decredplugin

import "encoding/json"

// Plugin settings, kinda doesn;t go here but for now it is fine
const (
	Version              = "1"
	ID                   = "decred"
	CmdStartVote         = "startvote"
	CmdCastVotes         = "castvotes"
	CmdBestBlock         = "bestblock"
	CmdNewComment        = "newcomment"
	CmdGetComments       = "getcomments"
	CmdProposalVotes     = "proposalvotes"
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
	return json.Marshal(cv)
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
	return json.Marshal(cvr)
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
	Token    string `json:"token"`    // Token that identifies vote
	Mask     uint64 `json:"mask"`     // Valid votebits
	Duration uint32 `json:"duration"` // Duration in blocks
	Options  []VoteOption
}

// EncodeVote encodes Vote into a JSON byte slice.
func EncodeVote(v Vote) ([]byte, error) {
	return json.Marshal(v)
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

type VoteResults struct {
	Token string `json:"token"` // Censorship token
}

type VoteResultsReply struct {
	Vote      Vote       `json:"vote"`      // Original ballot
	CastVotes []CastVote `json:"castvotes"` // All votes
}

// EncodeVoteResults encodes VoteResults into a JSON byte slice.
func EncodeVoteResults(v VoteResults) ([]byte, error) {
	return json.Marshal(v)
}

// DecodeVoteResults decodes a JSON byte slice into a VoteResults.
func DecodeVoteResults(payload []byte) (*VoteResults, error) {
	var v VoteResults

	err := json.Unmarshal(payload, &v)
	if err != nil {
		return nil, err
	}

	return &v, nil
}

// EncodeVoteResultsReply encodes VoteResults into a JSON byte slice.
func EncodeVoteResultsReply(v VoteResultsReply) ([]byte, error) {
	return json.Marshal(v)
}

// DecodeVoteResultsReply decodes a JSON byte slice into a VoteResults.
func DecodeVoteResultsReply(payload []byte) (*VoteResultsReply, error) {
	var v VoteResultsReply

	err := json.Unmarshal(payload, &v)
	if err != nil {
		return nil, err
	}

	return &v, nil
}

// CommentCensor is a journal entry for a censored comment.  The signature and
// public key are from the admin that censored this comment.
type CommentCensor struct {
	Token     string `json:"token"`     // Censorship token
	CommentID string `json:"commentid"` // Comment ID
	Signature string `json:"signature"` // Admin Signature of Token+CommentID
	PublicKey string `json:"publickey"` // Pubkey used for Signature
}

// CommentCensorReply returns the receipt for the cenosring action. The receipt
// is the politeaid side signature of CommentCensor.Signature.
type CommentCensorReply struct {
	Receipt string `json:"receipt"` // Server signature of the admin Signature
}

// Comment is the structure that describes the full server side content.  It
// includes server side meta-data as well. Note that the receipt is the server side
type Comment struct {
	// Data generated by client
	Token     string `json:"token"`     // Censorship token
	ParentID  string `json:"parentid"`  // Parent comment ID
	Comment   string `json:"comment"`   // Comment
	Signature string `json:"signature"` // Client Signature of Token+ParentID+Comment
	PublicKey string `json:"publickey"` // Pubkey used for Signature

	// Metadata generated by decred plugin
	CommentID string `json:"commentid"` // Comment ID
	Receipt   string `json:"receipt"`   // Server signature of the client Signature
	Timestamp int64  `json:"timestamp"` // Received UNIX timestamp
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

// NewCommentReply returns the comment as it was recorded in the journal.
type NewCommentReply struct {
	Comment Comment `json:"comment"` // Comment
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
