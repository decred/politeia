package decredplugin

import "encoding/json"

// Plugin settings, kinda doesn;t go here but for now it is fine
const (
	Version              = "1"
	ID                   = "decred"
	CmdStartVote         = "startvote"
	CmdBallot            = "ballot"
	CmdBestBlock         = "bestblock"
	CmdNewComment        = "newcomment"
	CmdLikeComment       = "likecomment"
	CmdGetComments       = "getcomments"
	CmdProposalVotes     = "proposalvotes"
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

// CastVoteReply contains the signature or error to a cast vote command.
type CastVoteReply struct {
	ClientSignature string `json:"clientsignature"` // Signature that was sent in
	Signature       string `json:"signature"`       // Signature of the ClientSignature
	Error           string `json:"error"`           // Error if something wen't wrong during casting a vote
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

// VoteOption describes a single vote option.
type VoteOption struct {
	Id          string `json:"id"`          // Single unique word identifying vote (e.g. yes)
	Description string `json:"description"` // Longer description of the vote.
	Bits        uint64 `json:"bits"`        // Bits used for this option
}

// Vote represents the vote options for vote that is identified by its token.
type Vote struct {
	Token    string       `json:"token"`    // Token that identifies vote
	Mask     uint64       `json:"mask"`     // Valid votebits
	Duration uint32       `json:"duration"` // Duration in blocks
	Options  []VoteOption `json:"options"`  // Vote option
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
	PublicKey string `json:"publickey"` // Key used for signature.
	Vote      Vote   `json:"vote"`      // Vote + options
	Signature string `json:"signature"` // Signature of Votehash
}

// EncodeStartVoteencodes StartVoteinto a JSON byte slice.
func EncodeStartVote(v StartVote) ([]byte, error) {
	return json.Marshal(v)
}

// DecodeVotedecodes a JSON byte slice into a StartVote.
func DecodeStartVote(payload []byte) (*StartVote, error) {
	var sv StartVote

	err := json.Unmarshal(payload, &sv)
	if err != nil {
		return nil, err
	}

	return &sv, nil
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
	StartVote StartVote  `json:"startvote"` // Original ballot
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
	CommentID   string `json:"commentid"`   // Comment ID
	Receipt     string `json:"receipt"`     // Server signature of the client Signature
	Timestamp   int64  `json:"timestamp"`   // Received UNIX timestamp
	TotalVotes  uint64 `json:"totalvotes"`  // Total number of up/down votes
	ResultVotes int64  `json:"resultvotes"` // Vote score
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

// LikeComment records an up or down vote from a user on a comment.
type LikeComment struct {
	Token     string `json:"token"`     // Censorship token
	CommentID string `json:"commentid"` // Comment ID
	Action    string `json:"Action"`    // Up or downvote (1, -1)
	Signature string `json:"signature"` // Client Signature of Token+CommentID+Action
	PublicKey string `json:"publickey"` // Pubkey used for Signature

	// Only used on disk
	Receipt   string `json:"receipt,omitempty"`   // Signature of Signature
	Timestamp int64  `json:"timestamp,omitempty"` // Received UNIX timestamp
}

// EncodeLikeComment encodes LikeComment into a JSON byte slice.
func EncodeLikeComment(lc LikeComment) ([]byte, error) {
	return json.Marshal(lc)
}

// DecodeLikeComment decodes a JSON byte slice into a LikeComment.
func DecodeLikeComment(payload []byte) (*LikeComment, error) {
	var lc LikeComment

	err := json.Unmarshal(payload, &lc)
	if err != nil {
		return nil, err
	}

	return &lc, nil
}

// LikeCommentReply returns the result of an up pordown vote.
type LikeCommentReply struct {
	Total   uint64 `json:"total"`   // Total number of up and down votes
	Result  int64  `json:"result"`  // Current tally of likes, can be negative
	Receipt string `json:"receipt"` // Server signature of client signature
}

// EncodeLikeCommentReply encodes LikeCommentReply into a JSON byte slice.
func EncodeLikeCommentReply(lcr LikeCommentReply) ([]byte, error) {
	return json.Marshal(lcr)
}

// DecodeLikeCommentReply decodes a JSON byte slice into a LikeCommentReply.
func DecodeLikeCommentReply(payload []byte) (*LikeCommentReply, error) {
	var lcr LikeCommentReply

	err := json.Unmarshal(payload, &lcr)
	if err != nil {
		return nil, err
	}

	return &lcr, nil
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
