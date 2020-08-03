// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package comments

import (
	"encoding/json"
	"fmt"
)

type VoteT int
type ErrorStatusT int

const (
	Version uint32 = 1
	ID             = "comments"

	// Plugin commands
	CmdNew        = "new"        // Create a new comment
	CmdEdit       = "edit"       // Edit a comment
	CmdDel        = "del"        // Del a comment
	CmdGet        = "get"        // Get specified comments
	CmdGetAll     = "getall"     // Get all comments for a record
	CmdGetVersion = "getversion" // Get specified version of a comment
	CmdCount      = "count"      // Get comments count for a record
	CmdVote       = "vote"       // Vote on a comment
	CmdProofs     = "proofs"     // Get inclusion proofs

	// Comment vote types
	VoteInvalid  VoteT = 0
	VoteDownvote VoteT = -1
	VoteUpvote   VoteT = 1

	// PolicayMaxVoteChanges is the maximum number times a user can
	// change their vote on a comment. This prevents a malicious user
	// from being able to spam comment votes.
	PolicyMaxVoteChanges = 5

	// Error status codes
	ErrorStatusInvalid          ErrorStatusT = 0
	ErrorStatusTokenInvalid     ErrorStatusT = 1
	ErrorStatusPublicKeyInvalid ErrorStatusT = 2
	ErrorStatusSignatureInvalid ErrorStatusT = 3
	ErrorStatusRecordNotFound   ErrorStatusT = 4
	ErrorStatusCommentNotFound  ErrorStatusT = 5
	ErrorStatusParentIDInvalid  ErrorStatusT = 6
	ErrorStatusNoCommentChanges ErrorStatusT = 7
	ErrorStatusVoteInvalid      ErrorStatusT = 8
	ErrorStatusMaxVoteChanges   ErrorStatusT = 9
)

var (
	// ErrorStatus contains human readable error statuses.
	ErrorStatus = map[ErrorStatusT]string{
		ErrorStatusInvalid:          "invalid error status",
		ErrorStatusTokenInvalid:     "invalid token",
		ErrorStatusPublicKeyInvalid: "invalid public key",
		ErrorStatusSignatureInvalid: "invalid signature",
		ErrorStatusRecordNotFound:   "record not found",
		ErrorStatusCommentNotFound:  "comment not found",
		ErrorStatusParentIDInvalid:  "parent id invalid",
		ErrorStatusNoCommentChanges: "comment did not change",
		ErrorStatusVoteInvalid:      "invalid vote",
		ErrorStatusMaxVoteChanges:   "max vote changes exceeded",
	}
)

// UserError represents an error that is cause by something that the user did.
type UserError struct {
	ErrorCode    ErrorStatusT
	ErrorContext []string
}

// Error satisfies the error interface.
func (e UserError) Error() string {
	return fmt.Sprintf("plugin error code: %v", e.ErrorCode)
}

// Comment represent a record comment.
type Comment struct {
	Token     string `json:"token"`     // Record token
	ParentID  uint32 `json:"parentid"`  // Parent comment ID if reply
	Comment   string `json:"comment"`   // Comment text
	PublicKey string `json:"publickey"` // Public key used for Signature
	Signature string `json:"signature"` // Signature of Token+ParentID+Comment
	CommentID uint32 `json:"commentid"` // Comment ID
	Version   uint32 `json:"version"`   // Comment version
	Receipt   string `json:"receipt"`   // Server signature of client signature
	Timestamp int64  `json:"timestamp"` // UNIX timestamp of last edit
	Score     int64  `json:"score"`     // Vote score
	Deleted   bool   `json:"deleted"`   // Comment has been deleted
	Reason    string `json:"reason"`    // Reason for deletion
}

// New creates a new comment. A parent ID of 0 indicates that the comment is
// a base level comment and not a reply commment.
type New struct {
	Token     string `json:"token"`     // Record token
	ParentID  uint32 `json:"parentid"`  // Parent comment ID
	Comment   string `json:"comment"`   // Comment text
	PublicKey string `json:"publickey"` // Pubkey used for Signature
	Signature string `json:"signature"` // Signature of Token+ParentID+Comment
}

// EncodeNew encodes a New into a JSON byte slice.
func EncodeNew(n New) ([]byte, error) {
	return json.Marshal(n)
}

// DecodeNew decodes a JSON byte slice into a New.
func DecodeNew(payload []byte) (*New, error) {
	var n New
	err := json.Unmarshal(payload, &n)
	if err != nil {
		return nil, err
	}
	return &n, nil
}

// NewReply is the reply to the New command.
type NewReply struct {
	CommentID uint32 `json:"commentid"` // Comment ID
	Receipt   string `json:"receipt"`   // Server sig of client sig
	Timestamp int64  `json:"timestamp"` // Received UNIX timestamp
}

// EncodeNew encodes a NewReply into a JSON byte slice.
func EncodeNewReply(r NewReply) ([]byte, error) {
	return json.Marshal(r)
}

// DecodeNew decodes a JSON byte slice into a NewReply.
func DecodeNewReply(payload []byte) (*NewReply, error) {
	var r NewReply
	err := json.Unmarshal(payload, &r)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// Edit edits an existing comment.
type Edit struct {
	Token     string `json:"token"`     // Record token
	ParentID  uint32 `json:"parentid"`  // Parent comment ID
	CommentID uint32 `json:"commentid"` // Comment ID
	Comment   string `json:"comment"`   // Comment text
	PublicKey string `json:"publickey"` // Pubkey used for Signature
	Signature string `json:"signature"` // Signature of Token+ParentID+Comment
}

// EncodeEdit encodes a Edit into a JSON byte slice.
func EncodeEdit(e Edit) ([]byte, error) {
	return json.Marshal(e)
}

// DecodeEdit decodes a JSON byte slice into a Edit.
func DecodeEdit(payload []byte) (*Edit, error) {
	var e Edit
	err := json.Unmarshal(payload, &e)
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// EditReply is the reply to the Edit command.
type EditReply struct {
	Version   uint32 `json:"version"`   // Comment version
	Receipt   string `json:"receipt"`   // Server signature of client signature
	Timestamp int64  `json:"timestamp"` // Received UNIX timestamp
}

// EncodeEdit encodes a EditReply into a JSON byte slice.
func EncodeEditReply(r EditReply) ([]byte, error) {
	return json.Marshal(r)
}

// DecodeEdit decodes a JSON byte slice into a EditReply.
func DecodeEditReply(payload []byte) (*EditReply, error) {
	var r EditReply
	err := json.Unmarshal(payload, &r)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// Del permanently deletes all versions of the provided comment.
type Del struct {
	Token     string `json:"token"`     // Record token
	CommentID uint32 `json:"commentid"` // Comment ID
	Reason    string `json:"reason"`    // Reason for deletion
	PublicKey string `json:"publickey"` // Public key used for signature
	Signature string `json:"signature"` // Signature of Token+CommentID+Reason
}

// EncodeDel encodes a Del into a JSON byte slice.
func EncodeDel(d Del) ([]byte, error) {
	return json.Marshal(d)
}

// DecodeDel decodes a JSON byte slice into a Del.
func DecodeDel(payload []byte) (*Del, error) {
	var d Del
	err := json.Unmarshal(payload, &d)
	if err != nil {
		return nil, err
	}
	return &d, nil
}

// DelReply is the reply to the Del command.
type DelReply struct {
	Receipt   string `json:"receipt"`   // Server signature of client signature
	Timestamp int64  `json:"timestamp"` // Received UNIX timestamp
}

// EncodeDelReply encodes a DelReply into a JSON byte slice.
func EncodeDelReply(d DelReply) ([]byte, error) {
	return json.Marshal(d)
}

// DecodeDelReply decodes a JSON byte slice into a DelReply.
func DecodeDelReply(payload []byte) (*DelReply, error) {
	var d DelReply
	err := json.Unmarshal(payload, &d)
	if err != nil {
		return nil, err
	}
	return &d, nil
}

// Get returns the latest version of the comments for the provided comment IDs.
// An error is not returned if a comment is not found for one or more of the
// comment IDs. Those entries will simply not be included in the reply.
type Get struct {
	Token      string   `json:"token"`
	CommentIDs []uint32 `json:"commentids"`
}

// EncodeGet encodes a Get into a JSON byte slice.
func EncodeGet(g Get) ([]byte, error) {
	return json.Marshal(g)
}

// DecodeGet decodes a JSON byte slice into a Get.
func DecodeGet(payload []byte) (*Get, error) {
	var g Get
	err := json.Unmarshal(payload, &g)
	if err != nil {
		return nil, err
	}
	return &g, nil
}

// GetReply is the reply to the Get command. The returned map will not include
// an entry for any comment IDs that did not correspond to an actual comment.
// It is the responsibility of the caller to ensure that a comment was returned
// for all of the provided comment IDs.
type GetReply struct {
	Comments map[uint32]Comment `json:"comments"` // [commentID]Comment
}

// EncodeGetReply encodes a GetReply into a JSON byte slice.
func EncodeGetReply(g GetReply) ([]byte, error) {
	return json.Marshal(g)
}

// DecodeGetReply decodes a JSON byte slice into a GetReply.
func DecodeGetReply(payload []byte) (*GetReply, error) {
	var g GetReply
	err := json.Unmarshal(payload, &g)
	if err != nil {
		return nil, err
	}
	return &g, nil
}

// GetAll returns the latest version off all comments for the provided record.
type GetAll struct {
	Token string `json:"token"`
}

// EncodeGetAll encodes a GetAll into a JSON byte slice.
func EncodeGetAll(g GetAll) ([]byte, error) {
	return json.Marshal(g)
}

// DecodeGetAll decodes a JSON byte slice into a GetAll.
func DecodeGetAll(payload []byte) (*GetAll, error) {
	var g GetAll
	err := json.Unmarshal(payload, &g)
	if err != nil {
		return nil, err
	}
	return &g, nil
}

// GetAllReply is the reply to the GetAll command.
type GetAllReply struct {
	Comments []Comment `json:"comments"`
}

// EncodeGetAllReply encodes a GetAllReply into a JSON byte slice.
func EncodeGetAllReply(g GetAllReply) ([]byte, error) {
	return json.Marshal(g)
}

// DecodeGetAllReply decodes a JSON byte slice into a GetAllReply.
func DecodeGetAllReply(payload []byte) (*GetAllReply, error) {
	var g GetAllReply
	err := json.Unmarshal(payload, &g)
	if err != nil {
		return nil, err
	}
	return &g, nil
}

// GetVersion returns a specific version of a comment.
type GetVersion struct {
	Token     string `json:"token"`
	CommentID uint32 `json:"commentid"`
	Version   uint32 `json:"version"`
}

// EncodeGetVersion encodes a GetVersion into a JSON byte slice.
func EncodeGetVersion(g GetVersion) ([]byte, error) {
	return json.Marshal(g)
}

// DecodeGetVersion decodes a JSON byte slice into a GetVersion.
func DecodeGetVersion(payload []byte) (*GetVersion, error) {
	var g GetVersion
	err := json.Unmarshal(payload, &g)
	if err != nil {
		return nil, err
	}
	return &g, nil
}

// GetVersionReply is the reply to the GetVersion command.
type GetVersionReply struct {
	Comment Comment `json:"comment"`
}

// EncodeGetVersionReply encodes a GetVersionReply into a JSON byte slice.
func EncodeGetVersionReply(g GetVersionReply) ([]byte, error) {
	return json.Marshal(g)
}

// DecodeGetVersionReply decodes a JSON byte slice into a GetVersionReply.
func DecodeGetVersionReply(payload []byte) (*GetVersionReply, error) {
	var g GetVersionReply
	err := json.Unmarshal(payload, &g)
	if err != nil {
		return nil, err
	}
	return &g, nil
}

// Count returns the comments count for the provided record.
type Count struct {
	Token string `json:"token"`
}

// EncodeCount encodes a Count into a JSON byte slice.
func EncodeCount(c Count) ([]byte, error) {
	return json.Marshal(c)
}

// DecodeCount decodes a JSON byte slice into a Count.
func DecodeCount(payload []byte) (*Count, error) {
	var c Count
	err := json.Unmarshal(payload, &c)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// CountReply is the reply to the Count command.
type CountReply struct {
	Count uint64 `json:"count"`
}

// EncodeCountReply encodes a CountReply into a JSON byte slice.
func EncodeCountReply(c CountReply) ([]byte, error) {
	return json.Marshal(c)
}

// DecodeCountReply decodes a JSON byte slice into a CountReply.
func DecodeCountReply(payload []byte) (*CountReply, error) {
	var c CountReply
	err := json.Unmarshal(payload, &c)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// Vote casts a comment vote (upvote or downvote).
//
// The uuid is required because the effect of a new vote on a comment score
// depends on the previous vote from that uuid. Example, a user upvotes a
// comment that they have already upvoted, the resulting vote score is 0 due to
// the second upvote removing the original upvote. The public key cannot be
// relied on to remain the same for each user so a uuid must be included.
type Vote struct {
	UUID      string `json:"uuid"`      // Unique user ID
	Token     string `json:"token"`     // Record token
	CommentID uint32 `json:"commentid"` // Comment ID
	Vote      VoteT  `json:"vote"`      // Upvote or downvote
	PublicKey string `json:"publickey"` // Public key used for signature
	Signature string `json:"signature"` // Signature of Token+CommentID+Vote
}

// EncodeVote encodes a Vote into a JSON byte slice.
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

// VoteReply is the reply to the Vote command.
type VoteReply struct {
	Score     int64  `json:"score"`     // Overall comment vote score
	Receipt   string `json:"receipt"`   // Server signature of client signature
	Timestamp int64  `json:"timestamp"` // Received UNIX timestamp
}

// EncodeVoteReply encodes a VoteReply into a JSON byte slice.
func EncodeVoteReply(v VoteReply) ([]byte, error) {
	return json.Marshal(v)
}

// DecodeVoteReply decodes a JSON byte slice into a VoteReply.
func DecodeVoteReply(payload []byte) (*VoteReply, error) {
	var v VoteReply
	err := json.Unmarshal(payload, &v)
	if err != nil {
		return nil, err
	}
	return &v, nil
}
