// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package comments

// The comments plugin treats the trillian tree as a journal. The following
// types are the journal actions that are saved to disk.

// commentAdd is the structure that is saved to disk when a comment is created
// or edited.
type commentAdd struct {
	// Data generated by client
	Token     string `json:"token"`     // Record token
	ParentID  uint32 `json:"parentid"`  // Parent comment ID
	Comment   string `json:"comment"`   // Comment
	PublicKey string `json:"publickey"` // Pubkey used for Signature
	Signature string `json:"signature"` // Signature of Token+ParentID+Comment

	// Metadata generated by server
	CommentID uint32 `json:"commentid"` // Comment ID
	Version   uint32 `json:"version"`   // Comment version
	Receipt   string `json:"receipt"`   // Server signature of client signature
	Timestamp int64  `json:"timestamp"` // Received UNIX timestamp
}

// commentDel is the structure that is saved to disk when a comment is deleted.
type commentDel struct {
	// Data generated by client
	Token     string `json:"token"`     // Record token
	CommentID uint32 `json:"commentid"` // Comment ID
	Reason    string `json:"reason"`    // Reason for deleting
	PublicKey string `json:"publickey"` // Pubkey used for Signature
	Signature string `json:"signature"` // Signature of Token+CommentID+Reason

	// Metadata generated by server
	Receipt   string `json:"receipt"`   // Server signature of client signature
	Timestamp int64  `json:"timestamp"` // Received UNIX timestamp
}

// commentVote is the structure that is saved to disk when a comment is voted
// on.
type commentVote struct {
	UUID      string `json:"uuid"`      // Unique user ID
	Token     string `json:"token"`     // Record token
	CommentID uint32 `json:"commentid"` // Comment ID
	Vote      int64  `json:"vote"`      // Upvote or downvote
	PublicKey string `json:"publickey"` // Public key used for signature
	Signature string `json:"signature"` // Signature of Token+CommentID+Vote
	Receipt   string `json:"receipt"`   // Server signature of client signature
	Timestamp int64  `json:"timestamp"` // Received UNIX timestamp
}
