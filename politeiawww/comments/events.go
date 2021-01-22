// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package comments

const (
	// EventTypeNew is the event that is emitted when a new comment is
	// made.
	EventTypeNew = "commentnew"
)

// EventNew is the event data that is emitted when a new comment is made.
type EventNew struct {
	State     string
	Token     string
	CommentID uint32
	ParentID  uint32
	Username  string
}
