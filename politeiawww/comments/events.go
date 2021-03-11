// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package comments

import (
	v1 "github.com/decred/politeia/politeiawww/api/comments/v1"
)

const (
	// EventTypeNew is emitted when a new comment is made.
	EventTypeNew = "comments-new"
)

// EventNew is the event data for the EventTypeNew.
type EventNew struct {
	State   v1.RecordStateT
	Comment v1.Comment
}
