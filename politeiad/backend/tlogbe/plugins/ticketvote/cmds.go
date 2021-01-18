// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import "github.com/decred/politeia/politeiad/plugins/ticketvote"

const (
	// Internal plugin commands
	cmdStartRunoffSub = "startrunoffsub"
)

// startRunoffSub is an internal plugin command that is used to start the
// voting period on a runoff vote submission.
type startRunoffSub struct {
	ParentTreeID int64                   `json:"parenttreeid"`
	StartDetails ticketvote.StartDetails `json:"startdetails"`
}

// startRunoffSubReply is the reply to the startRunoffSub command.
type startRunoffSubReply struct{}
