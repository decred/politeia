// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import (
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
)

const (
	// Internal plugin commands. These commands are not part of the
	// public plugin API. They are for internal use only.
	//
	// These commands are are necessary because the command to start
	// a runoff vote is executed on the parent record, but state is
	// updated for all of the runoff vote submissions as well. Plugin
	// commands should not normally be doing this, but we make an
	// exception in this case and use these internal plugin commands
	// as a workaround.
	cmdStartRunoffSub = "startrunoffsub"
	cmdRunoffDetails  = "runoffdetails"
)

// startRunoffSub is an internal plugin command that is used to start the
// voting period on a runoff vote submission.
type startRunoffSub struct {
	ParentToken  string                  `json:"parenttoken"`
	StartDetails ticketvote.StartDetails `json:"startdetails"`
}

// startRunoffSubReply is the reply to the startRunoffSub command.
type startRunoffSubReply struct{}

/*
// runoffDetails is an internal plugin command that requests the details of a
// runoff vote.
type runoffDetails struct{}

// runoffDetailsReply is the reply to the runoffDetails command.
type runoffDetailsReply struct {
	Runoff runoffRecord `json:"runoff"`
}
*/
