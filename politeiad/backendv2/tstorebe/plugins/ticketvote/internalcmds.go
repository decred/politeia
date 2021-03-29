// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import "github.com/decred/politeia/politeiad/plugins/ticketvote"

const (
	// Internal plugin commands. These commands are not part of the
	// public plugin API. They are for internal use only.
	//
	// These are are necessary because the command to start a runoff
	// vote is executed on the parent record, but state is updated in
	// all of the runoff vote submissions as well. Plugin commands
	// should not be doing this. This is an exception and we use these
	// internal plugin commands as a workaround.
	cmdStartRunoffSubmission = "startrunoffsub"
	cmdRunoffDetails         = "runoffdetails"
)

// startRunoffRecord is the record that is saved to the runoff vote's parent
// tree as the first step in starting a runoff vote. Plugins are not able to
// update multiple records atomically, so if this call gets interrupted before
// if can start the voting period on all runoff vote submissions, subsequent
// calls will use this record to pick up where the previous call left off. This
// allows us to recover from unexpected errors, such as network errors, and not
// leave a runoff vote in a weird state.
type startRunoffRecord struct {
	Submissions      []string `json:"submissions"`
	Mask             uint64   `json:"mask"`
	Duration         uint32   `json:"duration"`
	QuorumPercentage uint32   `json:"quorumpercentage"`
	PassPercentage   uint32   `json:"passpercentage"`
	StartBlockHeight uint32   `json:"startblockheight"`
	StartBlockHash   string   `json:"startblockhash"`
	EndBlockHeight   uint32   `json:"endblockheight"`
	EligibleTickets  []string `json:"eligibletickets"`
}

// startRunoffSubmission is an internal plugin command that is used to start
// the voting period on a runoff vote submission.
type startRunoffSubmission struct {
	ParentToken  string                  `json:"parenttoken"`
	StartDetails ticketvote.StartDetails `json:"startdetails"`
}

// startRunoffSubmissionReply is the reply to the startRunoffSubmission
// command.
type startRunoffSubmissionReply struct{}

// runoffDetails is an internal plugin command that requests the details of a
// runoff vote.
type runoffDetails struct{}

// runoffDetailsReply is the reply to the runoffDetails command.
type runoffDetailsReply struct {
	Runoff startRunoffRecord `json:"runoff"`
}
