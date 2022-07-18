// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

// ticketvote.go contains ticketvote plugin types that are not exported types,
// but are required when we import certain ticketvote data, so they are
// redefined here.

// voteCollider is an internal ticketvote plugin type that is not exported, so
// it's duplicated here.
type voteCollider struct {
	Token  string `json:"token"`
	Ticket string `json:"ticket"`
}

// startRunoffRecord is an internal ticketvote plugin type that is not
// exported, so it's duplicated here.
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
