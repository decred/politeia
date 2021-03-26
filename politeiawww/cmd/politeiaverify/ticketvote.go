// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	tkv1 "github.com/decred/politeia/politeiad/plugins/ticketvote"
)

// voteBundle represents the bundle that is downloaded from politeiagui for
// DCR ticket votes.
type voteBundle struct {
	Auths           []tkv1.AuthDetails     `json:"auths,omitempty"`
	Details         *tkv1.VoteDetails      `json:"details,omitempty"`
	Votes           []tkv1.CastVoteDetails `json:"votes,omitempty"`
	ServerPublicKey string                 `json:"serverpublickey"`
}
