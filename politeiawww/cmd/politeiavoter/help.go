// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

const listCmdMessage = `Available commands:
  inventory Retrieve all proposals that are being voted on
  vote      Vote on a proposal
  tally     Tally votes on a proposal
  verify    Verify votes on a proposal
  help      Print detailed help message for a command
`

const inventoryHelpMsg = `inventory 

Retrieve all proposals that are being voted on.
`

const voteHelpMsg = `vote "token" "voteid"

Vote on a proposal.

Arguments:
1. token   (string, required)  Proposal censorship token
2. voteid  (string, required)  Vote option ID (e.g. yes)
`

const tallyHelpMsg = `tally "token"

Tally votes on a proposal.

Arguments:
1. token   (string, required)  Proposal censorship token
`

const verifyHelpMsg = `verify "tokens..."

Verify votes on proposals. If no tokens are provided or 'ALL' string is 
provided then it verifies all votes present in the vote dir.

Arguments:
1. tokens  ([]string, optional)  Proposal tokens.
`
