// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package commands

import "github.com/decred/politeia/politeiawww/api/v1"

// Help message displayed for the command 'politeiawwwcli help proposalpaywall'
var ProposalPaywallCmdHelpMsg = `proposalpaywall

Fetch proposal paywall details.

Arguments:
None

Response:
{
  "creditprice"          (uint64)  Price per proposal credit in atoms
  "paywalladdress"       (string)  Proposal paywall address
  "paywalltxnotbefore"   (string)  Minimum timestamp for paywall tx
}`

type ProposalPaywallCmd struct{}

func (cmd *ProposalPaywallCmd) Execute(args []string) error {
	ppdr, err := c.ProposalPaywallDetails(&v1.ProposalPaywallDetails{})
	if err != nil {
		return err
	}
	return Print(ppdr, cfg.Verbose, cfg.RawJSON)
}
