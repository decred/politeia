// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package commands

// ProposalStatsCmd retrieves statistics on the proposal inventory.
type ProposalStatsCmd struct{}

// Execute executes the proposal stats command.
func (cmd *ProposalStatsCmd) Execute(args []string) error {
	psr, err := client.ProposalsStats()
	if err != nil {
		return err
	}
	return printJSON(psr)
}

// proposalStatsHelpMsg is the output of the help command when 'proposalstats'
// is specified.
const proposalStatsHelpMsg = `proposalstats

Get proposal inventory statistics.

Arguments: None

Result:
{
  "numofcensored": 1,
  "numofunvetted": 0,
  "numofunvettedchanges": 2,
  "numofpublic": 1,
  "numofabandoned": 1
}`
