package commands

// Help message displayed for the command 'politeiawwwcli help votestatus'
var VoteStatusCmdHelpMsg = `votestatus "token"

Fetch vote status for a proposal.

Proposal vote status codes:

'0' - Invalid vote status
'1' - Vote has not been authorized by proposal author
'2' - Vote has been authorized by proposal author
'3' - Proposal vote has been started
'4' - Proposal vote has been finished
'5' - Proposal doesn't exist

Arguments:
1. token       (string, required)  Proposal censorship token

Request:
{
  "token":     (string)  Proposal censorship token
}

Response:
{
  "token":              (string)  Public key of user that submitted proposal
  "status":             (int)     Vote status code
  "totalvotes":         (uint64)  Total number of votes on proposal
  "optionsresult": [
    {
      "option": {
        "id":           (string)  Unique word identifying vote (e.g. 'yes')
        "description":  (string)  Longer description of the vote
        "bits":         (uint64)  Bits used for this option
      },
      "votesreceived":  (uint64)  Number of votes received
    },
  ],
  "endheight":          (string)  String encoded final block height of the vote
  "numofeligiblevotes": (int)     Total number of eligible votes
  "quorumpercentage":   (uint32)  Percent of eligible votes required for quorum
  "passpercentage":     (uint32)  Percent of total votes required to pass
}`

type VoteStatusCmd struct {
	Args struct {
		Token string `positional-arg-name:"token" description:"Proposal censorship token"`
	} `positional-args:"true" required:"true"`
}

func (cmd *VoteStatusCmd) Execute(args []string) error {
	vsr, err := c.VoteStatus(cmd.Args.Token)
	if err != nil {
		return err
	}
	return Print(vsr, cfg.Verbose, cfg.RawJSON)
}
