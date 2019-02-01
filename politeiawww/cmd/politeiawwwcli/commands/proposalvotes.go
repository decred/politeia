package commands

// Help message displayed for the command 'politeiawwwcli help proposalvotes'
var ProposalVotesCmdHelpMsg = `proposalvotes "token"

Fetch vote results for a proposal.

Arguments:
1. token       (string, required)  Proposal censorship token

Request:
{
  "token":     (string)  Proposal censorship token
}

Response:
{
  "startvote": {
    "publickey"            (string)  Public key of user that submitted proposal
    "vote": {
      "token":             (string)  Censorship token
      "mask"               (uint64)  Valid votebits
      "duration":          (uint32)  Duration of vote in blocks
      "quorumpercentage"   (uint32)  Percent of votes required for quorum
      "passpercentage":    (uint32)  Percent of votes required to pass
      "options": [
        {
          "id"             (string)  Unique word identifying vote (e.g. yes)
          "description"    (string)  Longer description of the vote
          "bits":          (uint64)  Bits used for this option
        },
      ]
    },
    "signature"            (string)  Signature of Votehash
  },
  "castvotes": [],
  "startvotereply": {
    "startblockheight":    (string)  Block height at start of vote
    "startblockhash":      (string)  Hash of first block of vote interval
    "endheight":           (string)  Block height at end of vote
    "eligibletickets": [
      "removed by politeiawwwcli for readability"
    ]
  }
}`

type ProposalVotesCmd struct {
	Args struct {
		Token string `positional-arg-name:"token" description:"Proposal censorship token"`
	} `positional-args:"true" required:"true"`
}

func (cmd *ProposalVotesCmd) Execute(args []string) error {
	vrr, err := c.ProposalVotes(cmd.Args.Token)
	if err != nil {
		return err
	}

	// Remove eligible tickets snapshot from response
	// so that the output is legible
	if !cfg.RawJSON {
		vrr.StartVoteReply.EligibleTickets = []string{
			"removed by politeiawwwcli for readability",
		}
	}

	return Print(vrr, cfg.Verbose, cfg.RawJSON)
}
