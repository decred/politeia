package commands

import (
	"encoding/json"
	"fmt"

	"github.com/decred/politeia/politeiawww/cmd/politeiawwwcli/config"
)

type ProposalvotesArgs struct {
	Token string `positional-arg-name:"token" description:"Proposal censorship token"`
}

type ProposalvotesCmd struct {
	Args ProposalvotesArgs `positional-args:"true" required:"true"`
}

func (cmd *ProposalvotesCmd) Execute(args []string) error {
	vrr, err := Ctx.ProposalVotes(cmd.Args.Token)
	if err != nil {
		return err
	}

	// tally votes
	tally := make(map[string]uint)
	for _, v := range vrr.CastVotes {
		tally[v.VoteBit]++
	}

	// print vote tally as JSON
	if config.Verbose {
		tallyJSON, err := json.Marshal(tally)
		if err != nil {
			return fmt.Errorf("Could not marshal vote tally: %v", err)
		}
		fmt.Printf("%s\n", tallyJSON)
	}

	return err
}
