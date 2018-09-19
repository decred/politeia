package commands

import (
	"fmt"
	"strconv"
)

type TallyCmd struct {
	Args struct {
		Token string `positional-arg-name:"token" description:"Proposal censorship token"`
	} `positional-args:"true" required:"true"`
}

func (cmd *TallyCmd) Execute(args []string) error {
	// Get vote results for proposal
	vrr, err := c.ProposalVotes(cmd.Args.Token)
	if err != nil {
		return fmt.Errorf("ProposalVotes: %v", err)
	}

	// Tally votes
	var total uint
	tally := make(map[uint64]uint)
	for _, v := range vrr.CastVotes {
		bits, err := strconv.ParseUint(v.VoteBit, 10, 64)
		if err != nil {
			return err
		}
		tally[bits]++
		total++
	}

	if total == 0 {
		return fmt.Errorf("no votes recorded")
	}

	// Print results
	for _, vo := range vrr.StartVote.Vote.Options {
		votes := tally[vo.Bits]
		fmt.Printf("Vote Option:\n")
		fmt.Printf("  ID                   : %v\n", vo.Id)
		fmt.Printf("  Description          : %v\n", vo.Description)
		fmt.Printf("  Bits                 : %v\n", vo.Bits)
		fmt.Printf("  Votes received       : %v\n", votes)
		fmt.Printf("  Percentage           : %v%%\n",
			float64(votes)/float64(total)*100)
	}

	return nil
}
