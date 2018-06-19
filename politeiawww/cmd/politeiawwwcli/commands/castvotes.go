package commands

type CastvotesArgs struct {
	Token  string `positional-arg-name:"token" description:"Proposal censorship token"`
	VoteId string `positional-arg-name:"voteid" description:"A single unique word identifying the vote (e.g. yes). The voteid is applied to all the tickets in your wallet."`
}

type CastvotesCmd struct {
	Args CastvotesArgs `positional-args:"true" required:"true"`
}

func (cmd *CastvotesCmd) Execute(args []string) error {
	_, err := Ctx.CastVotes(cmd.Args.Token, cmd.Args.VoteId)
	return err
}
