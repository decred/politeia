package commands

type VerifyuserpaymentCmd struct {
	Args struct {
		Txid string `positional-arg-name:"txid" description:"The id of the transaction on the blockchain that was sent to the paywall address"`
	} `positional-args:"true" required:"true"`
}

func (cmd *VerifyuserpaymentCmd) Execute(args []string) error {
	_, err := Ctx.VerifyUserPayment(cmd.Args.Txid)
	return err
}
