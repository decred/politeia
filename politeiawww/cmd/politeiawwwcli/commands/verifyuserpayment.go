package commands

type VerifyuserpaymentCmd struct{}

func (cmd *VerifyuserpaymentCmd) Execute(args []string) error {
	_, err := Ctx.VerifyUserPayment()
	return err
}
