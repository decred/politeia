package commands

import "fmt"

type VerifyUserPaymentCmd struct{}

func (cmd *VerifyUserPaymentCmd) Execute(args []string) error {
	vupr, err := c.VerifyUserPayment()
	if err != nil {
		return fmt.Errorf("VerifyUserPayment: %v", err)
	}
	return Print(vupr, cfg.Verbose, cfg.RawJSON)
}
