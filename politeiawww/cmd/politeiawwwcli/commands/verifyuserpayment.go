package commands

import "fmt"

// Help message displayed for the command 'politeiawwwcli help verifyuserpayment'
var VerifyUserPaymentCmdHelpMsg = `verifyuserpayment 

Check if the currently logged in user has paid their user registration fee.

Arguments:
None

Result:
{
  "haspaid"                (bool)    Has paid or not
  "paywalladdress"         (string)  Registration paywall address
  "paywallamount"          (uint64)  Registration paywall amount in atoms
  "paywalltxnotbefore"     (int64)   Minimum timestamp for paywall tx
}`

type VerifyUserPaymentCmd struct{}

func (cmd *VerifyUserPaymentCmd) Execute(args []string) error {
	vupr, err := c.VerifyUserPayment()
	if err != nil {
		return fmt.Errorf("VerifyUserPayment: %v", err)
	}
	return Print(vupr, cfg.Verbose, cfg.RawJSON)
}
