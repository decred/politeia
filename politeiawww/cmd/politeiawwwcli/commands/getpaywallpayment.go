package commands

// Help message displayed for the command 'politeiawwwcli help getpaywallpayment'
var GetPaywallPaymentCmdHelpMsg = `getpaywallpayment

Fetch proposal paywall payment details for currently logged in user. 

Arguments:
None

Response:
{
  "txid"           (string)  Transaction id
  "amount"         (uint64)  Amount sent to paywall address in atoms
  "confirmations"  (uint64)  Number of confirmations of payment tx
}`

type GetPaywallPaymentCmd struct{}

func (cmd *GetPaywallPaymentCmd) Execute(args []string) error {
	pppr, err := c.ProposalPaywallPayment()
	if err != nil {
		return err
	}
	return Print(pppr, cfg.Verbose, cfg.RawJSON)
}
