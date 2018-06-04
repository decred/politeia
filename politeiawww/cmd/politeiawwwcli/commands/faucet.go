package commands

import (
	"fmt"

	"github.com/decred/politeia/politeiawww/cmd/politeiawwwcli/config"
	"github.com/decred/politeia/util"
)

type FaucetArgs struct {
	Address string `positional-arg-name:"address" description:"Address to send DCR to"`
	Amount  uint64 `positional-arg-name:"amount" description:"Amount to send in Atoms"`
}

type FaucetCmd struct {
	Args          FaucetArgs `positional-args:"true" required:"true"`
	OverrideToken string     `long:"overridetoken" optional:"true" description:"Override token for the testnet faucet"`
}

func (cmd *FaucetCmd) Execute(args []string) error {
	address := cmd.Args.Address
	amount := cmd.Args.Amount
	amountInDCR := float64(amount) / 1e8

	if address == "" && amount == 0 {
		return fmt.Errorf("Argument error. Unable to pay %v DCR to %v",
			amountInDCR, address)
	}

	faucetTx, err := util.PayWithTestnetFaucet(config.FaucetURL, address, amount,
		cmd.OverrideToken)
	if err != nil {
		return fmt.Errorf("Unable to pay %v DCR to %v with faucet: %v",
			amountInDCR, address, err)
	}

	if config.PrintJSON {
		fmt.Printf("{\"faucetTx\":\"%v\"}\n", faucetTx)
	}
	if config.Verbose {
		fmt.Printf("Paid %v DCR to %v with faucet tx %v\n", amountInDCR, address,
			faucetTx)
	}

	return nil
}
