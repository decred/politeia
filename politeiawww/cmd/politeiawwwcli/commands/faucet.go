package commands

import (
	"fmt"

	"github.com/decred/politeia/util"
)

// Help message displayed for the command 'politeiawwwcli help faucet'
var FaucetCmdHelpMsg = `faucet "address" "amount" 

Use the Decred testnet faucet to send DCR (in atoms) to an address. One atom is
one hundred millionth of a single DCR (0.00000001 DCR).

Arguments:
1. address      (string, required)   Receiving address
2. amount       (uint64, required)   Amount to send (atoms)

Result:
Paid [amount] DCR to [address] with txID [transaction id]`

type FaucetCmd struct {
	Args struct {
		Address       string `positional-arg-name:"address" required:"true" description:"Address to send DCR to"`
		Amount        uint64 `positional-arg-name:"amount" required:"true" description:"Amount to send (in atoms)"`
		OverrideToken string `positional-arg-name:"overridetoken" description:"Override token for testnet faucet"`
	} `positional-args:"true"`
}

func (cmd *FaucetCmd) Execute(args []string) error {
	address := cmd.Args.Address
	atoms := cmd.Args.Amount
	dcr := float64(atoms) / 1e8

	if address == "" && atoms == 0 {
		return fmt.Errorf("Invalid arguments. Unable to pay %v DCR to %v",
			dcr, address)
	}

	txID, err := util.PayWithTestnetFaucet(cfg.FaucetHost, address, atoms,
		cmd.Args.OverrideToken)
	if err != nil {
		return err
	}

	if cfg.RawJSON {
		fmt.Printf(`{"txid":"%v"}`, txID)
		fmt.Printf("\n")
	} else {
		fmt.Printf("Paid %v DCR to %v with txID %v\n",
			dcr, address, txID)
	}

	return nil
}
