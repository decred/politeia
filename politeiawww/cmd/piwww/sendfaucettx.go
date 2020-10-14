// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"

	"github.com/decred/politeia/util"
)

// sendFaucetTxCmd uses the Decred testnet faucet to send the specified amount
// of DCR (in atoms) to the specified address.
type sendFaucetTxCmd struct {
	Args struct {
		Address       string `positional-arg-name:"address" required:"true"`
		Amount        uint64 `positional-arg-name:"amount" required:"true"`
		OverrideToken string `positional-arg-name:"overridetoken"`
	} `positional-args:"true"`
}

// Execute executes the send faucet tx command.
func (cmd *sendFaucetTxCmd) Execute(args []string) error {
	address := cmd.Args.Address
	atoms := cmd.Args.Amount
	dcr := float64(atoms) / 1e8

	txID, err := util.PayWithTestnetFaucet(context.Background(),
		cfg.FaucetHost, address, atoms, cmd.Args.OverrideToken)
	if err != nil {
		return err
	}

	switch {
	case cfg.Silent:
		// Keep quite
	case cfg.RawJSON:
		fmt.Printf(`{"txid":"%v"}`, txID)
		fmt.Printf("\n")
	default:
		fmt.Printf("Paid %v DCR to %v with tx %v\n", dcr, address, txID)
	}

	return nil
}

// sendFaucetTxHelpMsg is the help command message.
const sendFaucetTxHelpMsg = `sendfaucettx "address" "amount" "overridetoken"

Use the Decred testnet faucet to send DCR (in atoms) to an address. One atom is
one hundred millionth of a single DCR (0.00000001 DCR).

Arguments:
1. address          (string, required)   Receiving address
2. amount           (uint64, required)   Amount to send (in atoms)
3. overridetoken    (string, optional)   Override token for testnet faucet
`
