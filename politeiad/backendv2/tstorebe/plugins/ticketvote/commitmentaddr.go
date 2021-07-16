// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import (
	"encoding/json"
	"fmt"

	"github.com/decred/politeia/politeiad/plugins/dcrdata"
)

// commitmentAddr represents the largest commitment address for a dcr ticket.
type commitmentAddr struct {
	addr string // Commitment address
	err  error  // Error if one occurred
}

// largestCommitmentAddrs retrieves the largest commitment addresses for each
// of the provided tickets from dcrdata. A map[ticket]commitmentAddr is
// returned. If an error is encountered while retrieving a commitment address,
// the error will be included in the commitmentAddr struct in the returned
// map.
func (p *ticketVotePlugin) largestCommitmentAddrs(tickets []string) (map[string]commitmentAddr, error) {
	// Get tx details
	tt := dcrdata.TxsTrimmed{
		TxIDs: tickets,
	}
	payload, err := json.Marshal(tt)
	if err != nil {
		return nil, err
	}
	reply, err := p.backend.PluginRead(nil, dcrdata.PluginID,
		dcrdata.CmdTxsTrimmed, string(payload))
	if err != nil {
		return nil, fmt.Errorf("PluginRead %v %v: %v",
			dcrdata.PluginID, dcrdata.CmdTxsTrimmed, err)
	}
	var ttr dcrdata.TxsTrimmedReply
	err = json.Unmarshal([]byte(reply), &ttr)
	if err != nil {
		return nil, err
	}

	// Find the largest commitment address for each tx
	addrs := make(map[string]commitmentAddr, len(ttr.Txs))
	for _, tx := range ttr.Txs {
		var (
			bestAddr string  // Addr with largest commitment amount
			bestAmt  float64 // Largest commitment amount
			addrErr  error   // Error if one is encountered
		)
		for _, vout := range tx.Vout {
			scriptPubKey := vout.ScriptPubKeyDecoded
			switch {
			case scriptPubKey.CommitAmt == nil:
				// No commitment amount; continue
			case len(scriptPubKey.Addresses) == 0:
				// No commitment address; continue
			case *scriptPubKey.CommitAmt > bestAmt:
				// New largest commitment address found
				bestAddr = scriptPubKey.Addresses[0]
				bestAmt = *scriptPubKey.CommitAmt
			}
		}
		if bestAddr == "" || bestAmt == 0.0 {
			addrErr = fmt.Errorf("no largest commitment address " +
				"found")
		}

		// Store result
		addrs[tx.TxID] = commitmentAddr{
			addr: bestAddr,
			err:  addrErr,
		}
	}

	return addrs, nil
}
