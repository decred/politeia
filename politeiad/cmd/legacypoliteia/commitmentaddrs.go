// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	dcrdata "github.com/decred/dcrdata/v6/api/types"
)

// commitmentAddrs returns the largest commitment address for each of the
// provided ticket hashes. Transaction data for the ticket is retrieved from
// dcrdata during this process.
func (c *convertCmd) commitmentAddrs(tickets []string) (map[string]string, error) {
	fmt.Printf("    Retrieving commitment addresses from dcrdata...\n")

	// Fetch addresses in batches
	var (
		addrs    = make(map[string]string, len(tickets)) // [ticket]address
		pageSize = 500
		startIdx int
		done     bool
	)
	for !done {
		endIdx := startIdx + pageSize
		if endIdx >= len(tickets) {
			endIdx = len(tickets)
			done = true
		}

		// startIdx is included. endIdx is excluded.
		ts := tickets[startIdx:endIdx]
		ttxs, err := c.trimmedTxs(ts)
		if err != nil {
			return nil, err
		}

		// Pull out the largest commitment address for each of the
		// transactions.
		for _, ttx := range ttxs {
			var (
				ticket = ttx.TxID
				addr   = largestCommitmentAddr(ttx)
			)
			if addr == "" {
				return nil, fmt.Errorf("no commitment address found for %v", ticket)
			}
			addrs[ticket] = addr
		}

		startIdx += pageSize
		printInPlace(fmt.Sprintf("    Retrieved addresses %v/%v",
			len(addrs), len(tickets)))
	}
	fmt.Printf("\n")

	return addrs, nil
}

// largestCommitmentAddr returns the largest commitment address that is found
// in the provided tx.
func largestCommitmentAddr(tx dcrdata.TrimmedTx) string {
	// Best is address with largest commit amount
	var bestAddr string
	var bestAmount float64
	for _, v := range tx.Vout {
		if v.ScriptPubKeyDecoded.CommitAmt == nil {
			continue
		}
		if *v.ScriptPubKeyDecoded.CommitAmt > bestAmount {
			if len(v.ScriptPubKeyDecoded.Addresses) == 0 {
				continue
			}
			bestAddr = v.ScriptPubKeyDecoded.Addresses[0]
			bestAmount = *v.ScriptPubKeyDecoded.CommitAmt
		}
	}
	if bestAmount == 0.0 {
		// This should not happen
		return ""
	}
	return bestAddr
}
