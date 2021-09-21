// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import (
	"encoding/json"
	"fmt"
	"strings"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/plugins/dcrdata"
	"github.com/pkg/errors"
)

const (
	// commitementAddrsKey is the key-value store key for the
	// the a cached commitmentAddrs.
	//
	// {token} is replaced by the record token.
	commitmentAddrsKey = pluginID + "-{token}-commitmentadddrs"
)

func getCommitmentAddrs(backend backend.Backend, tstore plugins.TstoreClient, tickets []string) (map[string]commitmentAddr, error) {
	// Check cache

	// Pull manually from dcrdata if needed

}

// commietmentAddrs contains the largest commitment address for each eligible
// ticket of a vote.
type commitmentAddrs struct {
	Addrs map[string]string `json:"addrs"` // [ticket]address
}

// TODO this should not use a database tx
// cacheCommitmentAddrs retreives the largest commitment address from dcrdata
// for each of the provided eligible tickets in a vote and saves the results to
// the cache.
func cacheCommitmentAddrs(backend backend.Backend, tstore plugins.TstoreClient, token string, eligibleTickets []string) {
	// Get the largest commitment address for each eligible
	// ticket. A TrimmedTxs response for 500 tickets is ~1MB.
	// It takes ~1.5 minutes to get the largest commitment
	// address for 41k eligible tickets from an off premise
	// dcrdata instance with minimal latency.
	var (
		pageSize = 500
		startIdx int
		done     bool

		// map[ticket]commitmentAddr
		addrs = make(map[string]commitmentAddr, len(eligibleTickets))
	)
	for !done {
		endIdx := startIdx + pageSize

		// Check if this is the last page
		if endIdx > len(eligibleTickets) {
			endIdx = len(eligibleTickets)
			done = true
		}

		log.Debugf("Get %v commitment addrs %v/%v",
			token, endIdx, len(eligibleTickets))

		// Get addresses
		tickets := eligibleTickets[startIdx:endIdx]
		a, err := getCommitmentAddrsFromDcrdata(backend, tickets)
		if err != nil {
			log.Errorf("Get commitment addresses for %v at %v: %v",
				token, startIdx, err)
			continue
		}

		// Save the results
		for k, v := range a {
			if v.err != nil {
				log.Errorf("Commitment address err: %v", err)
				continue
			}
			addrs[k] = v.addr
		}

		// Next page
		startIdx += pageSize
	}

	// Cache the addresses
	c := tstore.CacheClient(false)
	kv := map[string][]byte{
		getCommitmentAddrsKey(token): addrs,
	}
	err = c.Insert(kv)
	if err != nil {
		fmt.Errorf("Insert commitment addrs %v: %v",
			token, err)
	}
}

// commitmentAddr represents the largest commitment address for a dcr ticket.
type commitmentAddr struct {
	addr string // Commitment address
	err  error  // Error if one occurred
}

// getCommitmentAddrsFromDcrdata retrieves the largest commitment addresses for
// each of the provided tickets from dcrdata. If an error is encountered while
// retrieving a commitment address, the error will be included in the
// commitmentAddr struct. Individual errors will not cause this function to
// exit.
//
//  A map[ticket]commitmentAddr is returned.
func getCommitmentAddrsFromDcrdata(backend backend.Backend, tickets []string) (map[string]commitmentAddr, error) {
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
		return nil, errors.Errorf("PluginRead %v %v: %v",
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
			addrErr = errors.Errorf("no largest commitment address found")
		}

		// Store result
		addrs[tx.TxID] = commitmentAddr{
			addr: bestAddr,
			err:  addrErr,
		}
	}

	return addrs, nil
}

// getCommitmentAddrsKey returns the key-value store key for a cached
// commitmentAddrs.
func getCommitmentAddrsKey(token string) string {
	return strings.Replace(commitmentAddrskey, "{token}", token, 1)
}
