package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	dcrdata "github.com/decred/dcrdata/v6/api/types"
)

// Get largest commitment address from dcrdata
func batchTransactions(hashes []string) ([]dcrdata.TrimmedTx, error) {
	// Request body is dcrdataapi.Txns marshalled to JSON
	reqBody, err := json.Marshal(dcrdata.Txns{
		Transactions: hashes,
	})
	if err != nil {
		return nil, err
	}

	// Make the POST request
	url := "https://dcrdata.decred.org/api/txs/trimmed"
	r, err := http.Post(url, "application/json; charset=utf-8",
		bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			return nil, fmt.Errorf("dcrdata error: %v %v %v",
				r.StatusCode, url, err)
		}
		return nil, fmt.Errorf("dcrdata error: %v %v %s",
			r.StatusCode, url, body)
	}

	// Unmarshal the response
	var ttx []dcrdata.TrimmedTx
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&ttx); err != nil {
		return nil, err
	}
	return ttx, nil
}

func largestCommitmentAddresses(hashes []string) (map[string]largestCommitmentResult, error) {
	// Batch request all of the transaction info from dcrdata.
	ttxs, err := batchTransactions(hashes)
	if err != nil {
		return nil, err
	}

	// Find largest commitment address for each transaction.
	addrs := make(map[string]largestCommitmentResult, len(hashes))

	for i := range ttxs {
		// Best is address with largest commit amount.
		var bestAddr string
		var bestAmount float64
		for _, v := range ttxs[i].Vout {
			if v.ScriptPubKeyDecoded.CommitAmt == nil {
				continue
			}
			if *v.ScriptPubKeyDecoded.CommitAmt > bestAmount {
				if len(v.ScriptPubKeyDecoded.Addresses) == 0 {
					// jrick, does this need to be printed?
					fmt.Errorf("unexpected addresses "+
						"length: %v", ttxs[i].TxID)
					continue
				}
				bestAddr = v.ScriptPubKeyDecoded.Addresses[0]
				bestAmount = *v.ScriptPubKeyDecoded.CommitAmt
			}
		}

		if bestAddr == "" || bestAmount == 0.0 {
			addrs[ttxs[i].TxID] = largestCommitmentResult{
				err: fmt.Errorf("no best commitment address found: %v",
					ttxs[i].TxID),
			}
			continue
		}
		addrs[ttxs[i].TxID] = largestCommitmentResult{
			bestAddr: bestAddr,
		}
	}

	return addrs, nil
}
