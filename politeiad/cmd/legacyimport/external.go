package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	dcrdata "github.com/decred/dcrdata/v6/api/types"
)

// fetchUserByPubKey makes a call to the politeia API requesting the user
// with the provided public key.
func (l *legacy) fetchUserByPubKey(pubkey string) (*user, error) {
	url := "https://proposals.decred.org/api/v1/users?publickey=" + pubkey
	r, err := l.client.Get(url)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	var ur usersReply
	err = json.Unmarshal(body, &ur)
	if err != nil {
		return nil, err
	}

	if len(ur.Users) == 0 {
		return nil, fmt.Errorf("no user found for pubkey %v", pubkey)
	}

	return &ur.Users[0], nil
}

// fetchLargestCommitmentAddrs fetches the largest commitment address for each
// eligible ticket from a record vote. Returns a map of ticket hash to address.
func fetchLargestCommitmentAddrs(eligibleTickets []string) (map[string]string, error) {
	// Fetch addresses in batches of 500.
	var (
		ticketsLen = len(eligibleTickets)
		addrs      = make(map[string]string, ticketsLen) // [ticket]address
		pageSize   = 500
		startIdx   int
		done       bool
	)
	for !done {
		endIdx := startIdx + pageSize
		if endIdx > ticketsLen {
			endIdx = ticketsLen
			done = true
		}

		tickets := eligibleTickets[startIdx:endIdx]
		data, err := largestCommitmentAddrs(tickets)
		if err != nil {
			return nil, err
		}

		for ticket, address := range data {
			addrs[ticket] = address
		}

		startIdx += pageSize
	}

	return addrs, nil
}

func largestCommitmentAddrs(hashes []string) (map[string]string, error) {
	// Batch request all of the transaction info from dcrdata.
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
	var ttxs []dcrdata.TrimmedTx
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&ttxs); err != nil {
		return nil, err
	}

	// Find largest commitment address for each transaction.
	addrs := make(map[string]string, len(hashes))

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
					continue
				}
				bestAddr = v.ScriptPubKeyDecoded.Addresses[0]
				bestAmount = *v.ScriptPubKeyDecoded.CommitAmt
			}
		}

		if bestAddr == "" || bestAmount == 0.0 {
			return nil, fmt.Errorf("no best commitment address found: %v",
				ttxs[i].TxID)
		}
		addrs[ttxs[i].TxID] = bestAddr
	}

	return addrs, nil
}
