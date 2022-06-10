// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	dcrdata "github.com/decred/dcrdata/v6/api/types"
)

// dcrdata.go contains API requests to the dcrdata API.

const (
	dcrdataHost = "https://dcrdata.decred.org/api"
)

// trimmedTxs returned the trimmed transaction data for each of the provided
// transaction hashes.
func (c *convertCmd) trimmedTxs(txs []string) ([]dcrdata.TrimmedTx, error) {
	req := dcrdata.Txns{
		Transactions: txs,
	}
	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	var (
		url = dcrdataHost + "/txs/trimmed"
		b   = bytes.NewReader(reqBody)
	)
	r, err := c.client.Post(url, "application/json; charset=utf-8", b)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, fmt.Errorf("dcrdata error: %v %v %v",
				r.StatusCode, url, err)
		}
		return nil, fmt.Errorf("dcrdata error: %v %v %s",
			r.StatusCode, url, body)
	}

	var ttxs []dcrdata.TrimmedTx
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&ttxs); err != nil {
		return nil, err
	}

	return ttxs, nil
}
