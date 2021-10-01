// Copyright (c) 2017-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/dcrutil/v3"
	"github.com/decred/politeia/util"
)

// cmdSendFaucetTx uses the Decred testnet faucet to send the specified amount
// of DCR (in atoms) to the specified address.
type cmdSendFaucetTx struct {
	Args struct {
		Address       string `positional-arg-name:"address" required:"true"`
		Amount        string `positional-arg-name:"amount" required:"true"`
		OverrideToken string `positional-arg-name:"overridetoken"`
	} `positional-args:"true"`
}

// Execute executes the cmdSendFaucetTx command.
//
// This function satisfies the go-flags Commander interface.
func (c *cmdSendFaucetTx) Execute(args []string) error {
	address := c.Args.Address
	amount := c.Args.Amount

	txID, err := sendFaucetTx(cfg.FaucetHost, address,
		amount, c.Args.OverrideToken)
	if err != nil {
		return err
	}

	printf("Paid %v DCR to %v with tx %v\n", amount, address, txID)

	return nil
}

// faucetReply contains the reply from the DCR testnet faucet. The reply will
// be included in the "x-json-reply" header.
type faucetReply struct {
	TxID  string `json:"txid"`
	Error string `json:"error"`
}

// sendFaucetTx sends a request to the DCR testnet faucet that asks it to send
// DCR from the faucet to the provided address.
func sendFaucetTx(faucetURL string, address, amountInDCR, overridetoken string) (string, error) {
	// Verify address is valid
	_, err := dcrutil.DecodeAddress(address, chaincfg.TestNet3Params())
	if err != nil {
		return "", err
	}

	// Setup request
	form := url.Values{}
	form.Add("address", address)
	form.Add("amount", amountInDCR)
	form.Add("overridetoken", overridetoken)

	req, err := http.NewRequestWithContext(context.Background(),
		http.MethodPost, faucetURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.PostForm = form
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	// Send request
	client, err := util.NewHTTPClient(false, "")
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Handle reply
	if resp.StatusCode != http.StatusOK {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("testnet faucet error: %v %v %v",
				resp.StatusCode, faucetURL, err)
		}
		return "", fmt.Errorf("testnet faucet error: %v %v %s",
			resp.StatusCode, faucetURL, body)
	}

	// The reply will be in the JSON header
	reply := resp.Header.Get("X-Json-Reply")
	if reply == "" {
		return "", fmt.Errorf("empty JSON reply header")
	}

	var fr faucetReply
	err = json.Unmarshal([]byte(reply), &fr)
	if err != nil {
		return "", err
	}
	if fr.Error != "" {
		return "", errors.New(fr.Error)
	}

	return fr.TxID, nil
}

// sendFaucetTxHelpMsg is the printed to stdout by the help command.
const sendFaucetTxHelpMsg = `sendfaucettx "address" amount "overridetoken"

Use the Decred testnet faucet to send DCR to an address.

Arguments:
1. address        (string, required)  Receiving address
2. amount         (string, required)  Amount to send in DCR. Supported input
                                      variations: "1", ".1", "0.1".
3. overridetoken  (string, optional)  Override token for testnet faucet
`
