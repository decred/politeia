// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package util

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/dcrd/dcrutil"
	"github.com/decred/dcrd/hdkeychain"
)

const (
	faucetTimeout = 5 * time.Second // Testnet faucet request timeout

	// Must match dcrwallets udb.ExternalBranch
	externalBranch uint32 = 0
)

// FaucetResponse represents the expected JSON response from the testnet faucet.
type FaucetResponse struct {
	Txid  string
	Error string
}

// DerivePaywallAddress derives a paywall address using the provided xpub and
// index.
func DerivePaywallAddress(params *chaincfg.Params, xpub string, index uint32) (string, error) {
	// Parse the extended public key.
	acctKey, err := hdkeychain.NewKeyFromString(xpub)
	if err != nil {
		return "", err
	}

	// Derive the appropriate branch key.
	branchKey, err := acctKey.Child(externalBranch)
	if err != nil {
		return "", err
	}

	key, err := branchKey.Child(index)
	if err != nil {
		return "", err
	}

	addr, err := key.Address(params)
	if err != nil {
		return "", err
	}

	return addr.EncodeAddress(), nil
}

// PayWithTestnetFaucet makes a request to the testnet faucet.
func PayWithTestnetFaucet(faucetURL string, address string, amount uint64, overridetoken string) (string, error) {
	dcraddress, err := dcrutil.DecodeAddress(address)
	if err != nil {
		return "", fmt.Errorf("address is invalid: %v", err)
	}

	if !dcraddress.IsForNet(&chaincfg.TestNet3Params) {
		return "", fmt.Errorf("faucet only supports testnet")
	}

	dcramount := strconv.FormatFloat(dcrutil.Amount(amount).ToCoin(),
		'f', -1, 32)

	// build request
	form := url.Values{}
	form.Add("address", address)
	form.Add("amount", dcramount)
	form.Add("overridetoken", overridetoken)

	req, err := http.NewRequest("POST", faucetURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.PostForm = form
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	// limit the time we take
	ctx, cancel := context.WithTimeout(context.Background(),
		faucetTimeout)
	// it is good practice to use the cancellation function even with a timeout
	defer cancel()
	req = req.WithContext(ctx)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("testnet faucet error: %v %v %v",
				resp.StatusCode, faucetURL, err)
		}
		return "", fmt.Errorf("testnet faucet error: %v %v %s",
			resp.StatusCode, faucetURL, body)
	}

	if resp == nil {
		return "", errors.New("unknown error")
	}

	jsonReply := resp.Header.Get("X-Json-Reply")
	if jsonReply == "" {
		return "", fmt.Errorf("bad reply from %v", faucetURL)
	}

	fr := &FaucetResponse{}
	err = json.Unmarshal([]byte(jsonReply), fr)
	if err != nil {
		return "", fmt.Errorf("unable to process reply: '%v': %v", jsonReply,
			err)
	}

	if fr.Error != "" {
		return "", errors.New(fr.Error)
	}

	return fr.Txid, nil
}
