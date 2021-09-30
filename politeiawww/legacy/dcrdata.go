// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package legacy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/dcrutil/v3"
)

const (
	dcrdataTimeout = 3 * time.Second // Dcrdata request timeout
	faucetTimeout  = 5 * time.Second // Testnet faucet request timeout
)

func (p *Politeiawww) dcrdataHostHTTP() string {
	return fmt.Sprintf("https://%v/api", p.cfg.DcrdataHost)
}

func (p *Politeiawww) dcrdataHostWS() string {
	return fmt.Sprintf("wss://%v/ps", p.cfg.DcrdataHost)
}

// FaucetResponse represents the expected JSON response from the testnet faucet.
type FaucetResponse struct {
	Txid  string
	Error string
}

// BETransaction is an object representing a transaction; it's
// part of the data returned from the URL for the block explorer
// when fetching the transactions for an address.
type BETransaction struct {
	TxId          string              `json:"txid"`          // Transaction id
	Vin           []BETransactionVin  `json:"vin"`           // Transaction inputs
	Vout          []BETransactionVout `json:"vout"`          // Transaction outputs
	Confirmations uint64              `json:"confirmations"` // Number of confirmations
	Timestamp     int64               `json:"time"`          // Transaction timestamp
}

// BETransactionVin holds the transaction prevOut address information
type BETransactionVin struct {
	PrevOut BETransactionPrevOut `json:"prevOut"` // Previous transaction output
}

// BETransactionPrevOut holds the information about the inputs' previous addresses.
// This will allow one to check for dev subsidy origination, etc.
type BETransactionPrevOut struct {
	Addresses []string `json:"addresses"` // Array of transaction input addresses
}

// BETransactionVout holds the transaction amount information.
type BETransactionVout struct {
	Amount       json.Number               `json:"value"`        // Transaction amount (in DCR)
	ScriptPubkey BETransactionScriptPubkey `json:"scriptPubkey"` // Transaction script info
}

// BETransactionScriptPubkey holds the script info for a
// transaction.
type BETransactionScriptPubkey struct {
	Addresses []string `json:"addresses"` // Array of transaction input addresses
}

// TxDetails is an object representing a transaction.
// XXX This was previously being used to standardize the different responses
// from the dcrdata and insight APIs. Support for the insight API was removed
// but parts of politeiawww still consume this struct so it has remained.
type TxDetails struct {
	Address        string   // Transaction address
	TxID           string   // Transacion ID
	Amount         uint64   // Transaction amount (in atoms)
	Timestamp      int64    // Transaction timestamp
	Confirmations  uint64   // Number of confirmations
	InputAddresses []string /// An array of all addresses from previous outputs
}

func makeRequest(ctx context.Context, url string, timeout time.Duration) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to create request: %v", err)
	}

	client := &http.Client{
		Timeout: timeout * time.Second,
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return nil, fmt.Errorf("dcrdata error: %v %v %v",
				response.StatusCode, url, err)
		}
		return nil, fmt.Errorf("dcrdata error: %v %v %s",
			response.StatusCode, url, body)
	}

	return ioutil.ReadAll(response.Body)
}

// dcrStringToAmount converts a DCR amount as a string into a uint64
// representing atoms. Supported input variations: "1", ".1", "0.1"
func dcrStringToAmount(dcrstr string) (uint64, error) {
	match, err := regexp.MatchString("(\\d*\\.)*\\d+", dcrstr)
	if err != nil {
		return 0, err
	}
	if !match {
		return 0, fmt.Errorf("invalid DCR amount: %v", dcrstr)
	}

	var dcrsplit []string
	if strings.Contains(dcrstr, ".") {
		dcrsplit = strings.Split(dcrstr, ".")
		if len(dcrsplit[0]) == 0 {
			dcrsplit[0] = "0"
		}
	} else {
		dcrsplit = []string{dcrstr, "0"}
	}

	whole, err := strconv.ParseUint(dcrsplit[0], 10, 64)
	if err != nil {
		return 0, err
	}

	dcrsplit[1] += "00000000"
	fraction, err := strconv.ParseUint(dcrsplit[1][0:8], 10, 64)
	if err != nil {
		return 0, err
	}

	return ((whole * 1e8) + fraction), nil
}

func fetchTxWithBE(ctx context.Context, url string, address string, minimumAmount uint64, txnotbefore int64, minConfirmationsRequired uint64) (string, uint64, error) {
	responseBody, err := makeRequest(ctx, url, dcrdataTimeout)
	if err != nil {
		return "", 0, err
	}

	transactions := make([]BETransaction, 0)
	err = json.Unmarshal(responseBody, &transactions)
	if err != nil {
		return "", 0, err
	}

	for _, v := range transactions {
		if v.Timestamp < txnotbefore {
			continue
		}
		if v.Confirmations < minConfirmationsRequired {
			continue
		}

		for _, vout := range v.Vout {
			amount, err := dcrStringToAmount(vout.Amount.String())
			if err != nil {
				return "", 0, err
			}

			if amount < minimumAmount {
				continue
			}

			for _, addr := range vout.ScriptPubkey.Addresses {
				if address == addr {
					return v.TxId, amount, nil
				}
			}
		}
	}

	return "", 0, nil
}

// payWithTestnetFaucet makes a request to the testnet faucet.
func payWithTestnetFaucet(ctx context.Context, faucetURL string, address string, amount uint64, overridetoken string) (string, error) {
	_, err := dcrutil.DecodeAddress(address, chaincfg.TestNet3Params())
	if err != nil {
		return "", fmt.Errorf("address is invalid: %v", err)
	}

	dcramount := strconv.FormatFloat(dcrutil.Amount(amount).ToCoin(),
		'f', -1, 32)

	// build request
	form := url.Values{}
	form.Add("address", address)
	form.Add("amount", dcramount)
	form.Add("overridetoken", overridetoken)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, faucetURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.PostForm = form
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	// limit the time we take
	ctx, cancel := context.WithTimeout(ctx,
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

// fetchTxWithBlockExplorers uses public block explorers to look for a
// transaction for the given address that equals or exceeds the given amount,
// occurs after the txnotbefore time and has the minimum number of confirmations.
func fetchTxWithBlockExplorers(ctx context.Context, params *chaincfg.Params, address string, amount uint64, txnotbefore int64, minConfirmations uint64, dcrdataURL string) (string, uint64, error) {
	// pre-validate that the passed address, amount, and tx are at least
	// somewhat valid before querying the explorers
	addr, err := dcrutil.DecodeAddress(address, params)
	if err != nil {
		return "", 0, fmt.Errorf("invalid address %v: %v", addr, err)
	}

	// Construct proper dcrdata url
	dcrdataURL += "/address/" + address

	explorerURL := dcrdataURL + "/raw"

	// Fetch transaction from dcrdata
	txID, amount, err := fetchTxWithBE(ctx, explorerURL, address, amount,
		txnotbefore, minConfirmations)
	if err != nil {
		return "", 0, fmt.Errorf("failed to fetch from dcrdata: %v", err)
	}

	return txID, amount, nil
}

func fetchTxsWithBE(ctx context.Context, url string) ([]BETransaction, error) {
	responseBody, err := makeRequest(ctx, url, dcrdataTimeout)
	if err != nil {
		return nil, err
	}

	transactions := make([]BETransaction, 0)
	err = json.Unmarshal(responseBody, &transactions)
	if err != nil {
		return nil, fmt.Errorf("Unmarshal []BETransaction: %v", err)
	}

	return transactions, nil
}

func convertBETransactionToTxDetails(address string, tx BETransaction) (*TxDetails, error) {
	var amount uint64
	for _, vout := range tx.Vout {
		amt, err := dcrStringToAmount(vout.Amount.String())
		if err != nil {
			return nil, err
		}

		for _, addr := range vout.ScriptPubkey.Addresses {
			if address == addr {
				amount += amt
			}
		}
	}
	inputAddresses := make([]string, 0, 1064)
	for _, vin := range tx.Vin {
		inputAddresses = append(inputAddresses, vin.PrevOut.Addresses...)
	}

	return &TxDetails{
		Address:        address,
		TxID:           tx.TxId,
		Amount:         amount,
		Confirmations:  tx.Confirmations,
		Timestamp:      tx.Timestamp,
		InputAddresses: inputAddresses,
	}, nil
}

// fetchTxsForAddress fetches the transactions that have been sent to the
// provided wallet address from the dcrdata block explorer
func fetchTxsForAddress(ctx context.Context, params *chaincfg.Params, address string, dcrdataURL string) ([]TxDetails, error) {
	// Get block explorer URL
	addr, err := dcrutil.DecodeAddress(address, params)
	if err != nil {
		return nil, fmt.Errorf("invalid address %v: %v", addr, err)
	}

	// Construct proper dcrdata url
	dcrdataURL += "/address/" + address

	explorerURL := dcrdataURL + "/raw"

	// Fetch using dcrdata block explorer
	dcrdataTxs, err := fetchTxsWithBE(ctx, explorerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch from dcrdata: %v", err)
	}
	txs := make([]TxDetails, 0, len(dcrdataTxs))
	for _, tx := range dcrdataTxs {
		txDetail, err := convertBETransactionToTxDetails(address, tx)
		if err != nil {
			return nil, fmt.Errorf("convertBETransactionToTxDetails: %v",
				tx.TxId)
		}
		txs = append(txs, *txDetail)
	}
	return txs, nil
}

// fetchTxsForAddressNotBefore fetches all transactions for a wallet address
// that occurred after the passed in notBefore timestamp.
func fetchTxsForAddressNotBefore(ctx context.Context, params *chaincfg.Params, address string, notBefore int64, dcrdataURL string) ([]TxDetails, error) {
	// Get block explorer URL
	addr, err := dcrutil.DecodeAddress(address, params)
	if err != nil {
		return nil, fmt.Errorf("invalid address %v: %v", addr, err)
	}

	// Construct proper dcrdata url
	dcrdataURL += "/address/" + address

	// Fetch all txs for the passed in wallet address
	// that were sent after the notBefore timestamp
	var (
		targetTxs []TxDetails
		count     = 10
		skip      = 0
		done      = false
	)
	for !done {
		// Fetch a page of user payment txs
		url := dcrdataURL + "/count/" + strconv.Itoa(count) +
			"/skip/" + strconv.Itoa(skip) + "/raw"
		dcrdataTxs, err := fetchTxsWithBE(ctx, url)
		if err != nil {
			return nil, fmt.Errorf("fetchDcrdataAddress: %v", err)
		}
		// Convert transactions to TxDetails
		txs := make([]TxDetails, len(dcrdataTxs))
		for _, tx := range dcrdataTxs {
			txDetails, err := convertBETransactionToTxDetails(address, tx)
			if err != nil {
				return nil, fmt.Errorf("convertBETransactionToTxDetails: %v",
					tx.TxId)
			}
			txs = append(txs, *txDetails)
		}
		if len(txs) == 0 {
			done = true
			continue
		}
		// Sanity check. Txs should already be sorted
		// in reverse chronological order.
		sort.SliceStable(txs, func(i, j int) bool {
			return txs[i].Timestamp > txs[j].Timestamp
		})

		// Verify txs are within notBefore limit
		for _, tx := range txs {
			if tx.Timestamp > notBefore {
				targetTxs = append(targetTxs, tx)
			} else {
				// We have reached the notBefore
				// limit; stop requesting txs
				done = true
				break
			}
		}

		skip += count
	}

	return targetTxs, nil
}

// fetchTx fetches a given transaction based on the provided txid.
func fetchTx(ctx context.Context, params *chaincfg.Params, address, txid, dcrdataURL string) (*TxDetails, error) {
	// Get block explorer URLs
	addr, err := dcrutil.DecodeAddress(address, params)
	if err != nil {
		return nil, fmt.Errorf("invalid address %v: %v", addr, err)
	}

	// Construct proper dcrdata url}
	dcrdataURL += "/address/" + address

	primaryURL := dcrdataURL + "/raw"

	log.Debugf("fetching tx %s %s from primary %s\n", address, txid, primaryURL)
	// Try the primary (dcrdata)
	primaryTxs, err := fetchTxsWithBE(ctx, primaryURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch from dcrdata: %v", err)
	}
	for _, tx := range primaryTxs {
		if strings.TrimSpace(tx.TxId) != strings.TrimSpace(txid) {
			continue
		}
		txDetail, err := convertBETransactionToTxDetails(address, tx)
		if err != nil {
			return nil, fmt.Errorf("convertBETransactionToTxDetails: %v",
				tx.TxId)
		}
		return txDetail, nil
	}
	return nil, nil
}
