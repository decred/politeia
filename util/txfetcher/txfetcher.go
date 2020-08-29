// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package txfetcher

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/decred/dcrd/dcrutil"
)

const (
	dcrdataTimeout = 3 * time.Second // Dcrdata request timeout
)

//TxFetcher defines an interfaces for fetching transactions from the blockchain.
type TxFetcher interface {
	FetchTxWithBlockExplorers(string, uint64, int64, uint64) (string, uint64, error)
	FetchTxsForAddress(string) ([]TxDetails, error)
	FetchTxsForAddressNotBefore(string, int64) ([]TxDetails, error)
	FetchTx(string, string) (*TxDetails, error)
}

// DcrdataTxFetcher implements the TxFetcher interface.
type DcrdataTxFetcher struct {
	url string
}

// BETransaction is an object representing a transaction; it's
// part of the data returned from the URL for the block explorer
// when fetching the transactions for an address.
type BETransaction struct {
	TxID          string              `json:"TxID"`          // Transaction id
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

func makeRequest(url string, timeout time.Duration) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
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

// DcrStringToAmount converts a DCR amount as a string into a uint64
// representing atoms. Supported input variations: "1", ".1", "0.1"
func DcrStringToAmount(dcrstr string) (uint64, error) {
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

func fetchTxWithBE(url string, address string, minimumAmount uint64, txnotbefore int64, minConfirmationsRequired uint64) (string, uint64, error) {
	responseBody, err := makeRequest(url, dcrdataTimeout)
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
			amount, err := DcrStringToAmount(vout.Amount.String())
			if err != nil {
				return "", 0, err
			}

			if amount < minimumAmount {
				continue
			}

			for _, addr := range vout.ScriptPubkey.Addresses {
				if address == addr {
					return v.TxID, amount, nil
				}
			}
		}
	}

	return "", 0, nil
}

// FetchTxWithBlockExplorers uses public block explorers to look for a
// transaction for the given address that equals or exceeds the given amount,
// occurs after the txnotbefore time and has the minimum number of confirmations.
func (d *DcrdataTxFetcher) FetchTxWithBlockExplorers(address string, amount uint64, txnotbefore int64, minConfirmations uint64) (string, uint64, error) {
	// pre-validate that the passed address, amount, and tx are at least
	// somewhat valid before querying the explorers
	addr, err := dcrutil.DecodeAddress(address)
	if err != nil {
		return "", 0, fmt.Errorf("invalid address %v: %v", addr, err)
	}

	// Construct proper dcrdata url
	dcrdataURL := d.url + "/address/" + address

	explorerURL := dcrdataURL + "/raw"

	// Fetch transaction from dcrdata
	TxID, amount, err := fetchTxWithBE(explorerURL, address, amount,
		txnotbefore, minConfirmations)
	if err != nil {
		return "", 0, fmt.Errorf("failed to fetch from dcrdata: %v", err)
	}

	return TxID, amount, nil
}

func fetchTxsWithBE(url string) ([]BETransaction, error) {
	responseBody, err := makeRequest(url, dcrdataTimeout)
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
		amt, err := DcrStringToAmount(vout.Amount.String())
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
		TxID:           tx.TxID,
		Amount:         amount,
		Confirmations:  tx.Confirmations,
		Timestamp:      tx.Timestamp,
		InputAddresses: inputAddresses,
	}, nil
}

// FetchTxsForAddress fetches the transactions that have been sent to the
// provided wallet address from the dcrdata block explorer
func (d *DcrdataTxFetcher) FetchTxsForAddress(address string) ([]TxDetails, error) {
	// Get block explorer URL
	addr, err := dcrutil.DecodeAddress(address)
	if err != nil {
		return nil, fmt.Errorf("invalid address %v: %v", addr, err)
	}

	// Construct proper dcrdata url
	dcrdataURL := d.url + "/address/" + address

	explorerURL := dcrdataURL + "/raw"

	// Fetch using dcrdata block explorer
	dcrdataTxs, err := fetchTxsWithBE(explorerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch from dcrdata: %v", err)
	}
	txs := make([]TxDetails, 0, len(dcrdataTxs))
	for _, tx := range dcrdataTxs {
		txDetail, err := convertBETransactionToTxDetails(address, tx)
		if err != nil {
			return nil, fmt.Errorf("convertBETransactionToTxDetails: %v",
				tx.TxID)
		}
		txs = append(txs, *txDetail)
	}
	return txs, nil
}

// FetchTxsForAddressNotBefore fetches all transactions for a wallet address
// that occurred after the passed in notBefore timestamp.
func (d *DcrdataTxFetcher) FetchTxsForAddressNotBefore(address string, notBefore int64) ([]TxDetails, error) {
	// Get block explorer URL
	addr, err := dcrutil.DecodeAddress(address)
	if err != nil {
		return nil, fmt.Errorf("invalid address %v: %v", addr, err)
	}

	// Construct proper dcrdata url
	dcrdataURL := d.url + "/address/" + address

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
		dcrdataTxs, err := fetchTxsWithBE(url)
		if err != nil {
			return nil, fmt.Errorf("fetchDcrdataAddress: %v", err)
		}
		// Convert transactions to TxDetails
		txs := make([]TxDetails, len(dcrdataTxs))
		for _, tx := range dcrdataTxs {
			txDetails, err := convertBETransactionToTxDetails(address, tx)
			if err != nil {
				return nil, fmt.Errorf("convertBETransactionToTxDetails: %v",
					tx.TxID)
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

// FetchTx fetches a given transaction based on the provided TxID.
func (d *DcrdataTxFetcher) FetchTx(address, TxID string) (*TxDetails, error) {
	// Get block explorer URLs
	addr, err := dcrutil.DecodeAddress(address)
	if err != nil {
		return nil, fmt.Errorf("invalid address %v: %v", addr, err)
	}

	// Construct proper dcrdata url}
	dcrdataURL := d.url + "/address/" + address

	primaryURL := dcrdataURL + "/raw"

	log.Printf("fetching tx %s %s from primary %s\n", address, TxID, primaryURL)
	// Try the primary (dcrdata)
	primaryTxs, err := fetchTxsWithBE(primaryURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch from dcrdata: %v", err)
	}
	for _, tx := range primaryTxs {
		if strings.TrimSpace(tx.TxID) != strings.TrimSpace(TxID) {
			continue
		}
		txDetail, err := convertBETransactionToTxDetails(address, tx)
		if err != nil {
			return nil, fmt.Errorf("convertBETransactionToTxDetails: %v",
				tx.TxID)
		}
		return txDetail, nil
	}
	return nil, nil
}

// New returns a new DcrdataTxFetcher struct.
func New(url string) *DcrdataTxFetcher {
	return &DcrdataTxFetcher{
		url: url,
	}
}
