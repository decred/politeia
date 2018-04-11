package util

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/dcrd/dcrutil"
	"github.com/decred/dcrd/hdkeychain"
	"github.com/decred/dcrwallet/wallet/udb"
)

// FaucetResponse represents the expected JSON response from the testnet faucet.
type FaucetResponse struct {
	Txid  string
	Error string
}

// PaywallGatewayNewOrderResponse respresents the expected JSON response to a
// PaywallGatewayNewOrder command.
type PaywallGatewayNewOrderResponse struct {
	Error         string
	OrderID       string
	PaywallAmount int64
}

// BEPrimaryTransaction is an object representing a transaction; it's
// part of the data returned from the URL for the primary block explorer
// when fetching the transactions for an address.
type BEPrimaryTransaction struct {
	TxId          string                     `json:"txid"`          // Transaction id
	Vout          []BEPrimaryTransactionVout `json:"vout"`          // Transaction outputs
	Confirmations uint64                     `json:"confirmations"` // Number of confirmations
	Timestamp     int64                      `json:"time"`          // Transaction timestamp
}

// BEPrimaryTransactionVout holds the transaction amount information.
type BEPrimaryTransactionVout struct {
	Amount       json.Number                      `json:"value"`        // Transaction amount (in DCR)
	ScriptPubkey BEPrimaryTransactionScriptPubkey `json:"scriptPubkey"` // Transaction script info
}

// BEPrimaryTransactionScriptPubkey holds the script info for a
// transaction.
type BEPrimaryTransactionScriptPubkey struct {
	Addresses []string `json:"addresses"` // Array of transaction input addresses
}

// BEBackupTransaction is an object representing a transaction; it's
// part of the data returned from the URL for the backup block explorer
// when fetching the transactions for an address.
type BEBackupTransaction struct {
	Address       string      `json:"address"`       // Transaction address
	TxId          string      `json:"txid"`          // Transaction id
	Amount        json.Number `json:"amount"`        // Transaction amount (in DCR)
	Confirmations uint64      `json:"confirmations"` // Number of confirmations
	Timestamp     int64       `json:"ts"`            // Transaction timestamp
}

const (
	minConfirmationsRequired = 2
)

func makeRequest(url string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to create request: %v", err)
	}

	// Limit the time we take.
	ctx, cancel := context.WithTimeout(context.Background(),
		2500*time.Millisecond)
	defer cancel()
	req.WithContext(ctx)

	client := &http.Client{}
	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	return ioutil.ReadAll(response.Body)
}

// dcrStringToAmount converts a DCR amount as a string into a uint64
// representing atoms. Supported input variations: "1", ".1", "0.1"
func dcrStringToAmount(dcrstr string) (dcrutil.Amount, error) {
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

	dcrsplit[1] = dcrsplit[1] + "00000000"
	fraction, err := strconv.ParseUint(dcrsplit[1][0:7], 10, 64)
	if err != nil {
		return 0, err
	}

	return dcrutil.Amount((whole * 1e8) + fraction), nil
}

func verifyTxWithPrimaryBE(url string, address string, txid string, minimumAmount dcrutil.Amount, txnotbefore int64) (bool, error) {
	responseBody, err := makeRequest(url)
	if err != nil {
		return false, err
	}

	transactions := make([]BEPrimaryTransaction, 0)
	json.Unmarshal(responseBody, &transactions)

	for _, v := range transactions {
		if v.TxId != txid {
			continue
		}
		if v.Timestamp < txnotbefore {
			continue
		}
		if v.Confirmations < minConfirmationsRequired {
			continue
		}

		for _, vout := range v.Vout {
			amount, err := dcrStringToAmount(vout.Amount.String())
			if err != nil {
				return false, err
			}

			if amount < minimumAmount {
				continue
			}

			for _, addr := range vout.ScriptPubkey.Addresses {
				if address == addr {
					return true, nil
				}
			}
		}
	}

	return false, nil
}

func verifyTxWithBackupBE(url string, address string, txid string, minimumAmount dcrutil.Amount, txnotbefore int64) (bool, error) {
	responseBody, err := makeRequest(url)
	if err != nil {
		return false, err
	}

	transactions := make([]BEBackupTransaction, 0)
	json.Unmarshal(responseBody, &transactions)

	for _, v := range transactions {
		if v.TxId != txid {
			continue
		}
		if v.Timestamp < txnotbefore {
			continue
		}
		if v.Confirmations < minConfirmationsRequired {
			continue
		}

		amount, err := dcrStringToAmount(v.Amount.String())
		if err != nil {
			return false, err
		}
		if amount < minimumAmount {
			continue
		}

		return true, nil
	}

	return false, nil
}

func getNetworkName(params *chaincfg.Params) string {
	if strings.HasPrefix(params.Name, "testnet") {
		return "testnet"
	}
	return params.Name
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
	branchKey, err := acctKey.Child(udb.ExternalBranch)
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
func PayWithTestnetFaucet(faucetURL string, address string, amount dcrutil.Amount, overridetoken string) (string, error) {
	dcraddress, err := dcrutil.DecodeAddress(address)
	if err != nil {
		return "", fmt.Errorf("address is invalid: %v", err)
	}

	if !dcraddress.IsForNet(&chaincfg.TestNet2Params) {
		return "", fmt.Errorf("faucet only supports testnet")
	}

	dcramount := strconv.FormatFloat(dcrutil.Amount(amount).ToCoin(),
		'f', -1, 32)
	if err != nil {
		return "", fmt.Errorf("unable to process amount: %v", err)
	}

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
		2500*time.Millisecond)
	// it is good practice to use the cancellation function even with a timeout
	defer cancel()
	req.WithContext(ctx)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
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

// VerifyTxWithBlockExplorers verifies that the passed transaction id is a valid
// transaction that can be confirmed on a public block explorer.
func VerifyTxWithBlockExplorers(address string, amount dcrutil.Amount, txid string, txnotbefore int64) (confirmed bool, err error) {
	// pre-validate that the passed address, amount, and tx are at least
	// somewhat valid before querying the explorers
	addr, err := dcrutil.DecodeAddress(address)
	if err != nil {
		return false, fmt.Errorf("invalid address %v: %v", addr, err)
	}

	var (
		primaryURL string
		backupURL  string
	)

	params := addr.Net()
	network := getNetworkName(params)
	if params == &chaincfg.MainNetParams {
		primaryURL = "https://explorer.dcrdata.org/api/address/" + address + "/raw"
		backupURL = "https://mainnet.decred.org/api/addr/" + address + "/utxo?noCache=1"
	} else if params == &chaincfg.TestNet2Params {
		primaryURL = "https://testnet.dcrdata.org/api/address/" + address + "/raw"
		backupURL = "https://testnet.decred.org/api/addr/" + address + "/utxo?noCache=1"
	} else {
		return false, fmt.Errorf("unsupported network %v", network)
	}

	// Try the primary (dcrdata) first.
	verified, err := verifyTxWithPrimaryBE(primaryURL, address, txid, amount, txnotbefore)
	if err != nil {
		log.Printf("failed to fetch from dcrdata: %v", err)
	} else {
		return verified, nil
	}

	// Try the backup (insight).
	return verifyTxWithBackupBE(backupURL, address, txid, amount, txnotbefore)
}
