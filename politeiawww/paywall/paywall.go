package paywall

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
// XXX this needs to have JSON directives.
type FaucetResponse struct {
	Txid  string
	Error string
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

var (
	// ErrCannotVerifyPayment is emitted when a transaction cannot be verified
	// because it cannot reach either of the block explorer servers.
	ErrCannotVerifyPayment = errors.New("cannot verify payment at this time")
)

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

	dcrsplit[1] = dcrsplit[1] + "00000000"
	fraction, err := strconv.ParseUint(dcrsplit[1][0:8], 10, 64)
	if err != nil {
		return 0, err
	}

	return ((whole * 1e8) + fraction), nil
}

func fetchTxWithPrimaryBE(url string, address string, minimumAmount uint64, txnotbefore int64, minConfirmationsRequired uint64) (string, uint64, error) {
	responseBody, err := makeRequest(url, 3)
	if err != nil {
		return "", 0, err
	}

	transactions := make([]BEPrimaryTransaction, 0)
	json.Unmarshal(responseBody, &transactions)

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
					return v.TxId, amount, nil
				}
			}
		}
	}

	return "", 0, nil
}

func fetchTxWithBackupBE(url string, address string, minimumAmount uint64, txnotbefore int64, minConfirmationsRequired uint64) (string, uint64, error) {
	responseBody, err := makeRequest(url, 3)
	if err != nil {
		return "", 0, err
	}

	transactions := make([]BEBackupTransaction, 0)
	json.Unmarshal(responseBody, &transactions)

	for _, v := range transactions {
		if v.Timestamp < txnotbefore {
			continue
		}
		if v.Confirmations < minConfirmationsRequired {
			continue
		}

		amount, err := DcrStringToAmount(v.Amount.String())
		if err != nil {
			return "", 0, err
		}
		if amount < minimumAmount {
			continue
		}

		return v.TxId, amount, nil
	}

	return "", 0, nil
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
	req = req.WithContext(ctx)

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

// DefaultExplorerURLSreturns the default block explorer URLs based on the
// provided address.
func DefaultExplorerURLS(address string) (string, string, error) {
	addr, err := dcrutil.DecodeAddress(address)
	if err != nil {
		return "", "", fmt.Errorf("invalid address %v: %v", address,
			err)
	}

	var (
		primaryURL string
		backupURL  string
	)

	params := addr.Net()
	network := getNetworkName(params)
	if params == &chaincfg.MainNetParams {
		primaryURL = "https://explorer.dcrdata.org/api/address/" +
			address + "/raw"
		backupURL = "https://mainnet.decred.org/api/addr/" +
			address + "/utxo?noCache=1"
	} else if params == &chaincfg.TestNet3Params {
		primaryURL = "https://testnet.dcrdata.org/api/address/" +
			address + "/raw"
		backupURL = "https://testnet.decred.org/api/addr/" +
			address + "/utxo?noCache=1"
	} else {
		return "", "", fmt.Errorf("unsupported network %v", network)
	}

	return primaryURL, backupURL, nil
}

// FetchTxWithBlockExplorers uses public block explorers if overrideURL is not
// set to look for a transaction for the given address that equals or exceeds
// the given amount, occurs after the txnotbefore time and has the minimum
// number of confirmations.
func FetchTxWithBlockExplorers(overrideURL, address string, amount uint64, txNotBefore int64, minConfirmations uint64) (string, uint64, error) {
	var urls []string
	if overrideURL == "" {
		primary, backup, err := DefaultExplorerURLS(address)
		if err != nil {
			return "", 0, err
		}
		urls = []string{primary, backup}
	} else {
		// verify address
		_, err := dcrutil.DecodeAddress(address)
		if err != nil {
			return "", 0, fmt.Errorf("invalid address %v: %v",
				address, err)
		}
		urls = []string{overrideURL}
	}

	// Try the primary (dcrdata) first.
	for _, v := range urls {
		txID, amount, err := fetchTxWithPrimaryBE(v, address, amount,
			txNotBefore, minConfirmations)
		if err != nil {
			log.Printf("failed to fetch from %v: %v", v, err)
			continue
		}
		return txID, amount, nil
	}

	return "", 0, ErrCannotVerifyPayment
}
