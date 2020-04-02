// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	_ "encoding/gob"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/thi4go/politeia/mdstream"
	pd "github.com/thi4go/politeia/politeiad/api/v1"
	"github.com/thi4go/politeia/politeiad/api/v1/identity"
	"github.com/thi4go/politeia/politeiad/cache"
	cachedb "github.com/thi4go/politeia/politeiad/cache/cockroachdb"
	cms "github.com/thi4go/politeia/politeiawww/api/cms/v1"
	www "github.com/thi4go/politeia/politeiawww/api/www/v1"
	database "github.com/thi4go/politeia/politeiawww/cmsdatabase"
	cmsdb "github.com/thi4go/politeia/politeiawww/cmsdatabase/cockroachdb"
	"github.com/thi4go/politeia/politeiawww/sharedconfig"
	"github.com/thi4go/politeia/util"
)

const (
	defaultDBHost     = "localhost:26257"
	defaultDBRootCert = "~/.cockroachdb/certs/clients/politeiawww/ca.crt"
	defaultDBCert     = "~/.cockroachdb/certs/clients/politeiawww/client.politeiawww.crt"
	defaultDBKey      = "~/.cockroachdb/certs/clients/politeiawww/client.politeiawww.key"

	defaultIdentityFilename = "identity.json"

	defaultRPCUser = "user"
	defaultRPCPass = "pass"
	defaultRPCHost = "127.0.0.1"

	dcrdataMainnet = "https://dcrdata.decred.org/api"
	dcrdataTestnet = "https://testnet.decred.org/api"
)

var (
	defaultHomeDir      = sharedconfig.DefaultHomeDir
	defaultDataDir      = sharedconfig.DefaultDataDir
	defaultRPCCertFile  = filepath.Join(sharedconfig.DefaultHomeDir, "rpc.cert")
	defaultIdentityFile = filepath.Join(sharedconfig.DefaultHomeDir, defaultIdentityFilename)

	// Application options
	testnet    = flag.Bool("testnet", false, "")
	dataDir    = flag.String("datadir", defaultDataDir, "")
	dbHost     = flag.String("dbhost", defaultDBHost, "")
	dbCert     = flag.String("dbcert", defaultDBCert, "")
	dbRootCert = flag.String("dbrootcert", defaultDBRootCert, "")
	dbKey      = flag.String("dbkey", defaultDBKey, "")

	rpcCert = flag.String("rpccert", defaultRPCCertFile, "")
	rpcHost = flag.String("rpchost", defaultRPCHost, "")
	rpcUser = flag.String("rpcuser", defaultRPCUser, "")
	rpcPass = flag.String("rpcpass", defaultRPCPass, "")
	rpcPort = flag.String("rpcport", pd.DefaultMainnetPort, "")

	dIdentityFile = flag.String("identityfile", defaultIdentityFile, "")

	network string // Mainnet or testnet3
)

const usageMsg = `cmswww_payment usage:

  Application options
    -testnet
          Use testnet database
    -datadir string
          politeiawww data directory
            (default osDataDir/politeiawww/data)
    -dbhost string
          CockroachDB ip:port 
           (default localhost:26257)
    -dbrootcert string
          File containing the CockroachDB SSL root cert
          (default ~/.cockroachdb/certs/clients/politeiawww/ca.crt)
    -dbcert string
          File containing the CockroachDB SSL client cert
          (default ~/.cockroachdb/certs/clients/politeiawww/client.politeiawww.crt)
    -dbkey string
          File containing the CockroachDB SSL client cert key
          (default ~/.cockroachdb/certs/clients/politeiawww/client.politeiawww.key)
   -rpccert string
          File containing the RPC cert to communicate with politeiad
          (default ~/.politeiawww/rpc.cert)
   -rpcuser string
          RPC user name for privileged commands
          (default user)
   -rpcpass string
          RPC password for privileged commands
          (default pass)
   -rpchost string
          RPC Host for politeiad
          (default 127.0.0.1)
   -rpcport string
          RPC Port for politeiad
          (default 49374 / 59374)
   -identityfile
          Path to file containing the politeiad identity
          (default ~/.politeiawww/identity.json)
`

// makeRequest makes an http request to the method and route provided,
// serializing the provided object as the request body.
//
// XXX doesn't belong in this file but stuff it here for now.
func makeRequest(rpcHost string, method string, route string, v interface{}) ([]byte, error) {
	var (
		requestBody []byte
		err         error
	)
	if v != nil {
		requestBody, err = json.Marshal(v)
		if err != nil {
			return nil, err
		}
	}

	fullRoute := rpcHost + route

	client, err := util.NewClient(false, *rpcCert)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, fullRoute,
		bytes.NewReader(requestBody))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(*rpcUser, *rpcPass)
	r, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		var pdErrorReply www.PDErrorReply
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&pdErrorReply); err != nil {
			return nil, err
		}

		return nil, www.PDError{
			HTTPCode:   r.StatusCode,
			ErrorReply: pdErrorReply,
		}
	}

	responseBody := util.ConvertBodyToByteArray(r.Body, false)
	return responseBody, nil
}

func _main() error {
	flag.Parse()

	var err error
	var network string
	var rpcPort string
	var dcrdataHost string
	if *testnet {
		network = "testnet3"
		// Only set to testnet port if no rpc port flag set
		if rpcPort != pd.DefaultMainnetPort {
			rpcPort = pd.DefaultTestnetPort
		}
		dcrdataHost = dcrdataTestnet
	} else {
		network = "mainnet"
		dcrdataHost = dcrdataMainnet
	}

	dataDir := util.CleanAndExpandPath(*dataDir)
	dataDir = filepath.Join(dataDir, network)

	dbRootCert := util.CleanAndExpandPath(*dbRootCert)
	dbCert := util.CleanAndExpandPath(*dbCert)
	dbKey := util.CleanAndExpandPath(*dbKey)

	// Normalize rpc host:port
	rpcHost := util.NormalizeAddress(*rpcHost, rpcPort)
	u, err := url.Parse("https://" + rpcHost)
	if err != nil {
		return fmt.Errorf("url parse: %v", err)
	}
	rpcHost = u.String()

	dIdentity, err := identity.LoadPublicIdentity(*dIdentityFile)
	if err != nil {
		return fmt.Errorf("load public identity: %v", err)
	}

	net := filepath.Base(dataDir)
	cacheDB, err := cachedb.New(cachedb.UserPoliteiawww, *dbHost,
		net, dbRootCert, dbCert, dbKey)
	if err != nil {
		switch err {
		case cache.ErrNoVersionRecord:
			err = fmt.Errorf("cache version record not found; " +
				"start politeiad to setup the cache")
		case cache.ErrWrongVersion:
			err = fmt.Errorf("wrong cache version found; " +
				"restart politeiad to rebuild the cache")
		}
		return fmt.Errorf("cachedb new: %v", err)
	}

	net = filepath.Base(dataDir)
	cmsDB, err := cmsdb.New(*dbHost, net, dbRootCert, dbCert, dbKey)
	if err != nil {
		if err != database.ErrNoVersionRecord && err != database.ErrWrongVersion {
			return fmt.Errorf("cmsdb new: %v", err)
		}
	}

	paid, err := cmsDB.PaymentsByStatus(uint(cms.PaymentStatusPaid))
	if err != nil {
		return fmt.Errorf("payments by status: %v", err)
	}
	for _, payment := range paid {
		invoice, err := cacheDB.Record(payment.InvoiceToken)
		if err != nil {
			fmt.Printf("couldn't get invoice for payment check: %v, %v\n",
				payment.InvoiceToken, err)
			continue
		}
		found := false
		for _, v := range invoice.Metadata {
			if v.ID == mdstream.IDInvoicePayment {
				fmt.Printf("payment for invoice %v found!\n", payment.InvoiceToken)
				// Do we need to do any checks to make sure anything else
				// is needed?
				found = true
				break
			}
		}
		// If no associated payment metadata are found for the given
		// invoice, create the new metadata and add to the existing invoice.
		if !found {
			fmt.Printf("payment for invoice %v NOT found! creating metadata "+
				"stream for invoice record\n", payment.InvoiceToken)

			// Check the existing txids that have been saved in the db for
			// correctness due to a found issue with the address watcher
			// adding too many txids to the db for a given payment.
			txs := strings.Split(payment.TxIDs, ",")
			// If only 1 txids, nothing to check.
			validTxIds := ""
			if len(txs) > 1 {
				paymentReceived := uint64(0)
				for i, txid := range txs {
					tx, err := util.FetchTx(payment.Address, txid, dcrdataHost)
					if err != nil {
						fmt.Printf("error fetching txid %v %v\n", txid, err)
						break
					}
					if tx == nil {
						fmt.Printf("cannot find tx %v\n", txid)
						break
					}

					// Check to make sure that the tx was after payment
					// watching started.
					if payment.TimeStarted > tx.Timestamp {
						//continue
					}
					paymentReceived += tx.Amount
					if validTxIds == "" {
						validTxIds = txid
					} else {
						validTxIds += "," + txid
					}
					// Check to see if the additional tx fulfills the
					// amount needed and if the current txid is less than the
					// end of the list of txids, it needs to be updated.
					//
					// Update the payment db and then it will be added in the
					// metadata properly
					if int64(paymentReceived) >= payment.AmountNeeded &&
						i < len(txs) {
						payment.TxIDs = validTxIds
						err = cmsDB.UpdatePayments(&payment)
						if err != nil {
							fmt.Printf("Error updating payments information "+
								"for: %v %v\n",
								payment.Address, err)
						}
						break
					}
				}
			}
			// Create new backend invoice payment metadata
			c := mdstream.InvoicePayment{
				Version:        mdstream.VersionInvoicePayment,
				TxIDs:          payment.TxIDs,
				Timestamp:      payment.TimeLastUpdated,
				AmountReceived: payment.AmountReceived,
			}

			blob, err := mdstream.EncodeInvoicePayment(c)
			if err != nil {
				fmt.Printf("cms payment check: "+
					"encodeBackendInvoicePayment %v %v\n",
					payment.InvoiceToken, err)
				continue
			}

			challenge, err := util.Random(pd.ChallengeSize)
			if err != nil {
				fmt.Printf("cms payment check: random %v %v\n",
					payment.InvoiceToken, err)
				continue
			}

			pdCommand := pd.UpdateVettedMetadata{
				Challenge: hex.EncodeToString(challenge),
				Token:     payment.InvoiceToken,
				MDAppend: []pd.MetadataStream{
					{
						ID:      mdstream.IDInvoicePayment,
						Payload: string(blob),
					},
				},
			}
			responseBody, err := makeRequest(rpcHost, http.MethodPost,
				pd.UpdateVettedMetadataRoute, pdCommand)
			if err != nil {
				fmt.Printf("cms payment check: makeRequest %v %v\n",
					payment.InvoiceToken, err)
				continue
			}

			var pdReply pd.UpdateVettedMetadataReply
			err = json.Unmarshal(responseBody, &pdReply)
			if err != nil {
				fmt.Printf("cms payment check: unmarshall %v %v\n",
					payment.InvoiceToken, err)
				continue
			}
			// Verify the UpdateVettedMetadata challenge.
			err = util.VerifyChallenge(dIdentity, challenge,
				pdReply.Response)
			if err != nil {
				fmt.Printf("cms payment check: verifyChallenge %v %v\n",
					payment.InvoiceToken, err)
				continue
			}
		}
	}

	// Close user db connection
	cmsDB.Close()

	return nil
}

func main() {
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, usageMsg)
	}

	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
