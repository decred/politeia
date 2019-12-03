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

	"github.com/decred/politeia/mdstream"
	pd "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/cache"
	cachedb "github.com/decred/politeia/politeiad/cache/cockroachdb"
	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	cmsdb "github.com/decred/politeia/politeiawww/cmsdatabase/cockroachdb"
	"github.com/decred/politeia/politeiawww/sharedconfig"
	"github.com/decred/politeia/util"
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

	rpcCert = flag.String("rpcert", defaultRPCCertFile, "")
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
	if *testnet {
		network = "testnet3"
		// Only set to testnet port if no rpc port flag set
		if rpcPort != pd.DefaultMainnetPort {
			rpcPort = pd.DefaultTestnetPort
		}
	} else {
		network = "mainnet"
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
		return err
	}
	rpcHost = u.String()

	dIdentity, err := identity.LoadPublicIdentity(*dIdentityFile)
	if err != nil {
		return err
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
		return err
	}
	err = cmsDB.Setup()
	if err != nil {
		return fmt.Errorf("cmsdb setup: %v", err)
	}

	paid, err := cmsDB.PaymentsByStatus(uint(cms.PaymentStatusPaid))
	if err != nil {
		return err
	}
	for _, payment := range paid {
		invoice, err := cacheDB.Record(payment.InvoiceToken)
		if err != nil {
			fmt.Printf("couldn't get invoice for payment check: %v, %v",
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
			fmt.Printf("payment for invoice %v NOT found! creating metadata stream for invoice record\n", payment.InvoiceToken)
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
					"encodeBackendInvoicePayment %v %v",
					payment.InvoiceToken, err)
				continue
			}

			challenge, err := util.Random(pd.ChallengeSize)
			if err != nil {
				fmt.Printf("cms payment check: random %v %v",
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
				fmt.Printf("cms payment check: makeRequest %v %v",
					payment.InvoiceToken, err)
				continue
			}

			var pdReply pd.UpdateVettedMetadataReply
			err = json.Unmarshal(responseBody, &pdReply)
			if err != nil {
				fmt.Printf("cms payment check: unmarshall %v %v",
					payment.InvoiceToken, err)
				continue
			}
			// Verify the UpdateVettedMetadata challenge.
			err = util.VerifyChallenge(dIdentity, challenge,
				pdReply.Response)
			if err != nil {
				fmt.Printf("cms payment check: verifyChallenge %v %v",
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
