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
	"os"
	"path/filepath"

	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/politeia/mdstream"
	pd "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/cache"
	cachedb "github.com/decred/politeia/politeiad/cache/cockroachdb"
	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	cmsdb "github.com/decred/politeia/politeiawww/cmsdatabase/cockroachdb"
	"github.com/decred/politeia/politeiawww/sharedconfig"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/decred/politeia/util"
	"github.com/syndtr/goleveldb/leveldb"
)

const (
	defaultHost      = "localhost:26257"
	defaultCacheCert = "~/.cockroachdb/certs/clients/politeiawww/ca.crt"

	defaultRPCUser = "user"
	defaultRPCPass = "pass"
	defaultRPCHost = "127.0.0.1"
)

var (
	defaultHomeDir     = sharedconfig.DefaultHomeDir
	defaultDataDir     = sharedconfig.DefaultDataDir
	defaultRPCCertFile = filepath.Join(sharedconfig.DefaultHomeDir, "rpc.cert")

	// Application options
	testnet   = flag.Bool("testnet", false, "")
	dataDir   = flag.String("datadir", defaultDataDir, "")
	cacheHost = flag.String("cachehost", defaultHost, "")
	cacheCert = flag.String("cachecert", defaultCacheCert, "")
	dbHost    = flag.String("dbhost", defaultDBHost, "")
	dbCert    = flag.String("dbcert", defaultClientCert, "")
	dbKey     = flag.String("dbkey", defaultClientKey, "")

	rpcCert = flag.String("rpcert", defaultClientKey, "")
	rpcHost = flag.String("rpchost", defaultClientKey, "")
	rpcUser = flag.String("rpcuser", defaultClientKey, "")
	rpcPass = flag.String("rpcpass", defaultClientKey, "")

	network string // Mainnet or testnet3
	// XXX ldb should be abstracted away. dbutil commands should use
	// the user.Database interface instead.
	ldb    *leveldb.DB
	userDB user.Database
)

// makeRequest makes an http request to the method and route provided,
// serializing the provided object as the request body.
//
// XXX doesn't belong in this file but stuff it here for now.
func makeRequest(method string, route string, v interface{}) ([]byte, error) {
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

	fullRoute := *rpcHost + route

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
	if *testnet {
		network = chaincfg.TestNet3Params.Name
	} else {
		network = chaincfg.MainNetParams.Name
	}

	dBRootCert = cleanAndExpandPath(defaultDBRootCert)
	dBCert = cleanAndExpandPath(defaultDBCert)
	dBKey = cleanAndExpandPath(defaultDBKey)

	var err error
	dIdentity, err = identity.LoadPublicIdentity(rpcIdentityFile)
	if err != nil {
		return err
	}

	net := filepath.Base(dataDir)
	cacheDB, err := cachedb.New(cachedb.UserPoliteiawww, dBHost,
		net, dBRootCert, dBCert, dBKey)
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

	net = filepath.Base(loadedCfg.DataDir)
	cmsDB, err := cmsdb.New(loadedCfg.DBHost, net, loadedCfg.DBRootCert,
		loadedCfg.DBCert, loadedCfg.DBKey)
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
			fmt.Errorf("couldn't get invoice for payment check: %v, %v",
				payment.InvoiceToken, err)
			continue
		}
		found := false
		for _, v := range invoice.Metadata {
			if v.ID == mdstream.IDInvoicePayment {
				fmt.Printf("payment for invoice %v found!", payment.InvoiceToken)
				// Do we need to do any checks to make sure anything else
				// is needed?
				found = true
				break
			}
		}
		// If no associated payment metadata are found for the given
		// invoice, create the new metadata and add to the existing invoice.
		if !found {
			fmt.Printf("payment for invoice %v NOT found! creating metadata stream for invoice record", payment.InvoiceToken)
			// Create new backend invoice payment metadata
			c := mdstream.InvoicePayment{
				Version:        mdstream.VersionInvoicePayment,
				TxIDs:          payment.TxIDs,
				Timestamp:      payment.TimeLastUpdated,
				AmountReceived: payment.AmountReceived,
			}

			blob, err := mdstream.EncodeInvoicePayment(c)
			if err != nil {
				fmt.Errorf("cms payment check: "+
					"encodeBackendInvoicePayment %v %v",
					payment.InvoiceToken, err)
				continue
			}

			challenge, err := util.Random(pd.ChallengeSize)
			if err != nil {
				fmt.Errorf("cms payment check: random %v %v",
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
			responseBody, err := makeRequest(http.MethodPost,
				pd.UpdateVettedMetadataRoute, pdCommand)
			if err != nil {
				fmt.Errorf("cms payment check: makeRequest %v %v",
					payment.InvoiceToken, err)
				continue
			}

			var pdReply pd.UpdateVettedMetadataReply
			err = json.Unmarshal(responseBody, &pdReply)
			if err != nil {
				fmt.Errorf("cms payment check: unmarshall %v %v",
					payment.InvoiceToken, err)
				continue
			}
			// Verify the UpdateVettedMetadata challenge.
			err = util.VerifyChallenge(loadedCfg.Identity, challenge,
				pdReply.Response)
			if err != nil {
				fmt.Errorf("cms payment check: verifyChallenge %v %v",
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
	err := _main()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
