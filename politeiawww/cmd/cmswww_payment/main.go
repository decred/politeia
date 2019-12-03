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
	"os/user"
	"path/filepath"
	"runtime"
	"strings"

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
	defaultHomeDir     = sharedconfig.DefaultHomeDir
	defaultDataDir     = sharedconfig.DefaultDataDir
	defaultRPCCertFile = filepath.Join(sharedconfig.DefaultHomeDir, "rpc.cert")

	// Application options
	testnet    = flag.Bool("testnet", true, "")
	dataDir    = flag.String("datadir", defaultDataDir, "")
	dbHost     = flag.String("dbhost", defaultDBHost, "")
	dbCert     = flag.String("dbcert", defaultDBCert, "")
	dbRootCert = flag.String("dbrootcert", defaultDBRootCert, "")
	dbKey      = flag.String("dbkey", defaultDBKey, "")

	rpcCert = flag.String("rpcert", defaultRPCCertFile, "")
	rpcHost = flag.String("rpchost", defaultRPCHost, "")
	rpcUser = flag.String("rpcuser", defaultRPCUser, "")
	rpcPass = flag.String("rpcpass", defaultRPCPass, "")

	dIdentityFile = flag.String("identityfile", defaultIdentityFilename, "")

	network string // Mainnet or testnet3
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
		activeNetParams = &testNet3Params
	}
	dataDir := cleanAndExpandPath(*dataDir)
	dataDir = filepath.Join(dataDir, netName(activeNetParams))

	dbRootCert := cleanAndExpandPath(*dbRootCert)
	dbCert := cleanAndExpandPath(*dbCert)
	dbKey := cleanAndExpandPath(*dbKey)

	var err error
	dIdentity, err := identity.LoadPublicIdentity(filepath.Join(defaultHomeDir, *dIdentityFile))
	if err != nil {
		return err
	}
	fmt.Println(dataDir)
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
			fmt.Errorf("couldn't get invoice for payment check: %v, %v",
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
			err = util.VerifyChallenge(dIdentity, challenge,
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

// cleanAndExpandPath expands environment variables and leading ~ in the
// passed path, cleans the result, and returns it.
func cleanAndExpandPath(path string) string {
	// Nothing to do when no path is given.
	if path == "" {
		return path
	}

	// NOTE: The os.ExpandEnv doesn't work with Windows cmd.exe-style
	// %VARIABLE%, but the variables can still be expanded via POSIX-style
	// $VARIABLE.
	path = os.ExpandEnv(path)

	if !strings.HasPrefix(path, "~") {
		return filepath.Clean(path)
	}

	// Expand initial ~ to the current user's home directory, or ~otheruser
	// to otheruser's home directory.  On Windows, both forward and backward
	// slashes can be used.
	path = path[1:]

	var pathSeparators string
	if runtime.GOOS == "windows" {
		pathSeparators = string(os.PathSeparator) + "/"
	} else {
		pathSeparators = string(os.PathSeparator)
	}

	userName := ""
	if i := strings.IndexAny(path, pathSeparators); i != -1 {
		userName = path[:i]
		path = path[i:]
	}

	homeDir := ""
	var u *user.User
	var err error
	if userName == "" {
		u, err = user.Current()
	} else {
		u, err = user.Lookup(userName)
	}
	if err == nil {
		homeDir = u.HomeDir
	}
	// Fallback to CWD if user lookup fails or user has no home directory.
	if homeDir == "" {
		homeDir = "."
	}

	return filepath.Join(homeDir, path)
}
