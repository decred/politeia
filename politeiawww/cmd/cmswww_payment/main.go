// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	_ "encoding/gob"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	pd "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/cache"
	cachedb "github.com/decred/politeia/politeiad/cache/cockroachdb"
	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	cmsdb "github.com/decred/politeia/politeiawww/cmsdatabase/cockroachdb"
	"github.com/decred/politeia/util"
)

var (
	// ErrSessionUUIDNotFound is emitted when a UUID value is not found
	// in a session and indicates that the user is not logged in.
	ErrSessionUUIDNotFound = errors.New("session UUID not found")
)

// userErrorStatus retrieves the human readable error message for an error
// status code. The status code can be from either the pi or cms api.
func userErrorStatus(e www.ErrorStatusT) string {
	s, ok := www.ErrorStatus[e]
	if ok {
		return s
	}
	s, ok = cms.ErrorStatus[e]
	if ok {
		return s
	}
	return ""
}

// makeRequest makes an http request to the method and route provided,
// serializing the provided object as the request body.
//
// XXX doesn't belong in this file but stuff it here for now.
func makeRequest(cfg *config, method string, route string, v interface{}) ([]byte, error) {
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

	fullRoute := cfg.RPCHost + route

	client, err := util.NewClient(false, cfg.RPCCert)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, fullRoute,
		bytes.NewReader(requestBody))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(cfg.RPCUser, cfg.RPCPass)
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
	// Load configuration and parse command line.  This function also
	// initializes logging and configures it accordingly.
	loadedCfg, _, err := loadConfig()
	if err != nil {
		return fmt.Errorf("Could not load configuration file: %v", err)
	}
	log.Infof("Home dir: %v", loadedCfg.HomeDir)

	// Setup cache connection
	cachedb.UseLogger(cockroachdbLog)
	net := filepath.Base(loadedCfg.DataDir)
	cacheDB, err := cachedb.New(cachedb.UserPoliteiawww, loadedCfg.DBHost,
		net, loadedCfg.DBRootCert, loadedCfg.DBCert, loadedCfg.DBKey)
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

	cmsdb.UseLogger(cockroachdbLog)
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
			log.Errorf("couldn't get invoice for payment check: %v, %v",
				payment.InvoiceToken, err)
			continue
		}
		found := false
		for _, v := range invoice.Metadata {
			if v.ID == mdStreamInvoicePayment {
				// Do we need to do any checks to make sure anything else
				// is needed?
				found = true
				break
			}
		}
		// If no associated payment metadata are found for the given
		// invoice, create the new metadata and add to the existing invoice.
		if !found {
			// Create new backend invoice payment metadata
			c := backendInvoicePayment{
				Version:        backendInvoicePaymentVersion,
				TxIDs:          payment.TxIDs,
				Timestamp:      payment.TimeLastUpdated,
				AmountReceived: payment.AmountReceived,
			}

			blob, err := encodeBackendInvoicePayment(c)
			if err != nil {
				log.Errorf("cms payment check: "+
					"encodeBackendInvoicePayment %v %v",
					payment.InvoiceToken, err)
				continue
			}

			challenge, err := util.Random(pd.ChallengeSize)
			if err != nil {
				log.Errorf("cms payment check: random %v %v",
					payment.InvoiceToken, err)
				continue
			}

			pdCommand := pd.UpdateVettedMetadata{
				Challenge: hex.EncodeToString(challenge),
				Token:     payment.InvoiceToken,
				MDAppend: []pd.MetadataStream{
					{
						ID:      mdStreamInvoicePayment,
						Payload: string(blob),
					},
				},
			}
			responseBody, err := makeRequest(loadedCfg, http.MethodPost,
				pd.UpdateVettedMetadataRoute, pdCommand)
			if err != nil {
				log.Errorf("cms payment check: makeRequest %v %v",
					payment.InvoiceToken, err)
				continue
			}

			var pdReply pd.UpdateVettedMetadataReply
			err = json.Unmarshal(responseBody, &pdReply)
			if err != nil {
				log.Errorf("cms payment check: unmarshall %v %v",
					payment.InvoiceToken, err)
				continue
			}
			// Verify the UpdateVettedMetadata challenge.
			err = util.VerifyChallenge(loadedCfg.Identity, challenge,
				pdReply.Response)
			if err != nil {
				log.Errorf("cms payment check: verifyChallenge %v %v",
					payment.InvoiceToken, err)
				continue
			}
		}
	}

	log.Infof("Exiting")

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
