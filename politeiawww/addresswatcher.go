// Copyright (c) 2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/decred/dcrd/dcrutil"
	client "github.com/decred/dcrdata/pubsub/psclient"
	pstypes "github.com/decred/dcrdata/pubsub/types"
	"github.com/decred/dcrdata/semver"
	pd "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/cache"
	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	database "github.com/decred/politeia/politeiawww/cmsdatabase"
	"github.com/decred/politeia/util"
)

const mainnetSubsidyAddr = "Dcur2mcGjmENx4DhNqDctW5wJCVyT3Qeqkx"

func (p *politeiawww) addWatchAddress(address string) error {
	address = "address:" + address
	if subd, _ := strInSlice(p.currentSubs, address); subd {
		log.Infof("Already subscribed to %s.", address)
		return nil
	}
	p.currentSubs = append(p.currentSubs, address)
	_, err := p.wsClient.Subscribe(address)
	if err != nil {
		return fmt.Errorf("failed to subscribe: %v", err)
	}
	log.Infof("Subscribed to listen: %v", address)
	return nil
}

func (p *politeiawww) removeWatchAddress(address string) error {
	address = "address:" + address
	subd, i := strInSlice(p.currentSubs, address)
	if !subd {
		log.Infof("Not subscribed to %s.", address)
		return nil
	}
	p.currentSubs = append(p.currentSubs[:i], p.currentSubs[i+1:]...)
	_, err := p.wsClient.Unsubscribe(address)
	if err != nil {
		return fmt.Errorf("failed to unsubscribe: %v", err)
	}
	log.Infof("Unsubscribed: %v", address)
	return nil
}

func (p *politeiawww) addPing() error {
	_, err := p.wsClient.Subscribe("ping")
	if err != nil {
		return fmt.Errorf("failed to subscribe: %v", err)
	}
	log.Infof("Subscribed to ping")
	return nil
}

func (p *politeiawww) setupWatcher() error {
	// Create the websocket connection.
	wsURL, err := util.BlockExplorerURLForSubscriptions(activeNetParams.Params)
	if err != nil {
		return err
	}
	log.Infof("Connecting to ws at: %v", wsURL)

	opts := client.Opts{
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	}
	p.wsClient, err = client.New(wsURL, context.Background(), &opts)
	if err != nil {
		log.Errorf("failed to connect to %s: %v", wsURL, err)
		return err
	}
	serverVer, err := p.wsClient.ServerVersion()
	if err != nil {
		log.Errorf("failed to get server version: %v", err)
		return err
	}

	clientSemVer := client.Version()
	log.Infof("PubSub Server version: %s, Client version %v", serverVer, clientSemVer)
	serverSemVer := semver.NewSemver(serverVer.Major, serverVer.Minor, serverVer.Patch)
	if !semver.Compatible(clientSemVer, serverSemVer) {
		return fmt.Errorf("pubsub server version is %v, but client is version %v",
			serverSemVer, clientSemVer)
	}

	go func() {
		for {
			msg, ok := <-p.wsClient.Receive()
			if !ok {
				break
			}
			if msg == nil {
				log.Errorf("ReceiveMsg failed")
				continue
			}

			switch m := msg.Message.(type) {
			case string:
				log.Debugf("Message (%s): %s", msg.EventId, m)
			case int:
				log.Debugf("Message (%s): %v", msg.EventId, m)
			case *pstypes.AddressMessage:
				log.Debugf("Message (%s): AddressMessage(address=%s, txHash=%s)",
					msg.EventId, m.Address, m.TxHash)

				// Check payment history for address
				payment, err := p.cmsDB.PaymentsByAddress(m.Address)
				if err != nil {
					log.Errorf("error retreiving payments information from db %v", err)
				}
				paid := p.checkPayments(payment)
				if paid {
					p.removeWatchAddress(payment.Address)
				}
			case *pstypes.TxList:
				log.Debugf("Message (%s): TxList(len=%d)", msg.EventId, len(*m))
			default:
				log.Debugf("Message of type %v unhandled. %v", msg.EventId, m)
			}
		}
	}()
	return nil
}

func (p *politeiawww) restartAddressesWatching() error {
	approvedInvoices, err := p.cmsDB.InvoicesByStatus(int(cms.InvoiceStatusApproved))
	if err != nil {
		return err
	}
	for _, invoice := range approvedInvoices {
		_, err := p.cmsDB.PaymentsByAddress(invoice.PaymentAddress)
		if err != nil {
			if err == database.ErrInvoiceNotFound {
				payout, err := p.calculatePayout(invoice)
				if err != nil {
					return err
				}
				// Start listening the first day of the next month of invoice.
				listenStartDate := time.Date(int(invoice.Year),
					time.Month(invoice.Month+1), 0, 0, 0, 0, 0, time.UTC)
				invoice.Payments = database.Payments{
					Address:      invoice.PaymentAddress,
					TimeStarted:  listenStartDate.Unix(),
					Status:       cms.PaymentStatusWatching,
					AmountNeeded: int64(payout.DCRTotal),
				}
				fmt.Println(listenStartDate)
				err = p.cmsDB.UpdateInvoice(&invoice)
				if err != nil {
					return err
				}
			}
		}
	}
	unpaidPayments, err := p.cmsDB.PaymentsByStatus(uint(cms.PaymentStatusWatching))
	if err != nil {
		return err
	}
	for _, payments := range unpaidPayments {
		paid := p.checkPayments(&payments)
		if !paid {
			p.addWatchAddress(payments.Address)
		}
	}
	return nil
}

func strInSlice(sl []string, str string) (bool, int) {
	for i, s := range sl {
		if s == str {
			return true, i
		}
	}
	return false, -1
}

// checkPayments checks to see if a given payment has been successfully paid.
// It will return TRUE if paid, otherwise false.  It utilizes the util
// FetchTxsForAddressNotBefore which looks for transaction at a given address
// after a certain time (in Unix seconds).
func (p *politeiawww) checkPayments(payment *database.Payments) bool {
	// Get all txs since start time of watcher
	txs, err := util.FetchTxsForAddressNotBefore(payment.Address,
		payment.TimeStarted)
	if err != nil {
		// XXX Some sort of 'recheck' or notice that it should do it again?
		log.Errorf("error FetchTxsForAddressNotBefore for %s", payment.Address)
	}
	if len(txs) == len(payment.TxIDs) {
		// Same number of txids found, so nothing to update.
		return false
	}

	txIDs := ""
	// Calculate amount received
	amountReceived := dcrutil.Amount(0)
	for i, tx := range txs {
		// Check to see if running mainnet, if so, only accept transactions
		// that originate from the Treasury Subsidy.
		if !p.cfg.TestNet && !p.cfg.SimNet {
			found := false
			for _, address := range tx.InputAddresses {
				if address == mainnetSubsidyAddr {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		amountReceived += dcrutil.Amount(tx.Amount)
		if i == 0 {
			txIDs = tx.TxID
		} else {
			txIDs += ", " + tx.TxID
		}
	}
	payment.TxIDs = txIDs

	if int64(amountReceived) == payment.AmountReceived {
		// Amount received still the same so nothing to update.
		return false
	}

	if int64(amountReceived) >= payment.AmountNeeded {
		payment.Status = cms.PaymentStatusPaid
	}
	payment.AmountReceived = int64(amountReceived)
	payment.TimeLastUpdated = time.Now().Unix()

	err = p.cmsDB.UpdatePayments(payment)
	if err != nil {
		log.Errorf("Error updating payments information for: %v %v",
			payment.Address, err)
	}

	if payment.Status == cms.PaymentStatusPaid {
		// Update invoice status here
		err := p.invoiceStatusPaid(payment.InvoiceToken)
		if err != nil {
			log.Errorf("error updating invoice status to paid %v", err)
		}
		return true
	}
	return false
}

func (p *politeiawww) invoiceStatusPaid(token string) error {
	dbInvoice, err := p.cmsDB.InvoiceByToken(token)
	if err != nil {
		if err == cache.ErrRecordNotFound {
			err = www.UserError{
				ErrorCode: cms.ErrorStatusInvoiceNotFound,
			}
		}
		return err
	}

	// Create the change record.
	c := backendInvoiceStatusChange{
		Version:   backendInvoiceStatusChangeVersion,
		Timestamp: time.Now().Unix(),
		NewStatus: cms.InvoiceStatusPaid,
		Reason:    "Invoice watcher found payment transactions.",
	}

	blob, err := encodeBackendInvoiceStatusChange(c)
	if err != nil {
		return err
	}

	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return err
	}

	pdCommand := pd.UpdateVettedMetadata{
		Challenge: hex.EncodeToString(challenge),
		Token:     token,
		MDAppend: []pd.MetadataStream{
			{
				ID:      mdStreamInvoiceStatusChanges,
				Payload: string(blob),
			},
		},
	}
	responseBody, err := p.makeRequest(http.MethodPost,
		pd.UpdateVettedMetadataRoute, pdCommand)
	if err != nil {
		return err
	}

	var pdReply pd.UpdateVettedMetadataReply
	err = json.Unmarshal(responseBody, &pdReply)
	if err != nil {
		return fmt.Errorf("Could not unmarshal UpdateVettedMetadataReply: %v",
			err)
	}

	// Verify the UpdateVettedMetadata challenge.
	err = util.VerifyChallenge(p.cfg.Identity, challenge, pdReply.Response)
	if err != nil {
		return err
	}

	// Update the database with the metadata changes.
	dbInvoice.Changes = append(dbInvoice.Changes, database.InvoiceChange{
		Timestamp: c.Timestamp,
		NewStatus: c.NewStatus,
		Reason:    c.Reason,
	})
	dbInvoice.StatusChangeReason = c.Reason
	dbInvoice.Status = c.NewStatus

	err = p.cmsDB.UpdateInvoice(dbInvoice)
	if err != nil {
		return err
	}

	return nil
}
