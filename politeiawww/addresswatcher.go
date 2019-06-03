// Copyright (c) 2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"time"

	"github.com/decred/dcrd/dcrutil"
	client "github.com/decred/dcrdata/pubsub/psclient"
	pstypes "github.com/decred/dcrdata/pubsub/types"
	"github.com/decred/dcrdata/semver"
	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	database "github.com/decred/politeia/politeiawww/cmsdatabase"
	"github.com/decred/politeia/util"
)

func (p *politeiawww) addWatchAddress(address string) error {
	address = "address:" + address
	if subd, _ := strInSlice(p.currentSubs, address); subd {
		log.Infof("Already subscribed to %s.", address)
		return nil
	}
	p.currentSubs = append(p.currentSubs, address)
	resp, err := p.wsClient.Subscribe(address)
	if err != nil {
		return fmt.Errorf("failed to subscribe: %v", err)
	}
	log.Infof(resp.Data)
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
	resp, err := p.wsClient.Unsubscribe(address)
	if err != nil {
		return fmt.Errorf("failed to unsubscribe: %v", err)
	}
	log.Infof(resp.Data)
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

	ctx, cancel := context.WithCancel(context.Background())
	opts := client.Opts{
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	}
	p.cancelContext = cancel
	p.wsClient, err = client.New(wsURL, ctx, &opts)
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
			msg := <-p.wsClient.Receive()
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

func (p *politeiawww) checkPayments(payment *database.Payments) bool {
	// Get all txs since start time of watcher
	txs, err := util.FetchTxsForAddressNotBefore(payment.Address, payment.TimeStarted)
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
		payment.AmountReceived += int64(tx.Amount)
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

	payment.TimeLastUpdated = time.Now().Unix()

	err = p.cmsDB.UpdatePayments(payment)
	if err != nil {
		log.Errorf("Error updating payments information for: %v %v", payment.Address, err)
	}

	if payment.Status == cms.PaymentStatusPaid {
		return true
	}
	return false
}
