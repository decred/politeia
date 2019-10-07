// Copyright (c) 2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/decred/dcrd/dcrutil"
	pstypes "github.com/decred/dcrdata/pubsub/types/v2"
	pd "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/cache"
	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	database "github.com/decred/politeia/politeiawww/cmsdatabase"
	"github.com/decred/politeia/util"
)

const (
	// mainnetSubsidyAddr is the mainnet address in which cms payments
	// must come from in order to be considered a valid payment.
	mainnetSubsidyAddr = "Dcur2mcGjmENx4DhNqDctW5wJCVyT3Qeqkx"
)

func (p *politeiawww) addWatchAddress(address string) {
	err := p.wsDcrdata.subToAddr(address)
	if err != nil {
		log.Errorf("addWatchAddress: subscribe '%v': %v",
			address, err)
		p.reconnectWS()
		p.addWatchAddress(address)
		return
	}
	log.Infof("Subscribed to listen: %v", address)
}

func (p *politeiawww) removeWatchAddress(address string) {
	err := p.wsDcrdata.unsubFromAddr(address)
	if err != nil {
		log.Errorf("removeWatchAddress: unsubscribe '%v': %v",
			address, err)
		p.reconnectWS()
		p.removeWatchAddress(address)
		return
	}
	log.Infof("Unsubscribed: %v", address)
}

func (p *politeiawww) setupCMSAddressWatcher() {
	p.wsDcrdata.subToPing()
	go func() {
		for {
			msg, ok := <-p.wsDcrdata.client.Receive()
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
				paid := p.checkPayments(payment, m.Address, m.TxHash)
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
}

func (p *politeiawww) restartCMSAddressesWatching() error {
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
					Address:      strings.TrimSpace(invoice.PaymentAddress),
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
		payments.Address = strings.TrimSpace(payments.Address)
		paid := p.checkHistoricalPayments(&payments)
		if !paid {
			p.addWatchAddress(payments.Address)
		}
	}
	return nil
}

// checkHistoicalPayments checks to see if a given payment has been successfully paid.
// It will return TRUE if paid, otherwise false.  It utilizes the util
// FetchTxsForAddressNotBefore which looks for transaction at a given address
// after a certain time (in Unix seconds).
func (p *politeiawww) checkHistoricalPayments(payment *database.Payments) bool {
	// Get all txs since start time of watcher
	txs, err := util.FetchTxsForAddressNotBefore(strings.TrimSpace(payment.Address),
		payment.TimeStarted)
	if err != nil {
		// XXX Some sort of 'recheck' or notice that it should do it again?
		log.Errorf("error FetchTxsForAddressNotBefore for address %s: %v",
			payment.Address, err)
	}

	txIDs := ""
	// Calculate amount received
	amountReceived := dcrutil.Amount(0)
	log.Debugf("Reviewing transactions for address: %v", payment.Address)
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
		log.Debugf("Transaction %v with amount %v", tx.TxID, tx.Amount)
		amountReceived += dcrutil.Amount(tx.Amount)
		if i == 0 {
			txIDs = tx.TxID
		} else {
			txIDs += ", " + tx.TxID
		}
	}
	payment.TxIDs = txIDs

	log.Debugf("Amount received %v amount needed %v", int64(amountReceived),
		payment.AmountNeeded)

	if int64(amountReceived) == payment.AmountReceived {
		// Amount received still the same so nothing to update.
		return false
	}

	if int64(amountReceived) >= payment.AmountNeeded && amountReceived > 0 {
		log.Debugf("Invoice %v paid!", payment.InvoiceToken)
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
		log.Debugf("Updating invoice %v status to paid", payment.InvoiceToken)
		// Update invoice status here
		err := p.invoiceStatusPaid(payment.InvoiceToken)
		if err != nil {
			log.Errorf("error updating invoice status to paid %v", err)
		}
		return true
	}
	return false
}

// checkPayments checks to see if a given payment has been successfully paid.
// It will return TRUE if paid, otherwise false.  It utilizes the util
// FetchTxs which looks for transaction at a given address.
func (p *politeiawww) checkPayments(payment *database.Payments, watchedAddr, notifiedTx string) bool {
	txs, err := util.FetchTx(watchedAddr, notifiedTx)
	if err != nil {
		log.Errorf("error FetchTxs for address %s: %v", payment.Address, err)
		return false
	}
	if len(txs) == 0 {
		return false
	}

	txIDs := ""
	// Calculate amount received
	amountReceived := dcrutil.Amount(0)
	log.Debugf("Reviewing transactions for address: %v", payment.Address)
	// Transaction counter
	i := 0
	for _, tx := range txs {
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
		log.Debugf("Transaction %v with amount %v", tx.TxID, tx.Amount)
		amountReceived += dcrutil.Amount(tx.Amount)
		if i == 0 {
			txIDs = tx.TxID
		} else {
			txIDs += ", " + tx.TxID
		}
		i++
	}
	if payment.TxIDs == "" {
		payment.TxIDs = txIDs
	} else {
		payment.TxIDs += ", " + txIDs
	}

	log.Debugf("Amount received %v amount needed %v", int64(amountReceived),
		payment.AmountNeeded)

	if int64(amountReceived) >= payment.AmountNeeded && amountReceived > 0 {
		log.Debugf("Invoice %v paid!", payment.InvoiceToken)
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
		log.Debugf("Updating invoice %v status to paid", payment.InvoiceToken)
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

func (p *politeiawww) reconnectWS() {
	if p.wsDcrdata != nil {
		p.wsDcrdata.client.Stop()
		p.wsDcrdata = nil
	}
	var err error
	// Retry wsDcrdata reconnect every 1 minute
	for {
		p.wsDcrdata, err = newWSDcrdata()
		if err != nil {
			log.Errorf("reconnectWS error: %v", err)
		}
		if p.wsDcrdata != nil {
			break
		}
		log.Infof("Retrying ws dcrdata reconnect in 1 minute...")
		time.Sleep(1 * time.Minute)
	}
	p.setupCMSAddressWatcher()
}
