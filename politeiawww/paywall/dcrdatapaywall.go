package paywall

import (
	"sync"
	"time"

	pstypes "github.com/decred/dcrdata/pubsub/types/v3"
	"github.com/decred/politeia/util/txfetcher"
	"github.com/decred/politeia/wsdcrdata"
)

// DcrdataManager implements the Manager interface.
type DcrdataManager struct {
	sync.RWMutex

	wsDcrdata wsdcrdata.Client
	txFetcher txfetcher.TxFetcher
	callback  Callback
	paywalls  map[string]Paywall
}

func transactionsFulfillPaywall(txs []txfetcher.TxDetails, paywall Paywall) bool {
	var totalPaid uint64

	for i := 0; i < len(txs); i++ {
		if txs[i].Address == paywall.Address &&
			txs[i].Timestamp >= paywall.TxNotBefore {
			totalPaid += txs[i].Amount
		}
	}

	return totalPaid >= paywall.Amount
}

// RegisterPaywall registers a new paywall to the paywall manager.
//
// This function must be called WITH the lock held.
func (d *DcrdataManager) registerPaywall(paywall Paywall) error {
	_, ok := d.paywalls[paywall.Address]
	if ok {
		return ErrDuplicatePaywall
	}

	err := d.wsDcrdata.AddressSubscribe(paywall.Address)
	if err != nil {
		return err
	}

	d.paywalls[paywall.Address] = paywall
	return nil
}

// RegisterPaywall registers a new paywall to the paywall manager.
func (d *DcrdataManager) RegisterPaywall(paywall Paywall) error {
	txs, err := d.txFetcher.FetchTxsForAddressNotBefore(paywall.Address, paywall.TxNotBefore)
	if err != nil {
		return err
	}
	if transactionsFulfillPaywall(txs, paywall) {
		return ErrAlreadyPaid
	}

	d.Lock()
	defer d.Unlock()
	return d.registerPaywall(paywall)
}

// removePaywall removes a paywall from the paywall manager.
//
// This function must be called WITH the lock held.
func (d *DcrdataManager) removePaywall(address string) {
	delete(d.paywalls, address)
	d.wsDcrdata.AddressUnsubscribe(address)
}

// RemovePaywall removes a paywall from the paywall manager.
func (d *DcrdataManager) RemovePaywall(address string) {
	d.Lock()
	defer d.Unlock()

	d.removePaywall(address)
}

// processPaymentReceived is called whenever a websocket message regarding
// a transaction that potentially fulfulls a pending paywall is received.
// The Dcrdata HTTP API must be queried for the details of the transaction,
// and then the callback function is called to alert the client.
func (d *DcrdataManager) processPaymentReceived(address, txID string) {
	d.RLock()
	paywall, ok := d.paywalls[address]
	d.RUnlock()
	if !ok {
		return
	}

	// Sometimes, dcrdata sends a websocket messasge about a transaction,
	// but it is not yet available through the HTTP API. Therefore, we
	// query dcrdata multiple times until the response contains the
	// transaction.
	const (
		NumTries     = 10
		SecondsSleep = 30
	)

	var (
		txFound bool
		txs     []txfetcher.TxDetails
		err     error
	)

	for tries := 0; tries <= NumTries && !txFound; tries++ {
		txs, err = d.txFetcher.FetchTxsForAddressNotBefore(address,
			paywall.TxNotBefore)
		if err != nil {
			log.Errorf("FetchTxsForAddressNotBefore: %v", err)
			return
		}

		for i := 0; i < len(txs); i++ {
			if txs[i].TxID == txID {
				txFound = true
			}
		}

		if !txFound {
			time.Sleep(SecondsSleep * time.Second)
		}
	}

	// Once the transaction is found, the callback is called, and the paywall
	// is removed from the manager if the transaction completely fulfilled the
	// paywall.
	if txFound {
		d.Lock()
		defer d.Unlock()

		// We check if the entry is still in the map, because we don't want
		// to call the callback if the entry has been removed by another
		// goroutine.
		paywall, ok = d.paywalls[address]
		if !ok {
			return
		}

		paywallFulfilled := transactionsFulfillPaywall(txs, paywall)
		if paywallFulfilled {
			d.removePaywall(address)
		}

		d.callback(paywall, txs, paywallFulfilled)
	} else {
		log.Errorf("processPaymentReceived: txId %v not found after "+
			"%v tries.", txID, NumTries)
	}
}

// listenForPayment listens for wsdcrdata messages, an
func (d *DcrdataManager) listenForPayments() {
	defer func() {
		log.Infof("Dcrdata websocket closed")
	}()

	// Setup messages channel
	receiver := d.wsDcrdata.Receive()

	for {
		// Monitor for a new message
		msg, ok := <-receiver
		if !ok {
			// Check if the websocket was shut down intentionally or was
			// dropped unexpectedly.
			if d.wsDcrdata.Status() == wsdcrdata.StatusShutdown {
				return
			}
			log.Infof("Dcrdata websocket connection unexpectedly dropped")
			goto reconnect
		}

		// Handle new message
		switch m := msg.Message.(type) {
		case *pstypes.AddressMessage:
			log.Debugf("WSDcrdata message AddressMessage(address=%v , tx=%v)\n",
				m.Address, m.TxHash)
			go d.processPaymentReceived(m.Address, m.TxHash)

		case *pstypes.HangUp:
			log.Infof("Dcrdata websocket has hung up. Will reconnect.")
			goto reconnect

		case int:
			// Ping messages are of type int

		default:
			log.Errorf("wsDcrdata message of type %v unhandled: %v",
				msg.EventId, m)
		}

		// Check for next message
		continue

	reconnect:
		// Reconnect
		d.wsDcrdata.Reconnect()

		// Setup a new messages channel using the new connection.
		receiver = d.wsDcrdata.Receive()

		log.Infof("Successfully reconnected dcrdata websocket")
	}
}

// New creates a new DcrdataManger.
func New(ws wsdcrdata.Client, txFetcher txfetcher.TxFetcher, cb Callback) *DcrdataManager {
	d := DcrdataManager{
		paywalls:  make(map[string]Paywall),
		callback:  cb,
		wsDcrdata: ws,
		txFetcher: txFetcher,
	}

	go d.listenForPayments()

	return &d
}
