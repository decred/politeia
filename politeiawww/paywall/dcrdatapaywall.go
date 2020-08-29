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
	entries   map[string]*Entry
}

func transactionsFulfillPaywall(txs []txfetcher.TxDetails, entry Entry) bool {
	var totalPaid uint64

	for i := 0; i < len(txs); i++ {
		totalPaid += txs[i].Amount
	}

	return totalPaid >= entry.Amount
}

// RegisterPaywall satisfies the Manager interface.
func (d *DcrdataManager) RegisterPaywall(entry Entry) error {
	txs, err := d.txFetcher.FetchTxsForAddressNotBefore(entry.Address, entry.TxNotBefore)
	if err != nil {
		return err
	}
	if transactionsFulfillPaywall(txs, entry) {
		return ErrAlreadyPaid
	}

	d.Lock()
	defer d.Unlock()

	_, ok := d.entries[entry.Address]
	if ok {
		return ErrDuplicateEntry
	}

	err = d.wsDcrdata.AddressSubscribe(entry.Address)
	if err != nil {
		return err
	}

	d.entries[entry.Address] = &entry
	return nil
}

// RemovePaywall satisfies the manager interface.
func (d *DcrdataManager) RemovePaywall(address string) {
	d.Lock()
	defer d.Unlock()

	delete(d.entries, address)
}

func (d *DcrdataManager) processPaymentReceived(address, txID string) {
	d.RLock()
	entry, ok := d.entries[address]
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

	go func() {
		var tries int

		for {
			txs, err := d.txFetcher.FetchTxsForAddressNotBefore(address,
				entry.TxNotBefore)
			if err != nil {
				log.Errorf("FetchTxsForAddressNotBefore: %v", err)
				return
			}

			txFound := false
			for i := 0; i < len(txs); i++ {
				if txs[i].TxID == txID {
					txFound = true
					break
				}
			}

			if !txFound {
				if tries >= NumTries {
					return
				}

				tries++
				time.Sleep(SecondsSleep * time.Second)
				continue
			}

			paywallFulfilled := transactionsFulfillPaywall(txs, *entry)

			// We check if the entry is still in the map, because we don't want
			// to call the callback if the entry has been removed by another
			// goroutine.
			d.Lock()
			defer d.Unlock()
			entry, ok = d.entries[address]
			if !ok {
				return
			}
			if paywallFulfilled {
				delete(d.entries, address)
			}
			d.callback(entry, txs, paywallFulfilled)
			return
		}
	}()
}

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
			log.Debugf("WSDcrdata message AddressMessage(addres=%v , tx=%v)\n",
				m.Address, m.TxHash)
			d.processPaymentReceived(m.Address, m.TxHash)

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

// NewDcrdataManager creates a new DcrdataManger.
func NewDcrdataManager(ws wsdcrdata.Client, txFetcher txfetcher.TxFetcher, cb Callback) *DcrdataManager {
	d := DcrdataManager{
		entries:   make(map[string]*Entry),
		callback:  cb,
		wsDcrdata: ws,
		txFetcher: txFetcher,
	}

	go d.listenForPayments()

	return &d
}
