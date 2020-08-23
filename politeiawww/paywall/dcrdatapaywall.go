package paywall

import (
	"sync"
	"time"

	pstypes "github.com/decred/dcrdata/pubsub/types/v3"
	"github.com/decred/politeia/politeiawww/wsdcrdata"
	"github.com/decred/politeia/util/txfetcher"
)

// DcrdataManager implements the Manager interface.
type DcrdataManager struct {
	sync.RWMutex

	wsDcrdata wsdcrdata.WSDcrdata
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

	err = d.wsDcrdata.SubToAddr(entry.Address)
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
	for {
		receiver, err := d.wsDcrdata.Receive()
		if err == wsdcrdata.ErrShutdown {
			log.Infof("Dcrdata websocket closed")
			return
		} else if err != nil {
			log.Errorf("WSDcrdata receive: %v", err)
			log.Infof("Dcrdata websocket closed")
			return
		}

		msg, ok := <-receiver

		if !ok {
			// This check is here to avoid a spew of unnecessary error
			// messages. The channel is expected to be closed if WSDcrdata
			// is shut down.
			if d.wsDcrdata.IsShutdown() {
				return
			}

			log.Errorf("WSDcrdata receive channel closed. Will reconnect.")
			err = d.wsDcrdata.Reconnect()
			if err == wsdcrdata.ErrShutdown {
				log.Infof("Dcrdata websocket closed")
				return
			} else if err != nil {
				log.Errorf("wsDcrdata Reconnect: %v", err)
				log.Infof("Dcrdata websocket closed")
				return
			}

			continue
		}

		switch m := msg.Message.(type) {
		case *pstypes.HangUp:
			log.Infof("Dcrdata has hung up. Will reconnect.")
			err = d.wsDcrdata.Reconnect()
			if err == wsdcrdata.ErrShutdown {
				log.Infof("Dcrdata websocket closed")
				return
			} else if err != nil {
				log.Errorf("wsDcrdata Reconnect: %v", err)
				log.Infof("Dcrdata websocket closed")
				return
			}
			log.Infof("Successfully reconnected to dcrdata")
		case *pstypes.AddressMessage:
			log.Debugf("WSDcrdata message AddressMessage(addres=%v , tx=%v)\n",
				m.Address, m.TxHash)
			d.processPaymentReceived(m.Address, m.TxHash)
		case int:
			// Ping messages are of type int
		default:
			log.Errorf("WSDcrdata message of type %v unhandled. %v",
				msg.EventId, m)
		}
	}
}

// NewDcrdataManager creates a new DcrdataManger.
func NewDcrdataManager(ws wsdcrdata.WSDcrdata, txFetcher txfetcher.TxFetcher, cb Callback) *DcrdataManager {
	d := DcrdataManager{
		entries:   make(map[string]*Entry),
		callback:  cb,
		wsDcrdata: ws,
		txFetcher: txFetcher,
	}

	go d.listenForPayments()

	return &d
}
