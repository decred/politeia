package paywall

import (
	"fmt"
	"sync"
	"time"

	exptypes "github.com/decred/dcrdata/explorer/types/v2"
	pstypes "github.com/decred/dcrdata/pubsub/types/v3"
	"github.com/decred/politeia/politeiawww/dcrdata"
	"github.com/decred/politeia/util"
)

type DcrdataManager struct {
	sync.RWMutex

	wsDcrdata       *dcrdata.WSDcrdata
	callback        Callback
	entries         map[string]*Entry
	dcrdataHTTPHost string
}

func (d *DcrdataManager) SetCallback(cb Callback) {
	d.Lock()
	defer d.Unlock()

	d.callback = cb
}

func transactionsFulfillPaywall(txs []util.TxDetails, entry *Entry) bool {
	var totalPaid uint64

	for i := 0; i < len(txs); i++ {
		totalPaid += txs[i].Amount
	}

	return totalPaid >= entry.amount
}

func (d *DcrdataManager) RegisterPaywall(entry *Entry) error {
	_, ok := d.entries[entry.address]
	if ok {
		return ErrDuplicateEntry
	}

	txs, err := util.FetchTxsForAddressNotBefore(entry.address, entry.txNotBefore, d.dcrdataHTTPHost)
	if err != nil {
		return err
	}

	if transactionsFulfillPaywall(txs, entry) {
		return ErrAlreadyPaid
	}

	d.Lock()
	d.entries[entry.address] = entry
	d.Unlock()

	err = d.wsDcrdata.SubToAddr(entry.address)
	if err != nil {
		d.Lock()
		delete(d.entries, entry.address)
		d.Unlock()
		return err
	}

	return nil
}

func (d *DcrdataManager) RemovePaywall(address string) {
	d.Lock()
	defer d.Unlock()

	_, ok := d.entries[address]
	if ok {
		delete(d.entries, address)
	}
}

func (d *DcrdataManager) processPaymentReceived(address, txID string) {
	d.RLock()
	entry, ok := d.entries[address]
	callback := d.callback
	d.RUnlock()

	if !ok || callback == nil{
		return
	}

	go func() {

		var tries int

		for {
			txs, err := util.FetchTxsForAddressNotBefore(address, 
														 entry.txNotBefore,
														 d.dcrdataHTTPHost)
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
				if tries >= 10 {
					return
				}

				tries++
				time.Sleep(30 * time.Second)
				continue
			}
			
			paywallFulfilled := transactionsFulfillPaywall(txs, entry)
			if paywallFulfilled {
				d.Lock()
				delete(d.entries, address)
				d.Unlock()
			}
			callback(entry, txs, paywallFulfilled)
		}
	}()
}

func (d *DcrdataManager) listenForPayments() {
	for {
		receiver, err := d.wsDcrdata.Receive()
		if err == dcrdata.ErrShutdown {
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
			if err == dcrdata.ErrShutdown {
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
		case *exptypes.WebsocketBlock:
			log.Debugf("WSDcrdata message WebsocketBlock(height=%v)",
				m.Block.Height)
		case *pstypes.HangUp:
			log.Infof("Dcrdata has hung up. Will reconnect.")
			err = d.wsDcrdata.Reconnect()
			if err == dcrdata.ErrShutdown {
				log.Infof("Dcrdata websocket closed")
				return
			} else if err != nil {
				log.Errorf("wsDcrdata Reconnect: %v", err)
				log.Infof("Dcrdata websocket closed")
				return
			}
			log.Infof("Successfully reconnected to dcrdata")
		case *pstypes.AddressMessage:
			log.Debugf("WSDcrdata message AddressMessage(addres=%v , tx=%v)",
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

func NewDcrdataManager(dcrdataWSHost, dcrdataHTTPHost string) (DcrdataManager, error) {
	d := DcrdataManager{}

	ws, err := dcrdata.NewWSDcrdata(dcrdataWSHost)
	if err != nil {
		return d, fmt.Errorf("new wsDcrdata: %v", err)
	}

	d.dcrdataHTTPHost = dcrdataHTTPHost
	d.wsDcrdata = ws

	go d.listenForPayments()

	return d, nil
}
