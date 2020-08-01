package paywall

import (
	"fmt"
	"testing"

	pstypes "github.com/decred/dcrdata/pubsub/types/v3"
	client "github.com/decred/dcrdata/pubsub/v4/psclient"

	"github.com/decred/politeia/politeiawww/wsdcrdata"

	"github.com/decred/politeia/util/txfetcher"
)

type AddressPaywall struct {
	Address    string
	AmountPaid uint64
	Fulfilled  bool
}

func createUpdatePaywallsCallback(paywalls []AddressPaywall) Callback {
	return func(entry *Entry, txs []txfetcher.TxDetails, fulfilled bool) error {
		var foundPaywall bool

		for _, paywall := range paywalls {

			if paywall.address == entry.address {
				foundPaywall = true
			} else {
				continue
			}

			var amount uint64
			for i := 0; i < len(txs); i++ {
				amount += txs[i].Amount
			}

			paywall.amountPaid = amount
			paywall.fulfilled = fulfilled

			if fulfilled && amount < entry.amount {
				return fmt.Errorf("fulfilled but not enough paid")
			}

			break
		}

		if !foundPaywall {
			return fmt.Errorf("Callback called with address without entry")
		}

		return nil
	}
}

func TestTransactionsFulfillPaywall(t *testing.T) {
	paywalls := make([]AddressPaywall, 0)
	callback := createUpdatePaywallsCallback(paywalls)

	txFetcher := txfetcher.NewTestTxFetcher()
	wsDcrdata := wsdcrdata.NewTestWSDcrdata()

	paywallManager := NewDcrdataManager(wsDcrdata, txFetcher)
	paywallManager.SetCallback(callback)

	testEntries := []Entry{
		{
			address:     "1",
			amount:      1000,
			txNotBefore: 100,
		},
		{
			address:     "2",
			amount:      1000,
			txNotBefore: 100,
		},
		{
			address:     "3",
			amount:      1000,
			txNotBefore: 100,
		},
		{
			address:     "4",
			amount:      1000,
			txNotBefore: 100,
		},
	}

	testTXs := []txfetcher.TxDetails{
		txfetcher.TxDetails{
			Address:   "1",
			TxID:      "1",
			Amount:    1000,
			Timestamp: 80,
		},
		txfetcher.TxDetails{
			Address:   "2",
			TxID:      "2",
			Amount:    1000,
			Timestamp: 120,
		},
		txfetcher.TxDetails{
			Address:   "3",
			TxID:      "3",
			Amount:    800,
			Timestamp: 130,
		},
		txfetcher.TxDetails{
			Address:   "4",
			TxID:      "4",
			Amount:    500,
			Timestamp: 120,
		},
		txfetcher.TxDetails{
			Address:   "4",
			TxID:      "5",
			Amount:    700,
			Timestamp: 120,
		},
	}

	for _, entry := range testEntries {
		paywallManager.RegisterPaywall(&entry)
	}

	for _, tx := range testTXs {
		txFetcher.InsertTx(tx)

		wsDcrdata.SendMessage(
			&client.ClientMessage{
				EventId: "",
				Message: pstypes.AddressMessage{
					Address: tx.Address,
					TxHash:  tx.TxID,
				},
			})
	}

}
