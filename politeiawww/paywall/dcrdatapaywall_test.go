package paywall

import (
	"fmt"
	"sync"
	"testing"
	"time"

	pstypes "github.com/decred/dcrdata/pubsub/types/v3"
	client "github.com/decred/dcrdata/pubsub/v4/psclient"

	"github.com/decred/politeia/wsdcrdata"

	"github.com/decred/politeia/util/txfetcher"
)

type TestEntry struct {
	Address    string
	AmountPaid uint64
	Fulfilled  bool
}

func createUpdatePaywallsCallback(testEntries *[]*TestEntry, mutex *sync.RWMutex) Callback {

	return func(paywall Paywall, txs []txfetcher.TxDetails, fulfilled bool) error {
		mutex.Lock()
		defer mutex.Unlock()

		var foundPaywall bool

		for _, testEntry := range *testEntries {

			if paywall.Address == testEntry.Address {
				foundPaywall = true
			} else {
				continue
			}

			var amount uint64
			for i := 0; i < len(txs); i++ {
				amount += txs[i].Amount
			}

			testEntry.AmountPaid = amount
			testEntry.Fulfilled = fulfilled

			if fulfilled && amount < paywall.Amount {
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

func TestDcrdataPaywall(t *testing.T) {
	paywalls := []Paywall{
		{
			Address:     "1",
			Amount:      1000,
			TxNotBefore: 100,
		},
		{
			Address:     "2",
			Amount:      1000,
			TxNotBefore: 100,
		},
		{
			Address:     "3",
			Amount:      1000,
			TxNotBefore: 100,
		},
		{
			Address:     "4",
			Amount:      1000,
			TxNotBefore: 100,
		},
		{
			Address:     "5",
			Amount:      1000,
			TxNotBefore: 100,
		},
	}

	txs := []txfetcher.TxDetails{
		{
			Address:   "1",
			TxID:      "1",
			Amount:    1000,
			Timestamp: 80,
		},
		{
			Address:   "2",
			TxID:      "2",
			Amount:    1000,
			Timestamp: 120,
		},
		{
			Address:   "3",
			TxID:      "3",
			Amount:    800,
			Timestamp: 130,
		},
		{
			Address:   "4",
			TxID:      "4",
			Amount:    500,
			Timestamp: 120,
		},
		{
			Address:   "4",
			TxID:      "5",
			Amount:    700,
			Timestamp: 120,
		},
		{
			Address:   "5",
			TxID:      "6",
			Amount:    700,
			Timestamp: 120,
		},
	}

	expectedResults := []TestEntry{
		{
			Address:    "1",
			AmountPaid: 0,
			Fulfilled:  false,
		},
		{
			Address:    "2",
			AmountPaid: 1000,
			Fulfilled:  true,
		},
		{
			Address:    "3",
			AmountPaid: 800,
			Fulfilled:  false,
		},
		{
			Address:    "4",
			AmountPaid: 1200,
			Fulfilled:  true,
		},
		{
			Address:    "5",
			AmountPaid: 0,
			Fulfilled:  false,
		},
	}

	testEntries := make([]*TestEntry, 0)

	txFetcher := txfetcher.NewTest()
	wsDcrdata := wsdcrdata.NewTest()
	mutex := sync.RWMutex{}

	callback := createUpdatePaywallsCallback(&testEntries, &mutex)
	paywallManager := New(wsDcrdata, txFetcher, callback)

	for _, paywall := range paywalls {
		paywallManager.RegisterPaywall(paywall)
		testEntries = append(testEntries, &TestEntry{
			Address: paywall.Address,
		})
	}

	err := paywallManager.RegisterPaywall(paywalls[0])
	if err != ErrDuplicatePaywall {
		t.Fatal("Should not be able to register duplicate paywall")
	}

	paywallManager.RemovePaywall("5")

	for _, tx := range txs {
		txFetcher.InsertTx(tx)

		wsDcrdata.SendMessage(
			&client.ClientMessage{
				EventId: "",
				Message: &pstypes.AddressMessage{
					Address: tx.Address,
					TxHash:  tx.TxID,
				},
			})
	}

	time.Sleep(1 * time.Second)

	mutex.Lock()
	defer mutex.Unlock()

	if len(expectedResults) != len(paywalls) {
		t.Fatal("results and expected results have different lengths")
	}

	for i := 0; i < len(expectedResults); i++ {
		if expectedResults[i].Address != testEntries[i].Address {
			t.Fatal("results and expected results are in the wrong order")
		}
		if expectedResults[i].AmountPaid != testEntries[i].AmountPaid {
			t.Fatal("results and expected results amount paid does not match")
		}
		if expectedResults[i].Fulfilled != testEntries[i].Fulfilled {
			t.Fatal("results and expected results fulfilled does not match")
		}
	}
}

func TestDuplicateEntry(t *testing.T) {
	testEntries := make([]*TestEntry, 0)

	txFetcher := txfetcher.NewTest()
	wsDcrdata := wsdcrdata.NewTest()
	mutex := sync.RWMutex{}

	callback := createUpdatePaywallsCallback(&testEntries, &mutex)
	paywallManager := New(wsDcrdata, txFetcher, callback)

	paywallManager.RegisterPaywall(Paywall{
		Address:     "1",
		Amount:      1000,
		TxNotBefore: 100,
	},
	)

	err := paywallManager.RegisterPaywall(Paywall{
		Address:     "1",
		Amount:      3000,
		TxNotBefore: 120,
	},
	)

	if err != ErrDuplicatePaywall {
		t.Fatal("Should not be able to register duplicate paywall")
	}
}

func TestAlreadyPaid(t *testing.T) {
	testEntries := make([]*TestEntry, 0)

	txFetcher := txfetcher.NewTest()
	wsDcrdata := wsdcrdata.NewTest()
	mutex := sync.RWMutex{}

	callback := createUpdatePaywallsCallback(&testEntries, &mutex)
	paywallManager := New(wsDcrdata, txFetcher, callback)

	txFetcher.InsertTx(
		txfetcher.TxDetails{
			Address:   "1",
			TxID:      "1",
			Amount:    1500,
			Timestamp: 130,
		})

	err := paywallManager.RegisterPaywall(Paywall{
		Address:     "1",
		Amount:      1000,
		TxNotBefore: 100,
	})

	if err != ErrAlreadyPaid {
		t.Fatal("Should not be able to register paywall that is already" +
			" fulfilled")
	}
}
