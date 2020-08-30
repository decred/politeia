// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package txfetcher

import (
	"fmt"
	"sync"
)

// TestTxFetcher satisfies the TxFetcher interface.
type TestTxFetcher struct {
	sync.RWMutex

	txs []TxDetails
}

// InsertTx satisfies the TxFetcher interface.
func (t *TestTxFetcher) InsertTx(tx TxDetails) {
	t.Lock()
	defer t.Unlock()

	t.txs = append(t.txs, tx)
}

// FetchTxWithBlockExplorers satisfies the TxFetcher interface.
func (t *TestTxFetcher) FetchTxWithBlockExplorers(address string, amount uint64, txnotbefore int64, minConfirmations uint64) (string, uint64, error) {
	return "", 0, fmt.Errorf("TestTxFetcher FetchTxWithBlockExporer not yet implemented")
}

// FetchTxsForAddress satisfies the TxFetcher interface.
func (t *TestTxFetcher) FetchTxsForAddress(address string) ([]TxDetails, error) {
	return nil, fmt.Errorf("TestTxFetcher FetchTxsForAddress not yet implemented")
}

// FetchTxsForAddressNotBefore satisfies the TxFetcher interface.
func (t *TestTxFetcher) FetchTxsForAddressNotBefore(address string, notBefore int64) ([]TxDetails, error) {
	t.RLock()
	defer t.RUnlock()

	txs := make([]TxDetails, 0)

	for _, tx := range t.txs {
		if tx.Address == address &&
			tx.Timestamp >= notBefore {
			txs = append(txs, tx)
		}
	}

	return txs, nil
}

// FetchTx satisfies the TxFetcher interface.
func (t *TestTxFetcher) FetchTx(address, txid string) (*TxDetails, error) {
	return nil, fmt.Errorf("FetchTx FetchTxsForAddress not yet implemented")
}

// NewTest returns a new TestTxFetcher struct.
func NewTest() *TestTxFetcher {
	return &TestTxFetcher{
		txs: make([]TxDetails, 0),
	}
}
