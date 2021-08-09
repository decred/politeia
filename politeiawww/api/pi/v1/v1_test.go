// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC license that can be found in
// the LICENSE file.

package v1

import (
	"testing"

	"github.com/decred/politeia/unittest"
)

func TestMaps(t *testing.T) {
	err := unittest.TestGenericConstMap(ErrorCodes, uint64(ErrorCodeLast))
	if err != nil {
		t.Error(err)
	}
	err = unittest.TestGenericConstMap(BillingStatuses, uint64(BillingStatusLast))
	if err != nil {
		t.Error(err)
	}
}
