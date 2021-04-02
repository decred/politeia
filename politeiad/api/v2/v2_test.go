// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC license that can be found in
// the LICENSE file.

package v2

import (
	"testing"

	"github.com/decred/politeia/unittest"
)

func TestMaps(t *testing.T) {
	err := unittest.TestGenericConstMap(ErrorCodes, uint64(ErrorCodeLast))
	if err != nil {
		t.Fatalf("ErrorCodes: %v", err)
	}
	err = unittest.TestGenericConstMap(RecordStates, RecordStateLast)
	if err != nil {
		t.Fatalf("RecordStates: %v", err)
	}
	err = unittest.TestGenericConstMap(RecordStatuses, RecordStatusLast)
	if err != nil {
		t.Fatalf("RecordStatuses: %v", err)
	}
}
