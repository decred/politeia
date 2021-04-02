// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC license that can be found in
// the LICENSE file.

package v1

import (
	"testing"

	"github.com/decred/politeia/unittest"
)

func TestMaps(t *testing.T) {
	err := unittest.TestGenericConstMap(ErrorStatus, uint64(ErrorStatusLast))
	if err != nil {
		t.Fatalf("ErrorStatus: %v", err)
	}
	err = unittest.TestGenericConstMap(RecordStatus, uint64(RecordStatusLast))
	if err != nil {
		t.Fatalf("RecordStatus: %v", err)
	}
}
