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
		t.Fatalf("ErrorCodes: %v", err)
	}
	err = unittest.TestGenericConstMap(VoteTypes, uint64(VoteTypeLast))
	if err != nil {
		t.Fatalf("VoteTypes: %v", err)
	}
	err = unittest.TestGenericConstMap(VoteStatuses, uint64(VoteStatusLast))
	if err != nil {
		t.Fatalf("VoteStatuses: %v", err)
	}
}
