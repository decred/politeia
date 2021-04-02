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
	err = unittest.TestGenericConstMap(PropStatus, uint64(PropStatusLast))
	if err != nil {
		t.Fatalf("PropStatus: %v", err)
	}
	err = unittest.TestGenericConstMap(PropVoteStatus, uint64(PropVoteLast))
	if err != nil {
		t.Fatalf("PropVoteStatus: %v", err)
	}
	err = unittest.TestGenericConstMap(UserManageAction, uint64(UserManageLast))
	if err != nil {
		t.Fatalf("UserManageAction: %v", err)
	}
}
