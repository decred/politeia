// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import (
	"testing"

	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	"github.com/decred/politeia/unittest"
)

func TestVoteDetails(t *testing.T) {
	// Verify that the local structs match the API spec
	// structs.
	err := unittest.CompareStructFieldCounts(voteDetails{},
		ticketvote.VoteDetails{})
	if err != nil {
		t.Error(err)
	}
	err = unittest.CompareStructFieldCounts(voteParams{},
		ticketvote.VoteParams{})
	if err != nil {
		t.Error(err)
	}
	err = unittest.CompareStructFields(voteOption{},
		ticketvote.VoteOption{})
	if err != nil {
		t.Error(err)
	}
}
