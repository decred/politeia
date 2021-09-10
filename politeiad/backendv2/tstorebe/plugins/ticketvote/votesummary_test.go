// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import (
	"testing"

	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	"github.com/decred/politeia/unittest"
)

func TestVoteSummary(t *testing.T) {
	// Verify that the local struct match the API spec
	// struct.
	err := unittest.CompareStructFields(voteSummary{},
		ticketvote.VoteSummaryReply{})
	if err != nil {
		t.Error(err)
	}
}
