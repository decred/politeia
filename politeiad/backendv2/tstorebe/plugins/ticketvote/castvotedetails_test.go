// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import (
	"testing"

	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	"github.com/decred/politeia/unittest"
)

func TestCastVoteDetails(t *testing.T) {
	// Verify the local struct contains the all same fields
	// as the API struct.
	err := unittest.CompareStructFields(castVoteDetails{},
		ticketvote.CastVoteDetails{})
	if err != nil {
		t.Error(err)
	}
}
