// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC license that can be found in
// the LICENSE file.

package backendv2

import (
	"testing"

	"github.com/decred/politeia/unittest"
)

func TestMaps(t *testing.T) {
	err := unittest.TestGenericConstMap(States, uint64(StateLast))
	if err != nil {
		t.Fatalf("States: %v", err)
	}
	err = unittest.TestGenericConstMap(Statuses, uint64(StatusLast))
	if err != nil {
		t.Fatalf("Statuses: %v", err)
	}
}
