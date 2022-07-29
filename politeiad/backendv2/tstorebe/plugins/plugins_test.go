// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package plugins

import (
	"testing"

	"github.com/decred/politeia/util/unittest"
)

func TestHooks(t *testing.T) {
	err := unittest.TestGenericConstMap(Hooks, uint64(HookTypeLast))
	if err != nil {
		t.Error(err)
	}
}
