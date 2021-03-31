// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC license that can be found in
// the LICENSE file.

package backend

import (
	"testing"

	"github.com/decred/politeia/unittest"
)

func TestMaps(t *testing.T) {
	err := unittest.TestGenericConstMap(MDStatus, uint64(MDStatusLast))
	if err != nil {
		t.Fatalf("MDStatus: %v", err)
	}
}
