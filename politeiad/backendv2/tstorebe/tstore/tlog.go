// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tstore

import (
	"fmt"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/google/trillian"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// leavesAll provides a wrapper around the tlog LeavesAll method that unpacks
// any tree not found errors and instead returns a backend ErrRecordNotFound
// error.
func (t *Tstore) leavesAll(treeID int64) ([]*trillian.LogLeaf, error) {
	leaves, err := t.tlog.LeavesAll(treeID)
	if err != nil {
		if c := status.Code(err); c == codes.NotFound {
			return nil, backend.ErrRecordNotFound
		}
		return nil, fmt.Errorf("LeavesAll: %v", err)
	}
	return leaves, nil
}
