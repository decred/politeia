// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlogbe

import (
	"fmt"
	"testing"

	"github.com/decred/politeia/politeiad/backend"
)

func TestNewRecord(t *testing.T) {
	tlogBackend, err := newTestTlogBackend(t)
	if err != nil {
		fmt.Printf("Error in newTestTlogBackend %v", err)
		return
	}

	metadata := backend.MetadataStream{
		ID:      1,
		Payload: "",
	}

	file := backend.File{
		Name:    "index.md",
		MIME:    "text/plain; charset=utf-8",
		Digest:  "22e88c7d6da9b73fbb515ed6a8f6d133c680527a799e3069ca7ce346d90649b2",
		Payload: "bW9vCg==",
	}

	rmd, err := tlogBackend.New([]backend.MetadataStream{metadata}, []backend.File{file})
	if err != nil {
		fmt.Printf("Error in New %v", err)
		return
	}

	fmt.Println(rmd)
}
