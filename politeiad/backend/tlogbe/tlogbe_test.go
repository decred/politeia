// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlogbe

import (
	"errors"
	"testing"

	"github.com/decred/politeia/politeiad/backend"
)

func TestNewRecord(t *testing.T) {
	tlogBackend, err := newTestTlogBackend(t)
	if err != nil {
		t.Errorf("error in newTestTlogBackend %v", err)
	}

	// Test all record content verification error through the New endpoint
	recordContentTests := setupRecordContentTests(t)
	for _, test := range recordContentTests {
		t.Run(test.description, func(t *testing.T) {
			_, err := tlogBackend.New(test.metadata, test.files)

			var contentError backend.ContentVerificationError
			if errors.As(err, &contentError) {
				if contentError.ErrorCode != test.err.ErrorCode {
					t.Errorf("got error %v, want %v", contentError.ErrorCode,
						test.err.ErrorCode)
				}
			}
		})
	}

	// Test success case
	md := []backend.MetadataStream{
		newBackendMetadataStream(t, 1, ""),
	}
	fs := []backend.File{
		newBackendFile(t, "index.md"),
	}
	_, err = tlogBackend.New(md, fs)
	if err != nil {
		t.Errorf("success case failed with %v", err)
	}
}
