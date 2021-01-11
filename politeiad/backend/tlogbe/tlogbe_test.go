// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlogbe

import (
	"errors"
	"testing"

	v1 "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/util"
)

func TestNewRecord(t *testing.T) {
	tlogBackend, cleanup := newTestTlogBackend(t)
	defer cleanup()

	// Test all record content verification error through the New endpoint
	recordContentTests := setupRecordContentTests(t)
	for _, test := range recordContentTests {
		t.Run(test.description, func(t *testing.T) {
			// Make backend call
			_, err := tlogBackend.New(test.metadata, test.files)

			// Parse error
			var contentError backend.ContentVerificationError
			if errors.As(err, &contentError) {
				if contentError.ErrorCode != test.err.ErrorCode {
					t.Errorf("got error %v, want %v",
						v1.ErrorStatus[contentError.ErrorCode],
						v1.ErrorStatus[test.err.ErrorCode])
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
	_, err := tlogBackend.New(md, fs)
	if err != nil {
		t.Errorf("success case failed with %v", err)
	}
}

func TestUpdateUnvettedRecord(t *testing.T) {
	tlogBackend, cleanup := newTestTlogBackend(t)
	defer cleanup()

	// Create new record
	md := []backend.MetadataStream{
		newBackendMetadataStream(t, 1, ""),
	}
	fs := []backend.File{
		newBackendFile(t, "index.md"),
	}
	rec, err := tlogBackend.New(md, fs)
	if err != nil {
		t.Error(err)
	}
	token, err := tokenDecode(rec.Token)
	if err != nil {
		t.Error(err)
	}

	// Test all record content verification error through the
	// UpdateUnvettedRecord endpoint
	recordContentTests := setupRecordContentTests(t)
	for _, test := range recordContentTests {
		t.Run(test.description, func(t *testing.T) {
			// Convert token
			token, err := util.ConvertStringToken(rec.Token)
			if err != nil {
				t.Error(err)
			}

			// Make backend call
			_, err = tlogBackend.UpdateUnvettedRecord(token, test.metadata,
				[]backend.MetadataStream{}, test.files, test.filesDel)

			// Parse error
			var contentError backend.ContentVerificationError
			if errors.As(err, &contentError) {
				if contentError.ErrorCode != test.err.ErrorCode {
					t.Errorf("got error %v, want %v",
						v1.ErrorStatus[contentError.ErrorCode],
						v1.ErrorStatus[test.err.ErrorCode])
				}
			}
		})
	}

	// Random png image file to include in edit payload
	imageRandom := newBackendFilePNG(t)

	// test case: Token not full length
	tokenShort, err := util.ConvertStringToken(util.TokenToPrefix(rec.Token))
	if err != nil {
		t.Error(err)
	}

	// test case: Record not found
	tokenRandom := tokenFromTreeID(123)

	// test case: Frozen tree
	recFrozen, err := tlogBackend.New(md, fs)
	if err != nil {
		t.Error(err)
	}
	tokenFrozen, err := tokenDecode(recFrozen.Token)
	if err != nil {
		t.Error(err)
	}
	err = tlogBackend.unvetted.treeFreeze(treeIDFromToken(tokenFrozen),
		backend.RecordMetadata{}, []backend.MetadataStream{}, 0)
	if err != nil {
		t.Error(err)
	}

	// Setup UpdateUnvettedRecord tests
	var tests = []struct {
		description           string
		token                 []byte
		mdAppend, mdOverwrite []backend.MetadataStream
		filesAdd              []backend.File
		filesDel              []string
		wantContentErr        *backend.ContentVerificationError
		wantErr               error
	}{
		{
			"token not full length",
			tokenShort,
			[]backend.MetadataStream{},
			[]backend.MetadataStream{},
			[]backend.File{imageRandom},
			[]string{},
			&backend.ContentVerificationError{
				ErrorCode: v1.ErrorStatusInvalidToken,
			},
			nil,
		},
		{
			"record not found",
			tokenRandom,
			[]backend.MetadataStream{},
			[]backend.MetadataStream{},
			[]backend.File{imageRandom},
			[]string{},
			nil,
			backend.ErrRecordNotFound,
		},
		{
			"tree frozen for changes",
			tokenFrozen,
			[]backend.MetadataStream{},
			[]backend.MetadataStream{},
			[]backend.File{imageRandom},
			[]string{},
			nil,
			backend.ErrRecordLocked,
		},
		{
			"no changes to record",
			token,
			[]backend.MetadataStream{},
			[]backend.MetadataStream{},
			[]backend.File{},
			[]string{},
			nil,
			backend.ErrNoChanges,
		},
		{
			"success",
			token,
			[]backend.MetadataStream{},
			[]backend.MetadataStream{},
			[]backend.File{imageRandom},
			[]string{},
			nil,
			nil,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			// Make backend call
			_, err = tlogBackend.UpdateUnvettedRecord(test.token,
				test.mdAppend, test.mdOverwrite, test.filesAdd, test.filesDel)

			// Parse error
			var contentError backend.ContentVerificationError
			if errors.As(err, &contentError) {
				if test.wantContentErr == nil {
					t.Errorf("got error %v, want nil", err)
					return
				}
				if contentError.ErrorCode != test.wantContentErr.ErrorCode {
					t.Errorf("got error %v, want %v",
						v1.ErrorStatus[contentError.ErrorCode],
						v1.ErrorStatus[test.wantContentErr.ErrorCode])
				}
				return
			}

			if test.wantErr != err {
				t.Errorf("got error %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestUpdateVettedRecord(t *testing.T) {
	tlogBackend, cleanup := newTestTlogBackend(t)
	defer cleanup()

	// Create new record
	md := []backend.MetadataStream{
		newBackendMetadataStream(t, 1, ""),
	}
	fs := []backend.File{
		newBackendFile(t, "index.md"),
	}
	rec, err := tlogBackend.New(md, fs)
	if err != nil {
		t.Error(err)
	}
	token, err := tokenDecode(rec.Token)
	if err != nil {
		t.Error(err)
	}
	md = append(md, newBackendMetadataStream(t, 2, ""))

	// Publish the created record
	err = tlogBackend.unvettedPublish(token, *rec, md, fs)
	if err != nil {
		t.Error(err)
	}

	// Test all record content verification error through the
	// UpdateVettedRecord endpoint
	recordContentTests := setupRecordContentTests(t)
	for _, test := range recordContentTests {
		t.Run(test.description, func(t *testing.T) {
			// Convert token
			token, err := util.ConvertStringToken(rec.Token)
			if err != nil {
				t.Error(err)
			}

			// Make backend call
			_, err = tlogBackend.UpdateVettedRecord(token, test.metadata,
				[]backend.MetadataStream{}, test.files, test.filesDel)

			// Parse error
			var contentError backend.ContentVerificationError
			if errors.As(err, &contentError) {
				if contentError.ErrorCode != test.err.ErrorCode {
					t.Errorf("got error %v, want %v",
						v1.ErrorStatus[contentError.ErrorCode],
						v1.ErrorStatus[test.err.ErrorCode])
				}
			}
		})
	}

	// Random png image file to include in edit payload
	imageRandom := newBackendFilePNG(t)

	// test case: Token not full length
	tokenShort, err := util.ConvertStringToken(util.TokenToPrefix(rec.Token))
	if err != nil {
		t.Error(err)
	}

	// test case: Record not found
	tokenRandom := tokenFromTreeID(123)

	// test case: Frozen tree
	recFrozen, err := tlogBackend.New(md, fs)
	if err != nil {
		t.Error(err)
	}
	tokenFrozen, err := tokenDecode(recFrozen.Token)
	if err != nil {
		t.Error(err)
	}
	md = append(md, newBackendMetadataStream(t, 3, ""))
	err = tlogBackend.unvettedPublish(tokenFrozen, *recFrozen, md, fs)
	if err != nil {
		t.Error(err)
	}
	treeIDFrozenVetted := tlogBackend.vettedTreeIDs[recFrozen.Token]
	err = tlogBackend.vetted.treeFreeze(treeIDFrozenVetted,
		backend.RecordMetadata{}, []backend.MetadataStream{}, 0)
	if err != nil {
		t.Error(err)
	}

	// Setup UpdateVettedRecord tests
	var tests = []struct {
		description           string
		token                 []byte
		mdAppend, mdOverwirte []backend.MetadataStream
		filesAdd              []backend.File
		filesDel              []string
		wantContentErr        *backend.ContentVerificationError
		wantErr               error
	}{
		{
			"token not full length",
			tokenShort,
			[]backend.MetadataStream{},
			[]backend.MetadataStream{},
			[]backend.File{imageRandom},
			[]string{},
			&backend.ContentVerificationError{
				ErrorCode: v1.ErrorStatusInvalidToken,
			},
			nil,
		},
		{
			"record not found",
			tokenRandom,
			[]backend.MetadataStream{},
			[]backend.MetadataStream{},
			[]backend.File{imageRandom},
			[]string{},
			nil,
			backend.ErrRecordNotFound,
		},
		{
			"tree frozen for changes",
			tokenFrozen,
			[]backend.MetadataStream{},
			[]backend.MetadataStream{},
			[]backend.File{imageRandom},
			[]string{},
			nil,
			backend.ErrRecordLocked,
		},
		{
			"no changes to record",
			token,
			[]backend.MetadataStream{},
			[]backend.MetadataStream{},
			[]backend.File{},
			[]string{},
			nil,
			backend.ErrNoChanges,
		},
		{
			"success",
			token,
			[]backend.MetadataStream{},
			[]backend.MetadataStream{},
			[]backend.File{imageRandom},
			[]string{},
			nil,
			nil,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			// Make backend call
			_, err = tlogBackend.UpdateVettedRecord(test.token,
				test.mdAppend, test.mdOverwirte, test.filesAdd, test.filesDel)

			// Parse error
			var contentError backend.ContentVerificationError
			if errors.As(err, &contentError) {
				if test.wantContentErr == nil {
					t.Errorf("got error %v, want nil", err)
					return
				}
				if contentError.ErrorCode != test.wantContentErr.ErrorCode {
					t.Errorf("got error %v, want %v",
						v1.ErrorStatus[contentError.ErrorCode],
						v1.ErrorStatus[test.wantContentErr.ErrorCode])
				}
				return
			}

			if test.wantErr != err {
				t.Errorf("got error %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestUpdateUnvettedMetadata(t *testing.T) {
	tlogBackend, cleanup := newTestTlogBackend(t)
	defer cleanup()

	// Create new record
	md := []backend.MetadataStream{
		newBackendMetadataStream(t, 1, ""),
	}
	fs := []backend.File{
		newBackendFile(t, "index.md"),
	}
	rec, err := tlogBackend.New(md, fs)
	if err != nil {
		t.Error(err)
	}
	token, err := tokenDecode(rec.Token)
	if err != nil {
		t.Error(err)
	}

	// Test all record content verification error through the
	// UpdateUnvettedMetadata endpoint
	recordContentTests := setupRecordContentTests(t)
	for _, test := range recordContentTests {
		t.Run(test.description, func(t *testing.T) {
			// Make backend call
			err := tlogBackend.UpdateUnvettedMetadata(token,
				test.metadata, []backend.MetadataStream{})

			// Parse error
			var contentError backend.ContentVerificationError
			if errors.As(err, &contentError) {
				if contentError.ErrorCode != test.err.ErrorCode {
					t.Errorf("got error %v, want %v",
						v1.ErrorStatus[contentError.ErrorCode],
						v1.ErrorStatus[test.err.ErrorCode])
				}
			}
		})
	}

	// test case: Token not full length
	tokenShort, err := util.ConvertStringToken(util.TokenToPrefix(rec.Token))
	if err != nil {
		t.Error(err)
	}

	// test case: Record not found
	tokenRandom := tokenFromTreeID(123)

	// test case: Frozen tree
	recFrozen, err := tlogBackend.New(md, fs)
	if err != nil {
		t.Error(err)
	}
	tokenFrozen, err := tokenDecode(recFrozen.Token)
	if err != nil {
		t.Error(err)
	}
	err = tlogBackend.unvetted.treeFreeze(treeIDFromToken(tokenFrozen),
		backend.RecordMetadata{}, []backend.MetadataStream{}, 0)
	if err != nil {
		t.Error(err)
	}

	// Setup UpdateUnvettedMetadata tests
	var tests = []struct {
		description           string
		token                 []byte
		mdAppend, mdOverwrite []backend.MetadataStream
		wantContentErr        *backend.ContentVerificationError
		wantErr               error
	}{
		{
			"no changes to record metadata, empty streams",
			token,
			[]backend.MetadataStream{},
			[]backend.MetadataStream{},
			&backend.ContentVerificationError{
				ErrorCode: v1.ErrorStatusNoChanges,
			},
			nil,
		},
		{
			"invalid token",
			tokenShort,
			[]backend.MetadataStream{{
				ID:      2,
				Payload: "random",
			}},
			[]backend.MetadataStream{},
			&backend.ContentVerificationError{
				ErrorCode: v1.ErrorStatusInvalidToken,
			},
			nil,
		},
		{
			"record not found",
			tokenRandom,
			[]backend.MetadataStream{{
				ID:      2,
				Payload: "random",
			}},
			[]backend.MetadataStream{},
			nil,
			backend.ErrRecordNotFound,
		},
		{
			"tree frozen for changes",
			tokenFrozen,
			[]backend.MetadataStream{{
				ID:      2,
				Payload: "random",
			}},
			[]backend.MetadataStream{},
			nil,
			backend.ErrRecordLocked,
		},
		{
			"no changes to record metadata, same payload",
			token,
			[]backend.MetadataStream{},
			[]backend.MetadataStream{{
				ID:      1,
				Payload: "",
			}},
			nil,
			backend.ErrNoChanges,
		},
		{
			"success",
			token,
			[]backend.MetadataStream{},
			[]backend.MetadataStream{{
				ID:      1,
				Payload: "newdata",
			}},
			nil,
			nil,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			// Make backend call
			err = tlogBackend.UpdateUnvettedMetadata(test.token,
				test.mdAppend, test.mdOverwrite)

			// Parse error
			var contentError backend.ContentVerificationError
			if errors.As(err, &contentError) {
				if test.wantContentErr == nil {
					t.Errorf("got error %v, want nil", err)
					return
				}
				if contentError.ErrorCode != test.wantContentErr.ErrorCode {
					t.Errorf("got error %v, want %v",
						v1.ErrorStatus[contentError.ErrorCode],
						v1.ErrorStatus[test.wantContentErr.ErrorCode])
				}
				return
			}

			if test.wantErr != err {
				t.Errorf("got error %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestUpdateVettedMetadata(t *testing.T) {
	tlogBackend, cleanup := newTestTlogBackend(t)
	defer cleanup()

	// Create new record
	md := []backend.MetadataStream{
		newBackendMetadataStream(t, 1, ""),
	}
	fs := []backend.File{
		newBackendFile(t, "index.md"),
	}
	rec, err := tlogBackend.New(md, fs)
	if err != nil {
		t.Error(err)
	}
	token, err := tokenDecode(rec.Token)
	if err != nil {
		t.Error(err)
	}
	md = append(md, newBackendMetadataStream(t, 2, ""))
	err = tlogBackend.unvettedPublish(token, *rec, md, fs)
	if err != nil {
		t.Error(err)
	}

	// Test all record content verification error through the
	// UpdateVettedMetadata endpoint
	recordContentTests := setupRecordContentTests(t)
	for _, test := range recordContentTests {
		t.Run(test.description, func(t *testing.T) {
			// Make backend call
			err := tlogBackend.UpdateVettedMetadata(token,
				test.metadata, []backend.MetadataStream{})

			// Parse error
			var contentError backend.ContentVerificationError
			if errors.As(err, &contentError) {
				if contentError.ErrorCode != test.err.ErrorCode {
					t.Errorf("got error %v, want %v",
						v1.ErrorStatus[contentError.ErrorCode],
						v1.ErrorStatus[test.err.ErrorCode])
				}
			}
		})
	}

	// test case: Token not full length
	tokenShort, err := util.ConvertStringToken(util.TokenToPrefix(rec.Token))
	if err != nil {
		t.Error(err)
	}

	// test case: Record not found
	tokenRandom := tokenFromTreeID(123)

	// test case: Frozen tree
	recFrozen, err := tlogBackend.New(md, fs)
	if err != nil {
		t.Error(err)
	}
	tokenFrozen, err := tokenDecode(recFrozen.Token)
	if err != nil {
		t.Error(err)
	}
	md = append(md, newBackendMetadataStream(t, 3, ""))
	err = tlogBackend.unvettedPublish(tokenFrozen, *recFrozen, md, fs)
	if err != nil {
		t.Error(err)
	}
	treeIDFrozenVetted := tlogBackend.vettedTreeIDs[recFrozen.Token]
	err = tlogBackend.vetted.treeFreeze(treeIDFrozenVetted,
		backend.RecordMetadata{}, []backend.MetadataStream{}, 0)
	if err != nil {
		t.Error(err)
	}

	// Setup UpdateVettedMetadata tests
	var tests = []struct {
		description           string
		token                 []byte
		mdAppend, mdOverwrite []backend.MetadataStream
		wantContentErr        *backend.ContentVerificationError
		wantErr               error
	}{
		{
			"no changes to record metadata, empty streams",
			token,
			[]backend.MetadataStream{},
			[]backend.MetadataStream{},
			&backend.ContentVerificationError{
				ErrorCode: v1.ErrorStatusNoChanges,
			},
			nil,
		},
		{
			"invalid token",
			tokenShort,
			[]backend.MetadataStream{
				newBackendMetadataStream(t, 2, "random"),
			},
			[]backend.MetadataStream{},
			&backend.ContentVerificationError{
				ErrorCode: v1.ErrorStatusInvalidToken,
			},
			nil,
		},
		{
			"record not found",
			tokenRandom,
			[]backend.MetadataStream{
				newBackendMetadataStream(t, 2, "random"),
			},
			[]backend.MetadataStream{},
			nil,
			backend.ErrRecordNotFound,
		},
		{
			"tree frozen for changes",
			tokenFrozen,
			[]backend.MetadataStream{
				newBackendMetadataStream(t, 2, "random"),
			},
			[]backend.MetadataStream{},
			nil,
			backend.ErrRecordLocked,
		},
		{
			"no changes to record metadata, same payload",
			token,
			[]backend.MetadataStream{},
			[]backend.MetadataStream{
				newBackendMetadataStream(t, 2, ""),
			},
			nil,
			backend.ErrNoChanges,
		},
		{
			"success",
			token,
			[]backend.MetadataStream{},
			[]backend.MetadataStream{
				newBackendMetadataStream(t, 1, "newdata"),
			},
			nil,
			nil,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			// Make backend call
			err = tlogBackend.UpdateVettedMetadata(test.token,
				test.mdAppend, test.mdOverwrite)

			// Parse error
			var contentError backend.ContentVerificationError
			if errors.As(err, &contentError) {
				if test.wantContentErr == nil {
					t.Errorf("got error %v, want nil", err)
					return
				}
				if contentError.ErrorCode != test.wantContentErr.ErrorCode {
					t.Errorf("got error %v, want %v",
						v1.ErrorStatus[contentError.ErrorCode],
						v1.ErrorStatus[test.wantContentErr.ErrorCode])
				}
				return
			}

			if test.wantErr != err {
				t.Errorf("got error %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestUnvettedExists(t *testing.T) {
	tlogBackend, cleanup := newTestTlogBackend(t)
	defer cleanup()

	// Create new record
	md := []backend.MetadataStream{
		newBackendMetadataStream(t, 1, ""),
	}
	fs := []backend.File{
		newBackendFile(t, "index.md"),
	}
	rec, err := tlogBackend.New(md, fs)
	if err != nil {
		t.Error(err)
	}
	token, err := tokenDecode(rec.Token)
	if err != nil {
		t.Error(err)
	}

	// Random token
	tokenRandom := tokenFromTreeID(123)

	// Run UnvettedExists test cases
	//
	// Record exists
	result := tlogBackend.UnvettedExists(token)
	if result == false {
		t.Errorf("got false, want true")
	}
	// Record does not exist
	result = tlogBackend.UnvettedExists(tokenRandom)
	if result == true {
		t.Errorf("got true, want false")
	}
}

func TestVettedExists(t *testing.T) {
	tlogBackend, cleanup := newTestTlogBackend(t)
	defer cleanup()

	// Create unvetted record
	md := []backend.MetadataStream{
		newBackendMetadataStream(t, 1, ""),
	}
	fs := []backend.File{
		newBackendFile(t, "index.md"),
	}
	unvetted, err := tlogBackend.New(md, fs)
	if err != nil {
		t.Error(err)
	}
	tokenUnvetted, err := tokenDecode(unvetted.Token)
	if err != nil {
		t.Error(err)
	}

	// Create vetted record
	vetted, err := tlogBackend.New(md, fs)
	if err != nil {
		t.Error(err)
	}
	tokenVetted, err := tokenDecode(vetted.Token)
	if err != nil {
		t.Error(err)
	}
	md = append(md, newBackendMetadataStream(t, 2, ""))
	err = tlogBackend.unvettedPublish(tokenVetted, *vetted, md, fs)
	if err != nil {
		t.Error(err)
	}

	// Run VettedExists test cases
	//
	// Record exists
	result := tlogBackend.VettedExists(tokenVetted)
	if result == false {
		t.Errorf("got false, want true")
	}
	// Record does not exist
	result = tlogBackend.VettedExists(tokenUnvetted)
	if result == true {
		t.Errorf("got true, want false")
	}
}

func TestGetUnvetted(t *testing.T) {
	tlogBackend, cleanup := newTestTlogBackend(t)
	defer cleanup()

	// Create new record
	md := []backend.MetadataStream{
		newBackendMetadataStream(t, 1, ""),
	}
	fs := []backend.File{
		newBackendFile(t, "index.md"),
	}
	rec, err := tlogBackend.New(md, fs)
	if err != nil {
		t.Error(err)
	}
	token, err := tokenDecode(rec.Token)
	if err != nil {
		t.Error(err)
	}

	// Random token
	tokenRandom := tokenFromTreeID(123)

	// Bad version error
	_, err = tlogBackend.GetUnvetted(token, "badversion")
	if err != backend.ErrRecordNotFound {
		t.Errorf("got error %v, want %v", err, backend.ErrRecordNotFound)
	}

	// Bad token error
	_, err = tlogBackend.GetUnvetted(tokenRandom, "")
	if err != backend.ErrRecordNotFound {
		t.Errorf("got error %v, want %v", err, backend.ErrRecordNotFound)
	}

	// Success
	_, err = tlogBackend.GetUnvetted(token, "")
	if err != nil {
		t.Errorf("got error %v, want nil", err)
	}
}

func TestGetVetted(t *testing.T) {
	tlogBackend, cleanup := newTestTlogBackend(t)
	defer cleanup()

	// Create new record
	md := []backend.MetadataStream{
		newBackendMetadataStream(t, 1, ""),
	}
	fs := []backend.File{
		newBackendFile(t, "index.md"),
	}
	rec, err := tlogBackend.New(md, fs)
	if err != nil {
		t.Error(err)
	}
	token, err := tokenDecode(rec.Token)
	if err != nil {
		t.Error(err)
	}
	md = append(md, newBackendMetadataStream(t, 2, ""))
	err = tlogBackend.unvettedPublish(token, *rec, md, fs)
	if err != nil {
		t.Error(err)
	}

	// Random token
	tokenRandom := tokenFromTreeID(123)

	// Bad version error
	_, err = tlogBackend.GetVetted(token, "badversion")
	if err != backend.ErrRecordNotFound {
		t.Errorf("got error %v, want %v", err, backend.ErrRecordNotFound)
	}

	// Bad token error
	_, err = tlogBackend.GetVetted(tokenRandom, "")
	if err != backend.ErrRecordNotFound {
		t.Errorf("got error %v, want %v", err, backend.ErrRecordNotFound)
	}

	// Success
	_, err = tlogBackend.GetVetted(token, "")
	if err != nil {
		t.Errorf("got error %v, want nil", err)
	}
}

func TestSetUnvettedStatus(t *testing.T) {
	tlogBackend, cleanup := newTestTlogBackend(t)
	defer cleanup()

	// Helpers
	md := []backend.MetadataStream{
		newBackendMetadataStream(t, 1, ""),
	}
	fs := []backend.File{
		newBackendFile(t, "index.md"),
	}

	// Invalid status transitions
	//
	// test case: Unvetted to archived
	recUnvetToArch, err := tlogBackend.New(md, fs)
	if err != nil {
		t.Error(err)
	}
	tokenUnvetToArch, err := tokenDecode(recUnvetToArch.Token)
	if err != nil {
		t.Error(err)
	}
	// test case: Unvetted to unvetted
	recUnvetToUnvet, err := tlogBackend.New(md, fs)
	if err != nil {
		t.Error(err)
	}
	tokenUnvetToUnvet, err := tokenDecode(recUnvetToUnvet.Token)
	if err != nil {
		t.Error(err)
	}

	// Valid status transitions
	//
	// test case: Unvetted to vetted
	recUnvetToVet, err := tlogBackend.New(md, fs)
	if err != nil {
		t.Error(err)
	}
	tokenUnvetToVet, err := tokenDecode(recUnvetToVet.Token)
	if err != nil {
		t.Error(err)
	}
	// test case: Unvetted to censored
	recUnvetToCensored, err := tlogBackend.New(md, fs)
	if err != nil {
		t.Error(err)
	}
	tokenUnvetToCensored, err := tokenDecode(recUnvetToCensored.Token)
	if err != nil {
		t.Error(err)
	}

	// test case: Token not full length
	tokenShort, err := util.ConvertStringToken(
		util.TokenToPrefix(recUnvetToVet.Token))
	if err != nil {
		t.Error(err)
	}

	// test case: Record not found
	tokenRandom := tokenFromTreeID(123)

	// Setup SetUnvettedStatus tests
	var tests = []struct {
		description           string
		token                 []byte
		status                backend.MDStatusT
		mdAppend, mdOverwrite []backend.MetadataStream
		wantContentErr        *backend.ContentVerificationError
		wantErr               error
	}{
		{
			"invalid: unvetted to archived",
			tokenUnvetToArch,
			backend.MDStatusArchived,
			[]backend.MetadataStream{},
			[]backend.MetadataStream{},
			nil,
			backend.StateTransitionError{
				From: recUnvetToArch.Status,
				To:   backend.MDStatusArchived,
			},
		},
		{
			"invalid: unvetted to unvetted",
			tokenUnvetToUnvet,
			backend.MDStatusUnvetted,
			[]backend.MetadataStream{},
			[]backend.MetadataStream{},
			nil,
			backend.StateTransitionError{
				From: recUnvetToArch.Status,
				To:   backend.MDStatusUnvetted,
			},
		},
		{
			"valid: unvetted to vetted",
			tokenUnvetToVet,
			backend.MDStatusVetted,
			[]backend.MetadataStream{},
			[]backend.MetadataStream{},
			nil,
			nil,
		},
		{
			"valid: unvetted to censored",
			tokenUnvetToCensored,
			backend.MDStatusCensored,
			[]backend.MetadataStream{},
			[]backend.MetadataStream{},
			nil,
			nil,
		},
		{
			"invalid token",
			tokenShort,
			backend.MDStatusCensored,
			[]backend.MetadataStream{},
			[]backend.MetadataStream{},
			&backend.ContentVerificationError{
				ErrorCode: v1.ErrorStatusInvalidToken,
			},
			nil,
		},
		{
			"record not found",
			tokenRandom,
			backend.MDStatusCensored,
			[]backend.MetadataStream{},
			[]backend.MetadataStream{},
			nil,
			backend.ErrRecordNotFound,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			// Make backend call
			_, err = tlogBackend.SetUnvettedStatus(test.token, test.status,
				test.mdAppend, test.mdOverwrite)

			// Parse error
			var contentError backend.ContentVerificationError
			if errors.As(err, &contentError) {
				if test.wantContentErr == nil {
					t.Errorf("got error %v, want nil", err)
					return
				}
				if contentError.ErrorCode != test.wantContentErr.ErrorCode {
					t.Errorf("got error %v, want %v",
						v1.ErrorStatus[contentError.ErrorCode],
						v1.ErrorStatus[test.wantContentErr.ErrorCode])
				}
				return
			}

			if test.wantErr != err {
				t.Errorf("got error %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestSetVettedStatus(t *testing.T) {
	tlogBackend, cleanup := newTestTlogBackend(t)
	defer cleanup()

	// Helpers
	md := []backend.MetadataStream{
		newBackendMetadataStream(t, 1, ""),
	}
	fs := []backend.File{
		newBackendFile(t, "index.md"),
	}

	// Invalid status transitions
	//
	// test case: Vetted to unvetted
	recVetToUnvet, err := tlogBackend.New(md, fs)
	if err != nil {
		t.Error(err)
	}
	tokenVetToUnvet, err := tokenDecode(recVetToUnvet.Token)
	if err != nil {
		t.Error(err)
	}

	md = append(md, newBackendMetadataStream(t, 2, ""))
	_, err = tlogBackend.SetUnvettedStatus(tokenVetToUnvet,
		backend.MDStatusVetted, md, []backend.MetadataStream{})
	if err != nil {
		t.Error(err)
	}
	// test case: Vetted to vetted
	recVetToVet, err := tlogBackend.New(md, fs)
	if err != nil {
		t.Error(err)
	}
	tokenVetToVet, err := tokenDecode(recVetToVet.Token)
	if err != nil {
		t.Error(err)
	}
	md = append(md, newBackendMetadataStream(t, 3, ""))
	_, err = tlogBackend.SetUnvettedStatus(tokenVetToVet,
		backend.MDStatusVetted, md, []backend.MetadataStream{})
	if err != nil {
		t.Error(err)
	}

	// Valid status transitions
	//
	// test case: Vetted to archived
	recVetToArch, err := tlogBackend.New(md, fs)
	if err != nil {
		t.Error(err)
	}
	tokenVetToArch, err := tokenDecode(recVetToArch.Token)
	if err != nil {
		t.Error(err)
	}
	md = append(md, newBackendMetadataStream(t, 4, ""))
	_, err = tlogBackend.SetUnvettedStatus(tokenVetToArch,
		backend.MDStatusVetted, md, []backend.MetadataStream{})
	if err != nil {
		t.Error(err)
	}
	// test case: Vetted to censored
	recVetToCensored, err := tlogBackend.New(md, fs)
	if err != nil {
		t.Error(err)
	}
	tokenVetToCensored, err := tokenDecode(recVetToCensored.Token)
	if err != nil {
		t.Error(err)
	}
	md = append(md, newBackendMetadataStream(t, 5, ""))
	_, err = tlogBackend.SetUnvettedStatus(tokenVetToCensored,
		backend.MDStatusVetted, md, []backend.MetadataStream{})
	if err != nil {
		t.Error(err)
	}

	// test case: Token not full length
	tokenShort, err := util.ConvertStringToken(
		util.TokenToPrefix(recVetToCensored.Token))
	if err != nil {
		t.Error(err)
	}

	// test case: Record not found
	tokenRandom := tokenFromTreeID(123)

	// Setup SetVettedStatus tests
	var tests = []struct {
		description           string
		token                 []byte
		status                backend.MDStatusT
		mdAppend, mdOverwrite []backend.MetadataStream
		wantContentErr        *backend.ContentVerificationError
		wantErr               error
	}{
		{
			"invalid: vetted to unvetted",
			tokenVetToUnvet,
			backend.MDStatusUnvetted,
			[]backend.MetadataStream{},
			[]backend.MetadataStream{},
			nil,
			backend.StateTransitionError{
				From: backend.MDStatusVetted,
				To:   backend.MDStatusUnvetted,
			},
		},
		{
			"invalid: vetted to vetted",
			tokenVetToVet,
			backend.MDStatusVetted,
			[]backend.MetadataStream{},
			[]backend.MetadataStream{},
			nil,
			backend.StateTransitionError{
				From: backend.MDStatusVetted,
				To:   backend.MDStatusVetted,
			},
		},
		{
			"valid: vetted to archived",
			tokenVetToArch,
			backend.MDStatusArchived,
			[]backend.MetadataStream{},
			[]backend.MetadataStream{},
			nil,
			nil,
		},
		{
			"valid: vetted to censored",
			tokenVetToCensored,
			backend.MDStatusCensored,
			[]backend.MetadataStream{},
			[]backend.MetadataStream{},
			nil,
			nil,
		},
		{
			"invalid token",
			tokenShort,
			backend.MDStatusCensored,
			[]backend.MetadataStream{},
			[]backend.MetadataStream{},
			&backend.ContentVerificationError{
				ErrorCode: v1.ErrorStatusInvalidToken,
			},
			nil,
		},
		{
			"record not found",
			tokenRandom,
			backend.MDStatusCensored,
			[]backend.MetadataStream{},
			[]backend.MetadataStream{},
			nil,
			backend.ErrRecordNotFound,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			// Make backend call
			_, err = tlogBackend.SetVettedStatus(test.token, test.status,
				test.mdAppend, test.mdOverwrite)

			// Parse error
			var contentError backend.ContentVerificationError
			if errors.As(err, &contentError) {
				if test.wantContentErr == nil {
					t.Errorf("got error %v, want nil", err)
					return
				}
				if contentError.ErrorCode != test.wantContentErr.ErrorCode {
					t.Errorf("got error %v, want %v",
						v1.ErrorStatus[contentError.ErrorCode],
						v1.ErrorStatus[test.wantContentErr.ErrorCode])
				}
				return
			}

			if test.wantErr != err {
				t.Errorf("got error %v, want %v", err, test.wantErr)
			}
		})
	}
}
