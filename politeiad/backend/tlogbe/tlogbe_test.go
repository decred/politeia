// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlogbe

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"image"
	"image/jpeg"
	"image/png"
	"testing"

	v1 "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/api/v1/mime"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/util"
)

func newBackendFile(t *testing.T, fileName string) backend.File {
	t.Helper()

	r, err := util.Random(64)
	if err != nil {
		r = []byte{0, 0, 0} // random byte data
	}

	payload := hex.EncodeToString(r)
	digest := hex.EncodeToString(util.Digest([]byte(payload)))
	b64 := base64.StdEncoding.EncodeToString([]byte(payload))

	return backend.File{
		Name:    fileName,
		MIME:    mime.DetectMimeType([]byte(payload)),
		Digest:  digest,
		Payload: b64,
	}
}

func newBackendFileJPEG(t *testing.T) backend.File {
	t.Helper()

	b := new(bytes.Buffer)
	img := image.NewRGBA(image.Rect(0, 0, 1000, 500))

	err := jpeg.Encode(b, img, &jpeg.Options{})
	if err != nil {
		t.Fatal(err)
	}

	// Generate a random name
	r, err := util.Random(8)
	if err != nil {
		t.Fatal(err)
	}

	return backend.File{
		Name:    hex.EncodeToString(r) + ".jpeg",
		MIME:    mime.DetectMimeType(b.Bytes()),
		Digest:  hex.EncodeToString(util.Digest(b.Bytes())),
		Payload: base64.StdEncoding.EncodeToString(b.Bytes()),
	}
}

func newBackendFilePNG(t *testing.T) backend.File {
	t.Helper()

	b := new(bytes.Buffer)
	img := image.NewRGBA(image.Rect(0, 0, 1000, 500))

	err := png.Encode(b, img)
	if err != nil {
		t.Fatal(err)
	}

	// Generate a random name
	r, err := util.Random(8)
	if err != nil {
		t.Fatal(err)
	}

	return backend.File{
		Name:    hex.EncodeToString(r) + ".png",
		MIME:    mime.DetectMimeType(b.Bytes()),
		Digest:  hex.EncodeToString(util.Digest(b.Bytes())),
		Payload: base64.StdEncoding.EncodeToString(b.Bytes()),
	}
}

func newBackendMetadataStream(t *testing.T, id uint64, payload string) backend.MetadataStream {
	t.Helper()

	return backend.MetadataStream{
		ID:      id,
		Payload: payload,
	}
}

// recordContentTests defines the type used to describe the content
// verification error tests.
type recordContentTest struct {
	description string
	metadata    []backend.MetadataStream
	files       []backend.File
	filesDel    []string
	err         backend.ContentVerificationError
}

// setupRecordContentTests returns the list of tests for the verifyContent
// function. These tests are used on all backend api endpoints that verify
// content.
func setupRecordContentTests(t *testing.T) []recordContentTest {
	t.Helper()

	var rct []recordContentTest

	// Invalid metadata ID error
	md := []backend.MetadataStream{
		newBackendMetadataStream(t, v1.MetadataStreamsMax+1, ""),
	}
	fs := []backend.File{
		newBackendFile(t, "index.md"),
	}
	fsDel := []string{}
	err := backend.ContentVerificationError{
		ErrorCode: v1.ErrorStatusInvalidMDID,
	}
	rct = append(rct, recordContentTest{
		description: "Invalid metadata ID error",
		metadata:    md,
		files:       fs,
		filesDel:    fsDel,
		err:         err,
	})

	// Duplicate metadata ID error
	md = []backend.MetadataStream{
		newBackendMetadataStream(t, 1, ""),
		newBackendMetadataStream(t, 1, ""),
	}
	fs = []backend.File{
		newBackendFile(t, "index.md"),
	}
	err = backend.ContentVerificationError{
		ErrorCode: v1.ErrorStatusDuplicateMDID,
	}
	rct = append(rct, recordContentTest{
		description: "Duplicate metadata ID error",
		metadata:    md,
		files:       fs,
		filesDel:    fsDel,
		err:         err,
	})

	// Invalid filename error
	md = []backend.MetadataStream{
		newBackendMetadataStream(t, 1, ""),
	}
	fs = []backend.File{
		newBackendFile(t, "invalid/filename.md"),
	}
	err = backend.ContentVerificationError{
		ErrorCode: v1.ErrorStatusInvalidFilename,
	}
	rct = append(rct, recordContentTest{
		description: "Invalid filename error",
		metadata:    md,
		files:       fs,
		filesDel:    fsDel,
		err:         err,
	})

	// Invalid filename in filesDel error
	md = []backend.MetadataStream{
		newBackendMetadataStream(t, 1, ""),
	}
	fs = []backend.File{
		newBackendFile(t, "index.md"),
	}
	fsDel = []string{"invalid/filename.md"}
	err = backend.ContentVerificationError{
		ErrorCode: v1.ErrorStatusInvalidFilename,
	}
	rct = append(rct, recordContentTest{
		description: "Invalid filename in filesDel error",
		metadata:    md,
		files:       fs,
		filesDel:    fsDel,
		err:         err,
	})

	// Empty files error
	md = []backend.MetadataStream{
		newBackendMetadataStream(t, 1, ""),
	}
	fs = []backend.File{}
	fsDel = []string{}
	err = backend.ContentVerificationError{
		ErrorCode: v1.ErrorStatusEmpty,
	}
	rct = append(rct, recordContentTest{
		description: "Empty files error",
		metadata:    md,
		files:       fs,
		filesDel:    fsDel,
		err:         err,
	})

	// Duplicate filename error
	md = []backend.MetadataStream{
		newBackendMetadataStream(t, 1, ""),
	}
	fs = []backend.File{
		newBackendFile(t, "index.md"),
		newBackendFile(t, "index.md"),
	}
	err = backend.ContentVerificationError{
		ErrorCode: v1.ErrorStatusDuplicateFilename,
	}
	rct = append(rct, recordContentTest{
		description: "Duplicate filename error",
		metadata:    md,
		files:       fs,
		filesDel:    fsDel,
		err:         err,
	})

	// Duplicate filename in filesDel error
	md = []backend.MetadataStream{
		newBackendMetadataStream(t, 1, ""),
	}
	fs = []backend.File{
		newBackendFile(t, "index.md"),
	}
	fsDel = []string{
		"duplicate.md",
		"duplicate.md",
	}
	err = backend.ContentVerificationError{
		ErrorCode: v1.ErrorStatusDuplicateFilename,
	}
	rct = append(rct, recordContentTest{
		description: "Duplicate filename in filesDel error",
		metadata:    md,
		files:       fs,
		filesDel:    fsDel,
		err:         err,
	})

	// Invalid file digest error
	md = []backend.MetadataStream{
		newBackendMetadataStream(t, 1, ""),
	}
	fs = []backend.File{
		newBackendFile(t, "index.md"),
	}
	fsDel = []string{}
	err = backend.ContentVerificationError{
		ErrorCode: v1.ErrorStatusInvalidFileDigest,
	}
	rct = append(rct, recordContentTest{
		description: "Invalid file digest error",
		metadata:    md,
		files:       fs,
		filesDel:    fsDel,
		err:         err,
	})

	// Invalid base64 error
	md = []backend.MetadataStream{
		newBackendMetadataStream(t, 1, ""),
	}
	f := newBackendFile(t, "index.md")
	f.Payload = "*"
	fs = []backend.File{f}
	err = backend.ContentVerificationError{
		ErrorCode: v1.ErrorStatusInvalidBase64,
	}
	rct = append(rct, recordContentTest{
		description: "Invalid file digest error",
		metadata:    md,
		files:       fs,
		filesDel:    fsDel,
		err:         err,
	})

	// Invalid payload digest error
	md = []backend.MetadataStream{
		newBackendMetadataStream(t, 1, ""),
	}
	f = newBackendFile(t, "index.md")
	f.Payload = "rand"
	fs = []backend.File{f}
	err = backend.ContentVerificationError{
		ErrorCode: v1.ErrorStatusInvalidFileDigest,
	}
	rct = append(rct, recordContentTest{
		description: "Invalid payload digest error",
		metadata:    md,
		files:       fs,
		filesDel:    fsDel,
		err:         err,
	})

	// Invalid MIME type from payload error
	md = []backend.MetadataStream{
		newBackendMetadataStream(t, 1, ""),
	}
	jpeg := newBackendFileJPEG(t)
	jpeg.Payload = "rand"
	payload, er := base64.StdEncoding.DecodeString(jpeg.Payload)
	if er != nil {
		t.Fatalf(er.Error())
	}
	jpeg.Digest = hex.EncodeToString(util.Digest(payload))
	fs = []backend.File{
		newBackendFile(t, "index.md"),
		jpeg,
	}
	err = backend.ContentVerificationError{
		ErrorCode: v1.ErrorStatusInvalidMIMEType,
	}
	rct = append(rct, recordContentTest{
		description: "Invalid MIME type from payload error",
		metadata:    md,
		files:       fs,
		filesDel:    fsDel,
		err:         err,
	})

	// Unsupported MIME type error
	md = []backend.MetadataStream{
		newBackendMetadataStream(t, 1, ""),
	}
	jpeg = newBackendFileJPEG(t)
	fs = []backend.File{
		newBackendFile(t, "index.md"),
		jpeg,
	}
	err = backend.ContentVerificationError{
		ErrorCode: v1.ErrorStatusUnsupportedMIMEType,
	}
	rct = append(rct, recordContentTest{
		description: "Unsupported MIME type error",
		metadata:    md,
		files:       fs,
		filesDel:    fsDel,
		err:         err,
	})

	return rct
}

func TestNewRecord(t *testing.T) {
	tlogBackend, cleanup := NewTestTlogBackend(t)
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
	tlogBackend, cleanup := NewTestTlogBackend(t)
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
		t.Fatal(err)
	}
	token, err := tokenDecode(rec.Token)
	if err != nil {
		t.Fatal(err)
	}

	// Test all record content verification error through the
	// UpdateUnvettedRecord endpoint
	recordContentTests := setupRecordContentTests(t)
	for _, test := range recordContentTests {
		t.Run(test.description, func(t *testing.T) {
			// Convert token
			token, err := tokenDecodeAnyLength(rec.Token)
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
	tokenShort, err := tokenDecodeAnyLength(util.TokenToPrefix(rec.Token))
	if err != nil {
		t.Fatal(err)
	}

	// test case: Record not found
	tokenRandom := tokenFromTreeID(123)

	// test case: Frozen tree
	recFrozen, err := tlogBackend.New(md, fs)
	if err != nil {
		t.Fatal(err)
	}
	tokenFrozen, err := tokenDecode(recFrozen.Token)
	if err != nil {
		t.Fatal(err)
	}
	err = tlogBackend.unvetted.treeFreeze(treeIDFromToken(tokenFrozen),
		backend.RecordMetadata{}, []backend.MetadataStream{}, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Setup UpdateUnvettedRecord tests
	var tests = []struct {
		description           string
		token                 []byte
		mdAppend, mdOverwrite []backend.MetadataStream
		filesAdd              []backend.File
		filesDel              []string
		wantContentErr        error
		wantErr               error
	}{
		{
			"token not full length",
			tokenShort,
			[]backend.MetadataStream{},
			[]backend.MetadataStream{},
			[]backend.File{imageRandom},
			[]string{},
			backend.ContentVerificationError{
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
				wantContentErr :=
					test.wantContentErr.(backend.ContentVerificationError)
				if contentError.ErrorCode != wantContentErr.ErrorCode {
					t.Errorf("got error %v, want %v",
						v1.ErrorStatus[contentError.ErrorCode],
						v1.ErrorStatus[wantContentErr.ErrorCode])
				}
				return
			}

			// Expecting content error, but got none
			if test.wantContentErr != nil {
				t.Errorf("got error %v, want %v", err, test.wantContentErr)
			}

			// Expectations not met
			if test.wantErr != err {
				t.Errorf("got error %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestUpdateVettedRecord(t *testing.T) {
	tlogBackend, cleanup := NewTestTlogBackend(t)
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
		t.Fatal(err)
	}
	token, err := tokenDecode(rec.Token)
	if err != nil {
		t.Fatal(err)
	}
	md = append(md, newBackendMetadataStream(t, 2, ""))

	// Publish the created record
	err = tlogBackend.unvettedPublish(token, *rec, md, fs)
	if err != nil {
		t.Fatal(err)
	}

	// Test all record content verification error through the
	// UpdateVettedRecord endpoint
	recordContentTests := setupRecordContentTests(t)
	for _, test := range recordContentTests {
		t.Run(test.description, func(t *testing.T) {
			// Convert token
			token, err := tokenDecodeAnyLength(rec.Token)
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
	tokenShort, err := tokenDecodeAnyLength(util.TokenToPrefix(rec.Token))
	if err != nil {
		t.Error(err)
	}

	// test case: Record not found
	tokenRandom := tokenFromTreeID(123)

	// test case: Frozen tree
	recFrozen, err := tlogBackend.New(md, fs)
	if err != nil {
		t.Fatal(err)
	}
	tokenFrozen, err := tokenDecode(recFrozen.Token)
	if err != nil {
		t.Fatal(err)
	}
	md = append(md, newBackendMetadataStream(t, 3, ""))
	err = tlogBackend.unvettedPublish(tokenFrozen, *recFrozen, md, fs)
	if err != nil {
		t.Fatal(err)
	}
	treeIDFrozenVetted := tlogBackend.vettedTreeIDs[recFrozen.Token]
	err = tlogBackend.vetted.treeFreeze(treeIDFrozenVetted,
		backend.RecordMetadata{}, []backend.MetadataStream{}, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Setup UpdateVettedRecord tests
	var tests = []struct {
		description           string
		token                 []byte
		mdAppend, mdOverwirte []backend.MetadataStream
		filesAdd              []backend.File
		filesDel              []string
		wantContentErr        error
		wantErr               error
	}{
		{
			"token not full length",
			tokenShort,
			[]backend.MetadataStream{},
			[]backend.MetadataStream{},
			[]backend.File{imageRandom},
			[]string{},
			backend.ContentVerificationError{
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
				wantContentErr :=
					test.wantContentErr.(backend.ContentVerificationError)
				if contentError.ErrorCode != wantContentErr.ErrorCode {
					t.Errorf("got error %v, want %v",
						v1.ErrorStatus[contentError.ErrorCode],
						v1.ErrorStatus[wantContentErr.ErrorCode])
				}
				return
			}

			// Expecting content error, but got none
			if test.wantContentErr != nil {
				t.Errorf("got error %v, want %v", err, test.wantContentErr)
			}

			// Expectations not met
			if test.wantErr != err {
				t.Errorf("got error %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestUpdateUnvettedMetadata(t *testing.T) {
	tlogBackend, cleanup := NewTestTlogBackend(t)
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
		t.Fatal(err)
	}
	token, err := tokenDecode(rec.Token)
	if err != nil {
		t.Fatal(err)
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
	tokenShort, err := tokenDecodeAnyLength(util.TokenToPrefix(rec.Token))
	if err != nil {
		t.Fatal(err)
	}

	// test case: Record not found
	tokenRandom := tokenFromTreeID(123)

	// test case: Frozen tree
	recFrozen, err := tlogBackend.New(md, fs)
	if err != nil {
		t.Fatal(err)
	}
	tokenFrozen, err := tokenDecode(recFrozen.Token)
	if err != nil {
		t.Fatal(err)
	}
	err = tlogBackend.unvetted.treeFreeze(treeIDFromToken(tokenFrozen),
		backend.RecordMetadata{}, []backend.MetadataStream{}, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Setup UpdateUnvettedMetadata tests
	var tests = []struct {
		description           string
		token                 []byte
		mdAppend, mdOverwrite []backend.MetadataStream
		wantContentErr        error
		wantErr               error
	}{
		{
			"no changes to record metadata, empty streams",
			token,
			[]backend.MetadataStream{},
			[]backend.MetadataStream{},
			backend.ContentVerificationError{
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
			backend.ContentVerificationError{
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
				wantContentErr :=
					test.wantContentErr.(backend.ContentVerificationError)
				if contentError.ErrorCode != wantContentErr.ErrorCode {
					t.Errorf("got error %v, want %v",
						v1.ErrorStatus[contentError.ErrorCode],
						v1.ErrorStatus[wantContentErr.ErrorCode])
				}
				return
			}

			// Expecting content error, but got none
			if test.wantContentErr != nil {
				t.Errorf("got error %v, want %v", err, test.wantContentErr)
			}

			// Expectations not met
			if test.wantErr != err {
				t.Errorf("got error %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestUpdateVettedMetadata(t *testing.T) {
	tlogBackend, cleanup := NewTestTlogBackend(t)
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
		t.Fatal(err)
	}
	token, err := tokenDecode(rec.Token)
	if err != nil {
		t.Fatal(err)
	}
	md = append(md, newBackendMetadataStream(t, 2, ""))
	err = tlogBackend.unvettedPublish(token, *rec, md, fs)
	if err != nil {
		t.Fatal(err)
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
	tokenShort, err := tokenDecodeAnyLength(util.TokenToPrefix(rec.Token))
	if err != nil {
		t.Fatal(err)
	}

	// test case: Record not found
	tokenRandom := tokenFromTreeID(123)

	// test case: Frozen tree
	recFrozen, err := tlogBackend.New(md, fs)
	if err != nil {
		t.Fatal(err)
	}
	tokenFrozen, err := tokenDecode(recFrozen.Token)
	if err != nil {
		t.Fatal(err)
	}
	md = append(md, newBackendMetadataStream(t, 3, ""))
	err = tlogBackend.unvettedPublish(tokenFrozen, *recFrozen, md, fs)
	if err != nil {
		t.Fatal(err)
	}
	treeIDFrozenVetted := tlogBackend.vettedTreeIDs[recFrozen.Token]
	err = tlogBackend.vetted.treeFreeze(treeIDFrozenVetted,
		backend.RecordMetadata{}, []backend.MetadataStream{}, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Setup UpdateVettedMetadata tests
	var tests = []struct {
		description           string
		token                 []byte
		mdAppend, mdOverwrite []backend.MetadataStream
		wantContentErr        error
		wantErr               error
	}{
		{
			"no changes to record metadata, empty streams",
			token,
			[]backend.MetadataStream{},
			[]backend.MetadataStream{},
			backend.ContentVerificationError{
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
			backend.ContentVerificationError{
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
				wantContentErr :=
					test.wantContentErr.(backend.ContentVerificationError)
				if contentError.ErrorCode != wantContentErr.ErrorCode {
					t.Errorf("got error %v, want %v",
						v1.ErrorStatus[contentError.ErrorCode],
						v1.ErrorStatus[wantContentErr.ErrorCode])
				}
				return
			}

			// Expecting content error, but got none
			if test.wantContentErr != nil {
				t.Errorf("got error %v, want %v", err, test.wantContentErr)
			}

			// Expectations not met
			if test.wantErr != err {
				t.Errorf("got error %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestUnvettedExists(t *testing.T) {
	tlogBackend, cleanup := NewTestTlogBackend(t)
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
		t.Fatal(err)
	}
	token, err := tokenDecode(rec.Token)
	if err != nil {
		t.Fatal(err)
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
	tlogBackend, cleanup := NewTestTlogBackend(t)
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
		t.Fatal(err)
	}
	tokenUnvetted, err := tokenDecode(unvetted.Token)
	if err != nil {
		t.Fatal(err)
	}

	// Create vetted record
	vetted, err := tlogBackend.New(md, fs)
	if err != nil {
		t.Fatal(err)
	}
	tokenVetted, err := tokenDecode(vetted.Token)
	if err != nil {
		t.Fatal(err)
	}
	md = append(md, newBackendMetadataStream(t, 2, ""))
	err = tlogBackend.unvettedPublish(tokenVetted, *vetted, md, fs)
	if err != nil {
		t.Fatal(err)
	}

	// Run VettedExists test cases
	//
	// Record exists
	result := tlogBackend.VettedExists(tokenVetted)
	if result == false {
		t.Fatal("got false, want true")
	}
	// Record does not exist
	result = tlogBackend.VettedExists(tokenUnvetted)
	if result == true {
		t.Fatal("got true, want false")
	}
}

func TestGetUnvetted(t *testing.T) {
	tlogBackend, cleanup := NewTestTlogBackend(t)
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
		t.Fatal(err)
	}
	token, err := tokenDecode(rec.Token)
	if err != nil {
		t.Fatal(err)
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
	tlogBackend, cleanup := NewTestTlogBackend(t)
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
		t.Fatal(err)
	}
	token, err := tokenDecode(rec.Token)
	if err != nil {
		t.Fatal(err)
	}
	md = append(md, newBackendMetadataStream(t, 2, ""))
	err = tlogBackend.unvettedPublish(token, *rec, md, fs)
	if err != nil {
		t.Fatal(err)
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
	tlogBackend, cleanup := NewTestTlogBackend(t)
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
		t.Fatal(err)
	}
	tokenUnvetToArch, err := tokenDecode(recUnvetToArch.Token)
	if err != nil {
		t.Fatal(err)
	}
	// test case: Unvetted to unvetted
	recUnvetToUnvet, err := tlogBackend.New(md, fs)
	if err != nil {
		t.Fatal(err)
	}
	tokenUnvetToUnvet, err := tokenDecode(recUnvetToUnvet.Token)
	if err != nil {
		t.Fatal(err)
	}

	// Valid status transitions
	//
	// test case: Unvetted to vetted
	recUnvetToVet, err := tlogBackend.New(md, fs)
	if err != nil {
		t.Fatal(err)
	}
	tokenUnvetToVet, err := tokenDecode(recUnvetToVet.Token)
	if err != nil {
		t.Fatal(err)
	}
	// test case: Unvetted to censored
	recUnvetToCensored, err := tlogBackend.New(md, fs)
	if err != nil {
		t.Fatal(err)
	}
	tokenUnvetToCensored, err := tokenDecode(recUnvetToCensored.Token)
	if err != nil {
		t.Fatal(err)
	}

	// test case: Token not full length
	tokenShort, err := tokenDecodeAnyLength(
		util.TokenToPrefix(recUnvetToVet.Token))
	if err != nil {
		t.Fatal(err)
	}

	// test case: Record not found
	tokenRandom := tokenFromTreeID(123)

	// Setup SetUnvettedStatus tests
	var tests = []struct {
		description           string
		token                 []byte
		status                backend.MDStatusT
		mdAppend, mdOverwrite []backend.MetadataStream
		wantContentErr        error
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
			backend.ContentVerificationError{
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
				wantContentErr :=
					test.wantContentErr.(backend.ContentVerificationError)
				if contentError.ErrorCode != wantContentErr.ErrorCode {
					t.Errorf("got error %v, want %v",
						v1.ErrorStatus[contentError.ErrorCode],
						v1.ErrorStatus[wantContentErr.ErrorCode])
				}
				return
			}

			// Expecting content error, but got none
			if test.wantContentErr != nil {
				t.Errorf("got error %v, want %v", err, test.wantContentErr)
			}

			// Expectations not met
			if test.wantErr != err {
				t.Errorf("got error %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestSetVettedStatus(t *testing.T) {
	tlogBackend, cleanup := NewTestTlogBackend(t)
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
		t.Fatal(err)
	}
	tokenVetToUnvet, err := tokenDecode(recVetToUnvet.Token)
	if err != nil {
		t.Fatal(err)
	}

	md = append(md, newBackendMetadataStream(t, 2, ""))
	_, err = tlogBackend.SetUnvettedStatus(tokenVetToUnvet,
		backend.MDStatusVetted, md, []backend.MetadataStream{})
	if err != nil {
		t.Fatal(err)
	}
	// test case: Vetted to vetted
	recVetToVet, err := tlogBackend.New(md, fs)
	if err != nil {
		t.Fatal(err)
	}
	tokenVetToVet, err := tokenDecode(recVetToVet.Token)
	if err != nil {
		t.Fatal(err)
	}
	md = append(md, newBackendMetadataStream(t, 3, ""))
	_, err = tlogBackend.SetUnvettedStatus(tokenVetToVet,
		backend.MDStatusVetted, md, []backend.MetadataStream{})
	if err != nil {
		t.Fatal(err)
	}

	// Valid status transitions
	//
	// test case: Vetted to archived
	recVetToArch, err := tlogBackend.New(md, fs)
	if err != nil {
		t.Fatal(err)
	}
	tokenVetToArch, err := tokenDecode(recVetToArch.Token)
	if err != nil {
		t.Fatal(err)
	}
	md = append(md, newBackendMetadataStream(t, 4, ""))
	_, err = tlogBackend.SetUnvettedStatus(tokenVetToArch,
		backend.MDStatusVetted, md, []backend.MetadataStream{})
	if err != nil {
		t.Fatal(err)
	}
	// test case: Vetted to censored
	recVetToCensored, err := tlogBackend.New(md, fs)
	if err != nil {
		t.Fatal(err)
	}
	tokenVetToCensored, err := tokenDecode(recVetToCensored.Token)
	if err != nil {
		t.Fatal(err)
	}
	md = append(md, newBackendMetadataStream(t, 5, ""))
	_, err = tlogBackend.SetUnvettedStatus(tokenVetToCensored,
		backend.MDStatusVetted, md, []backend.MetadataStream{})
	if err != nil {
		t.Fatal(err)
	}

	// test case: Token not full length
	tokenShort, err := tokenDecodeAnyLength(
		util.TokenToPrefix(recVetToCensored.Token))
	if err != nil {
		t.Fatal(err)
	}

	// test case: Record not found
	tokenRandom := tokenFromTreeID(123)

	// Setup SetVettedStatus tests
	var tests = []struct {
		description           string
		token                 []byte
		status                backend.MDStatusT
		mdAppend, mdOverwrite []backend.MetadataStream
		wantContentErr        error
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
			backend.ContentVerificationError{
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
				wantContentErr :=
					test.wantContentErr.(backend.ContentVerificationError)
				if contentError.ErrorCode != wantContentErr.ErrorCode {
					t.Errorf("got error %v, want %v",
						v1.ErrorStatus[contentError.ErrorCode],
						v1.ErrorStatus[wantContentErr.ErrorCode])
				}
				return
			}

			// Expecting content error, but got none
			if test.wantContentErr != nil {
				t.Errorf("got error %v, want %v", err, test.wantContentErr)
			}

			// Expectations not met
			if test.wantErr != err {
				t.Errorf("got error %v, want %v", err, test.wantErr)
			}
		})
	}
}
