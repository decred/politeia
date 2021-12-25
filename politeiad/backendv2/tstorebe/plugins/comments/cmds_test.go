// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package comments

import (
	"encoding/hex"
	"encoding/json"
	"strconv"
	"testing"

	"github.com/decred/politeia/politeiad/api/v1/identity"
	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/plugins/comments"
	"github.com/decred/politeia/politeiad/plugins/pi"
	"github.com/pkg/errors"
)

func TestCmdEdit(t *testing.T) {
	// Setup comments plugin
	c, cleanup := newTestCommentsPlugin(t)
	defer cleanup()

	// Setup an identity that will be used to create the payload
	// signatures.
	fid, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}

	// Setup test data
	var (
		// Valid input
		token         = "45154fb45664714b"
		userID        = "6dc1c8ca-abb5-4631-8ed4-f991b0169770"
		state         = comments.RecordStateVetted
		parentID      = uint32(0)
		commentID     = uint32(1)
		comment       = "comment"
		extraData     = ""
		extraDataHint = ""
		publicKey     = fid.Public.String()

		msg = strconv.FormatUint(uint64(state), 10) + token +
			strconv.FormatUint(uint64(parentID), 10) +
			strconv.FormatUint(uint64(commentID), 10) +
			comment + extraData + extraDataHint
		signatureb = fid.SignMessage([]byte(msg))
		signature  = hex.EncodeToString(signatureb[:])

		// signatureIsWrong is a valid hex encoded, ed25519 signature,
		// but that does not correspond to the valid input parameters
		// listed above.
		signatureIsWrong = "b387f678e1236ca1784c4bc77912c754c6b122dd8b" +
			"3e499617706dd0bd09167a113e59339d2ce4b3570af37a092ba88f39e7f" +
			"c93a5ac7513e52dca3e5e13f705"
	)
	tokenb, err := hex.DecodeString(token)
	if err != nil {
		t.Fatal(err)
	}

	// Setup tests
	var tests = []struct {
		name       string // Test name
		token      []byte
		e          comments.Edit
		allowEdits bool
		err        error // Expected error output
	}{
		{
			"comment edits not allowed",
			tokenb,
			edit(t, fid,
				comments.Edit{
					UserID:        userID,
					State:         state,
					Token:         token,
					ParentID:      parentID,
					CommentID:     commentID,
					Comment:       comment,
					ExtraData:     extraData,
					ExtraDataHint: extraDataHint,
				}),
			false,
			pluginError(comments.ErrorCodeEditsNotAllowed),
		},
		{
			"payload token invalid",
			tokenb,
			edit(t, fid,
				comments.Edit{
					UserID:        userID,
					State:         state,
					Token:         "invalid-token",
					ParentID:      parentID,
					CommentID:     commentID,
					Comment:       comment,
					ExtraData:     extraData,
					ExtraDataHint: extraDataHint,
				}),
			true,
			pluginError(comments.ErrorCodeTokenInvalid),
		},
		{
			"payload token does not match cmd token",
			tokenb,
			edit(t, fid,
				comments.Edit{
					UserID:        userID,
					State:         state,
					Token:         "da70d0766348340c",
					ParentID:      parentID,
					CommentID:     commentID,
					Comment:       comment,
					ExtraData:     extraData,
					ExtraDataHint: extraDataHint,
				}),
			true,
			pluginError(comments.ErrorCodeTokenInvalid),
		},
		{
			"signature is not hex",
			tokenb,
			comments.Edit{
				UserID:        userID,
				State:         state,
				Token:         token,
				ParentID:      parentID,
				CommentID:     commentID,
				Comment:       comment,
				ExtraData:     extraData,
				ExtraDataHint: extraDataHint,
				PublicKey:     publicKey,
				Signature:     "zzz",
			},
			true,
			pluginError(comments.ErrorCodeSignatureInvalid),
		},
		{
			"signature is the wrong size",
			tokenb,
			comments.Edit{
				UserID:        userID,
				State:         state,
				Token:         token,
				ParentID:      parentID,
				CommentID:     commentID,
				Comment:       comment,
				ExtraData:     extraData,
				ExtraDataHint: extraDataHint,
				PublicKey:     publicKey,
				Signature:     "123456",
			},
			true,
			pluginError(comments.ErrorCodeSignatureInvalid),
		},
		{
			"signature is wrong",
			tokenb,
			comments.Edit{
				UserID:        userID,
				State:         state,
				Token:         token,
				ParentID:      parentID,
				CommentID:     commentID,
				Comment:       comment,
				ExtraData:     extraData,
				ExtraDataHint: extraDataHint,
				PublicKey:     publicKey,
				Signature:     signatureIsWrong,
			},
			true,
			pluginError(comments.ErrorCodeSignatureInvalid),
		},
		{
			"public key is not a hex",
			tokenb,
			comments.Edit{
				UserID:        userID,
				State:         state,
				Token:         token,
				ParentID:      parentID,
				CommentID:     commentID,
				Comment:       comment,
				ExtraData:     extraData,
				ExtraDataHint: extraDataHint,
				PublicKey:     "",
				Signature:     signature,
			},
			true,
			pluginError(comments.ErrorCodePublicKeyInvalid),
		},
		{
			"public key is the wrong length",
			tokenb,
			comments.Edit{
				UserID:        userID,
				State:         state,
				Token:         token,
				ParentID:      parentID,
				CommentID:     commentID,
				Comment:       comment,
				ExtraData:     extraData,
				ExtraDataHint: extraDataHint,
				PublicKey:     "123456",
				Signature:     signature,
			},
			true,
			pluginError(comments.ErrorCodePublicKeyInvalid),
		},
	}

	// Run tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup command payload
			b, err := json.Marshal(tc.e)
			if err != nil {
				t.Fatal(err)
			}
			payload := string(b)

			// Decode the expected error into a PluginError. If
			// an error is being returned it should always be a
			// PluginError.
			var wantErrorCode comments.ErrorCodeT
			if tc.err != nil {
				var pe backend.PluginError
				if !errors.As(tc.err, &pe) {
					t.Fatalf("error is not a plugin error '%v'", tc.err)
				}
				wantErrorCode = comments.ErrorCodeT(pe.ErrorCode)
			}

			// Run test
			c.allowEdits = tc.allowEdits
			_, err = c.cmdEdit(tc.token, payload)
			switch {
			case tc.err != nil && err == nil:
				// Wanted an error but didn't get one
				t.Errorf("want error '%v', got nil",
					comments.ErrorCodes[wantErrorCode])
				return

			case tc.err == nil && err != nil:
				// Wanted success but got an error
				t.Errorf("want error nil, got '%v'", err)
				return

			case tc.err != nil && err != nil:
				// Wanted an error and got an error. Verify that it's
				// the correct error. All errors should be backend
				// plugin errors.
				var gotErr backend.PluginError
				if !errors.As(err, &gotErr) {
					t.Errorf("want plugin error, got '%v'", err)
					return
				}
				if comments.PluginID != gotErr.PluginID {
					t.Errorf("want plugin error with plugin ID '%v', got '%v'",
						pi.PluginID, gotErr.PluginID)
					return
				}

				gotErrorCode := comments.ErrorCodeT(gotErr.ErrorCode)
				if wantErrorCode != gotErrorCode {
					t.Errorf("want error '%v', got '%v'",
						comments.ErrorCodes[wantErrorCode],
						comments.ErrorCodes[gotErrorCode])
				}

				// Success; continue to next test
				return

			case tc.err == nil && err == nil:
				// Success; continue to next test
				return
			}
		})
	}
}

// edit uses the provided arguments to return an Edit command
// with a valid PublicKey and Signature.
func edit(t *testing.T, fid *identity.FullIdentity, e comments.Edit) comments.Edit {
	t.Helper()

	msg := strconv.FormatUint(uint64(e.State), 10) + e.Token +
		strconv.FormatUint(uint64(e.ParentID), 10) +
		strconv.FormatUint(uint64(e.CommentID), 10) +
		e.Comment + e.ExtraData + e.ExtraDataHint
	sig := fid.SignMessage([]byte(msg))

	return comments.Edit{
		UserID:        e.UserID,
		State:         e.State,
		Token:         e.Token,
		ParentID:      e.ParentID,
		CommentID:     e.CommentID,
		Comment:       e.Comment,
		ExtraData:     e.ExtraData,
		ExtraDataHint: e.ExtraDataHint,
		PublicKey:     fid.Public.String(),
		Signature:     hex.EncodeToString(sig[:]),
	}
}

// pluginError returns a backend PluginError for the provided comments
// ErrorCodeT.
func pluginError(e comments.ErrorCodeT) error {
	return backend.PluginError{
		PluginID:  comments.PluginID,
		ErrorCode: uint32(e),
	}
}
