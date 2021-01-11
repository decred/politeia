// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlogbe

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/plugins/comments"
	"github.com/google/uuid"
)

func TestCmdNew(t *testing.T) {
	tlogBackend, cleanup := newTestTlogBackend(t)
	defer cleanup()

	id, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	settings := []backend.PluginSetting{{
		Key:   pluginSettingDataDir,
		Value: tlogBackend.dataDir,
	}}

	commentsPlugin, err := newCommentsPlugin(tlogBackend,
		newBackendClient(tlogBackend), settings, id)
	if err != nil {
		t.Fatal(err)
	}

	// New record
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

	// Helpers
	comment := "random comment"
	tokenRandom := hex.EncodeToString(tokenFromTreeID(123))
	parentID := uint32(0)
	invalidParentID := uint32(3)

	uid, err := identity.New()
	if err != nil {
		t.Error(err)
	}

	// Setup new comment plugin tests
	var tests = []struct {
		description string
		payload     comments.New
		wantErr     *backend.PluginUserError
	}{
		{
			"invalid comment state",
			comments.New{
				UserID:    uuid.New().String(),
				State:     comments.StateInvalid,
				Token:     rec.Token,
				ParentID:  parentID,
				Comment:   comment,
				PublicKey: uid.Public.String(),
				Signature: commentSignature(t, uid, comments.StateInvalid,
					rec.Token, comment, parentID),
			},
			&backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusStateInvalid),
			},
		},
		{
			"invalid token",
			comments.New{
				UserID:    uuid.New().String(),
				State:     comments.StateUnvetted,
				Token:     "invalid",
				ParentID:  parentID,
				Comment:   comment,
				PublicKey: uid.Public.String(),
				Signature: commentSignature(t, uid, comments.StateUnvetted,
					rec.Token, comment, parentID),
			},
			&backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusTokenInvalid),
			},
		},
		{
			"invalid signature",
			comments.New{
				UserID:    uuid.New().String(),
				State:     comments.StateUnvetted,
				Token:     rec.Token,
				ParentID:  parentID,
				Comment:   comment,
				PublicKey: uid.Public.String(),
				Signature: "invalid",
			},
			&backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusSignatureInvalid),
			},
		},
		{
			"invalid public key",
			comments.New{
				UserID:    uuid.New().String(),
				State:     comments.StateUnvetted,
				Token:     rec.Token,
				ParentID:  parentID,
				Comment:   comment,
				PublicKey: "invalid",
				Signature: commentSignature(t, uid, comments.StateUnvetted,
					rec.Token, comment, parentID),
			},
			&backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusPublicKeyInvalid),
			},
		},
		{
			"comment max length exceeded",
			comments.New{
				UserID:    uuid.New().String(),
				State:     comments.StateUnvetted,
				Token:     rec.Token,
				ParentID:  parentID,
				Comment:   commentMaxLengthExceeded(t),
				PublicKey: uid.Public.String(),
				Signature: commentSignature(t, uid, comments.StateUnvetted,
					rec.Token, commentMaxLengthExceeded(t), parentID),
			},
			&backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusCommentTextInvalid),
			},
		},
		{
			"invalid parent ID",
			comments.New{
				UserID:    uuid.New().String(),
				State:     comments.StateUnvetted,
				Token:     rec.Token,
				ParentID:  invalidParentID,
				Comment:   comment,
				PublicKey: uid.Public.String(),
				Signature: commentSignature(t, uid, comments.StateUnvetted,
					rec.Token, comment, invalidParentID),
			},
			&backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusParentIDInvalid),
			},
		},
		{
			"record not found",
			comments.New{
				UserID:    uuid.New().String(),
				State:     comments.StateUnvetted,
				Token:     tokenRandom,
				ParentID:  parentID,
				Comment:   comment,
				PublicKey: uid.Public.String(),
				Signature: commentSignature(t, uid, comments.StateUnvetted,
					tokenRandom, comment, parentID),
			},
			&backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusRecordNotFound),
			},
		},
		{
			"success",
			comments.New{
				UserID:    uuid.New().String(),
				State:     comments.StateUnvetted,
				Token:     rec.Token,
				ParentID:  parentID,
				Comment:   comment,
				PublicKey: uid.Public.String(),
				Signature: commentSignature(t, uid, comments.StateUnvetted,
					rec.Token, comment, parentID),
			},
			nil,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			// New Comment
			ncEncoded, err := comments.EncodeNew(test.payload)
			if err != nil {
				t.Error(err)
			}

			// Execute plugin command
			_, err = commentsPlugin.cmdNew(string(ncEncoded))

			// Parse plugin user error
			var pluginUserError backend.PluginUserError
			if errors.As(err, &pluginUserError) {
				if test.wantErr == nil {
					t.Errorf("got error %v, want nil", err)
					return
				}
				if pluginUserError.ErrorCode != test.wantErr.ErrorCode {
					t.Errorf("got error %v, want %v",
						pluginUserError.ErrorCode,
						test.wantErr.ErrorCode)
				}
				return
			}

			// Expecting nil err
			if err != nil {
				t.Errorf("got error %v, want nil", err)
			}
		})
	}
}
