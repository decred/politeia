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
	"github.com/decred/politeia/politeiad/plugins/pi"
	"github.com/google/uuid"
)

func TestCommentNew(t *testing.T) {
	piPlugin, tlogBackend, cleanup := newTestPiPlugin(t)
	defer cleanup()

	// Register comments plugin
	id, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	settings := []backend.PluginSetting{{
		Key:   pluginSettingDataDir,
		Value: tlogBackend.dataDir,
	}}
	tlogBackend.RegisterPlugin(backend.Plugin{
		ID:       comments.ID,
		Settings: settings,
		Identity: id,
	})

	// New record
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

	// Helpers
	comment := "random comment"
	tokenRandom := hex.EncodeToString(tokenFromTreeID(123))
	parentID := uint32(0)

	uid, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}

	// Setup comment new pi plugin tests
	var tests = []struct {
		description string
		payload     comments.New
		wantErr     error
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
			backend.PluginUserError{
				ErrorCode: int(pi.ErrorStatusPropStateInvalid),
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
			backend.PluginUserError{
				ErrorCode: int(pi.ErrorStatusPropTokenInvalid),
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
			backend.PluginUserError{
				ErrorCode: int(pi.ErrorStatusPropNotFound),
			},
		},
		// TODO: bad vote status test case. waiting on plugin architecture
		// refactor
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
			_, err = piPlugin.commentNew(string(ncEncoded))

			// Parse plugin user error
			var pluginUserError backend.PluginUserError
			if errors.As(err, &pluginUserError) {
				if test.wantErr == nil {
					t.Errorf("got error %v, want nil2", err)
					return
				}
				wantErr := test.wantErr.(backend.PluginUserError)
				if pluginUserError.ErrorCode != wantErr.ErrorCode {
					t.Errorf("got error %v, want %v",
						pluginUserError.ErrorCode,
						wantErr.ErrorCode)
				}
				return
			}

			// Expectations not met
			if err != test.wantErr {
				t.Errorf("got error %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestCommentDel(t *testing.T) {
	piPlugin, tlogBackend, cleanup := newTestPiPlugin(t)
	defer cleanup()

	// Register comments plugin
	id, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	settings := []backend.PluginSetting{{
		Key:   pluginSettingDataDir,
		Value: tlogBackend.dataDir,
	}}
	tlogBackend.RegisterPlugin(backend.Plugin{
		ID:       comments.ID,
		Settings: settings,
		Identity: id,
	})

	// New record
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

	// Helpers
	comment := "random comment"
	reason := "random reason"
	tokenRandom := hex.EncodeToString(tokenFromTreeID(123))
	parentID := uint32(0)

	uid, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}

	// New comment
	ncEncoded, err := comments.EncodeNew(
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
	)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := piPlugin.commentNew(string(ncEncoded))
	if err != nil {
		t.Fatal(err)
	}
	nr, err := comments.DecodeNewReply([]byte(reply))
	if err != nil {
		t.Fatal(err)
	}

	// Setup comment del pi plugin tests
	var tests = []struct {
		description string
		payload     comments.Del
		wantErr     error
	}{
		{
			"invalid comment state",
			comments.Del{
				State:     comments.StateInvalid,
				Token:     rec.Token,
				CommentID: nr.Comment.CommentID,
				Reason:    reason,
				PublicKey: uid.Public.String(),
				Signature: commentSignature(t, uid, comments.StateInvalid,
					rec.Token, reason, nr.Comment.CommentID),
			},
			backend.PluginUserError{
				ErrorCode: int(pi.ErrorStatusPropStateInvalid),
			},
		},
		{
			"invalid token",
			comments.Del{
				State:     comments.StateUnvetted,
				Token:     "invalid",
				CommentID: nr.Comment.CommentID,
				Reason:    reason,
				PublicKey: uid.Public.String(),
				Signature: commentSignature(t, uid, comments.StateUnvetted,
					"invalid", reason, nr.Comment.CommentID),
			},
			backend.PluginUserError{
				ErrorCode: int(pi.ErrorStatusPropTokenInvalid),
			},
		},
		{
			"proposal not found",
			comments.Del{
				State:     comments.StateUnvetted,
				Token:     tokenRandom,
				CommentID: nr.Comment.CommentID,
				Reason:    reason,
				PublicKey: uid.Public.String(),
				Signature: commentSignature(t, uid, comments.StateUnvetted,
					tokenRandom, reason, nr.Comment.CommentID),
			},
			backend.PluginUserError{
				ErrorCode: int(pi.ErrorStatusPropNotFound),
			},
		},
		{
			"success",
			comments.Del{
				State:     comments.StateUnvetted,
				Token:     rec.Token,
				CommentID: nr.Comment.CommentID,
				Reason:    reason,
				PublicKey: uid.Public.String(),
				Signature: commentSignature(t, uid, comments.StateUnvetted,
					rec.Token, reason, nr.Comment.CommentID),
			},
			nil,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			// New Comment
			dcEncoded, err := comments.EncodeDel(test.payload)
			if err != nil {
				t.Error(err)
			}

			// Execute plugin command
			_, err = piPlugin.commentDel(string(dcEncoded))

			// Parse plugin user error
			var pluginUserError backend.PluginUserError
			if errors.As(err, &pluginUserError) {
				if test.wantErr == nil {
					t.Errorf("got error %v, want nil", err)
					return
				}
				wantErr := test.wantErr.(backend.PluginUserError)
				if pluginUserError.ErrorCode != wantErr.ErrorCode {
					t.Errorf("got error %v, want %v",
						pluginUserError.ErrorCode,
						wantErr.ErrorCode)
				}
				return
			}

			// Expectations not met
			if err != test.wantErr {
				t.Errorf("got error %v, want %v", err, test.wantErr)
			}
		})
	}

}
