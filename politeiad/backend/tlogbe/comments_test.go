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
		t.Fatal(err)
	}

	// Helpers
	comment := "random comment"
	tokenRandom := hex.EncodeToString(tokenFromTreeID(123))
	parentID := uint32(0)
	invalidParentID := uint32(3)

	uid, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}

	// Setup new comment plugin tests
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
			backend.PluginUserError{
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
			backend.PluginUserError{
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
			backend.PluginUserError{
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
			backend.PluginUserError{
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
			backend.PluginUserError{
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
			backend.PluginUserError{
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

func TestCmdEdit(t *testing.T) {
	commentsPlugin, tlogBackend, cleanup := newTestCommentsPlugin(t)
	defer cleanup()

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
	commentEdit := comment + "more content"
	parentID := uint32(0)
	invalidParentID := uint32(3)
	invalidCommentID := uint32(3)
	tokenRandom := hex.EncodeToString(tokenFromTreeID(123))

	id, err := identity.New()
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
			PublicKey: id.Public.String(),
			Signature: commentSignature(t, id, comments.StateUnvetted,
				rec.Token, comment, parentID),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := commentsPlugin.cmdNew(string(ncEncoded))
	if err != nil {
		t.Fatal(err)
	}
	nr, err := comments.DecodeNewReply([]byte(reply))
	if err != nil {
		t.Fatal(err)
	}

	// Setup edit comment plugin tests
	var tests = []struct {
		description string
		payload     comments.Edit
		wantErr     error
	}{
		{
			"invalid comment state",
			comments.Edit{
				UserID:    nr.Comment.UserID,
				State:     comments.StateInvalid,
				Token:     rec.Token,
				ParentID:  nr.Comment.ParentID,
				CommentID: nr.Comment.CommentID,
				Comment:   commentEdit,
				PublicKey: id.Public.String(),
				Signature: commentSignature(t, id, comments.StateInvalid,
					rec.Token, commentEdit, nr.Comment.ParentID),
			},
			backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusStateInvalid),
			},
		},
		{
			"invalid token",
			comments.Edit{
				UserID:    nr.Comment.UserID,
				State:     nr.Comment.State,
				Token:     "invalid",
				ParentID:  nr.Comment.ParentID,
				CommentID: nr.Comment.CommentID,
				Comment:   commentEdit,
				PublicKey: id.Public.String(),
				Signature: commentSignature(t, id, nr.Comment.State, "invalid",
					commentEdit, nr.Comment.ParentID),
			},
			backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusTokenInvalid),
			},
		},
		{
			"invalid signature",
			comments.Edit{
				UserID:    nr.Comment.UserID,
				State:     nr.Comment.State,
				Token:     rec.Token,
				ParentID:  nr.Comment.ParentID,
				CommentID: nr.Comment.CommentID,
				Comment:   commentEdit,
				PublicKey: id.Public.String(),
				Signature: "invalid",
			},
			backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusSignatureInvalid),
			},
		},
		{
			"invalid public key",
			comments.Edit{
				UserID:    nr.Comment.UserID,
				State:     nr.Comment.State,
				Token:     rec.Token,
				ParentID:  nr.Comment.ParentID,
				CommentID: nr.Comment.CommentID,
				Comment:   commentEdit,
				PublicKey: "invalid",
				Signature: commentSignature(t, id, nr.Comment.State, rec.Token,
					commentEdit, nr.Comment.ParentID),
			},
			backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusPublicKeyInvalid),
			},
		},
		{
			"comment max length exceeded",
			comments.Edit{
				UserID:    nr.Comment.UserID,
				State:     nr.Comment.State,
				Token:     rec.Token,
				ParentID:  nr.Comment.ParentID,
				CommentID: nr.Comment.CommentID,
				Comment:   commentMaxLengthExceeded(t),
				PublicKey: id.Public.String(),
				Signature: commentSignature(t, id, nr.Comment.State, rec.Token,
					commentMaxLengthExceeded(t), nr.Comment.ParentID),
			},
			backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusCommentTextInvalid),
			},
		},
		{
			"comment id not found",
			comments.Edit{
				UserID:    nr.Comment.UserID,
				State:     nr.Comment.State,
				Token:     rec.Token,
				ParentID:  nr.Comment.ParentID,
				CommentID: invalidCommentID,
				Comment:   commentEdit,
				PublicKey: id.Public.String(),
				Signature: commentSignature(t, id, nr.Comment.State, rec.Token,
					commentEdit, nr.Comment.ParentID),
			},
			backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusCommentNotFound),
			},
		},
		{
			"unauthorized user",
			comments.Edit{
				UserID:    uuid.New().String(),
				State:     nr.Comment.State,
				Token:     rec.Token,
				ParentID:  nr.Comment.ParentID,
				CommentID: nr.Comment.CommentID,
				Comment:   commentEdit,
				PublicKey: id.Public.String(),
				Signature: commentSignature(t, id, nr.Comment.State, rec.Token,
					commentEdit, nr.Comment.ParentID),
			},
			backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusUserUnauthorized),
			},
		},
		{
			"invalid parent ID",
			comments.Edit{
				UserID:    nr.Comment.UserID,
				State:     nr.Comment.State,
				Token:     rec.Token,
				ParentID:  invalidParentID,
				CommentID: nr.Comment.CommentID,
				Comment:   commentEdit,
				PublicKey: id.Public.String(),
				Signature: commentSignature(t, id, nr.Comment.State,
					rec.Token, commentEdit, invalidParentID),
			},
			backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusParentIDInvalid),
			},
		},
		{
			"comment did not change",
			comments.Edit{
				UserID:    nr.Comment.UserID,
				State:     nr.Comment.State,
				Token:     rec.Token,
				ParentID:  nr.Comment.ParentID,
				CommentID: nr.Comment.CommentID,
				Comment:   comment,
				PublicKey: id.Public.String(),
				Signature: commentSignature(t, id, nr.Comment.State,
					rec.Token, comment, nr.Comment.ParentID),
			},
			backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusCommentTextInvalid),
			},
		},
		{
			"record not found",
			comments.Edit{
				UserID:    nr.Comment.UserID,
				State:     nr.Comment.State,
				Token:     tokenRandom,
				ParentID:  nr.Comment.ParentID,
				CommentID: nr.Comment.ParentID,
				Comment:   commentEdit,
				PublicKey: id.Public.String(),
				Signature: commentSignature(t, id, nr.Comment.State,
					tokenRandom, commentEdit, nr.Comment.ParentID),
			},
			backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusRecordNotFound),
			},
		},
		{
			"success",
			comments.Edit{
				UserID:    nr.Comment.UserID,
				State:     nr.Comment.State,
				Token:     rec.Token,
				ParentID:  nr.Comment.ParentID,
				CommentID: nr.Comment.CommentID,
				Comment:   commentEdit,
				PublicKey: id.Public.String(),
				Signature: commentSignature(t, id, nr.Comment.State,
					rec.Token, commentEdit, nr.Comment.ParentID),
			},
			nil,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			// Edit Comment
			ecEncoded, err := comments.EncodeEdit(test.payload)
			if err != nil {
				t.Error(err)
			}

			// Execute plugin command
			_, err = commentsPlugin.cmdEdit(string(ecEncoded))

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

func TestCmdDel(t *testing.T) {
	commentsPlugin, tlogBackend, cleanup := newTestCommentsPlugin(t)
	defer cleanup()

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
	parentID := uint32(0)
	tokenRandom := hex.EncodeToString(tokenFromTreeID(123))
	id, err := identity.New()
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
			PublicKey: id.Public.String(),
			Signature: commentSignature(t, id, comments.StateUnvetted,
				rec.Token, comment, parentID),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := commentsPlugin.cmdNew(string(ncEncoded))
	if err != nil {
		t.Fatal(err)
	}
	nr, err := comments.DecodeNewReply([]byte(reply))
	if err != nil {
		t.Fatal(err)
	}

	// Setup del comment plugin tests
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
				PublicKey: id.Public.String(),
				Signature: commentSignature(t, id, comments.StateInvalid,
					rec.Token, reason, nr.Comment.CommentID),
			},
			backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusStateInvalid),
			},
		},
		{
			"invalid token",
			comments.Del{
				State:     comments.StateUnvetted,
				Token:     "invalid",
				CommentID: nr.Comment.CommentID,
				Reason:    reason,
				PublicKey: id.Public.String(),
				Signature: commentSignature(t, id, comments.StateUnvetted,
					"invalid", reason, nr.Comment.CommentID),
			},
			backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusTokenInvalid),
			},
		},
		{
			"invalid signature",
			comments.Del{
				State:     comments.StateUnvetted,
				Token:     rec.Token,
				CommentID: nr.Comment.CommentID,
				Reason:    reason,
				PublicKey: id.Public.String(),
				Signature: "invalid",
			},
			backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusSignatureInvalid),
			},
		},
		{
			"invalid public key",
			comments.Del{
				State:     comments.StateUnvetted,
				Token:     rec.Token,
				CommentID: nr.Comment.CommentID,
				Reason:    reason,
				PublicKey: "invalid",
				Signature: commentSignature(t, id, comments.StateUnvetted,
					rec.Token, reason, nr.Comment.CommentID),
			},
			backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusPublicKeyInvalid),
			},
		},
		{
			"record not found",
			comments.Del{
				State:     comments.StateUnvetted,
				Token:     tokenRandom,
				CommentID: nr.Comment.CommentID,
				Reason:    reason,
				PublicKey: id.Public.String(),
				Signature: commentSignature(t, id, comments.StateUnvetted,
					tokenRandom, reason, nr.Comment.CommentID),
			},
			backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusRecordNotFound),
			},
		},
		{
			"comment id not found",
			comments.Del{
				State:     comments.StateUnvetted,
				Token:     rec.Token,
				CommentID: 3,
				Reason:    reason,
				PublicKey: id.Public.String(),
				Signature: commentSignature(t, id, comments.StateUnvetted,
					rec.Token, reason, 3),
			},
			backend.PluginUserError{
				ErrorCode: int(comments.ErrorStatusCommentNotFound),
			},
		},
		{
			"success",
			comments.Del{
				State:     comments.StateUnvetted,
				Token:     rec.Token,
				CommentID: nr.Comment.CommentID,
				Reason:    reason,
				PublicKey: id.Public.String(),
				Signature: commentSignature(t, id, comments.StateUnvetted,
					rec.Token, reason, nr.Comment.CommentID),
			},
			nil,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			// Del Comment
			dcEncoded, err := comments.EncodeDel(test.payload)
			if err != nil {
				t.Error(err)
			}

			// Execute plugin command
			_, err = commentsPlugin.cmdDel(string(dcEncoded))

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
