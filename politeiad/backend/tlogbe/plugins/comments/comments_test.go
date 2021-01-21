// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package comments

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"strconv"
	"testing"

	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe/plugins"
	"github.com/decred/politeia/politeiad/plugins/comments"
	"github.com/google/uuid"
)

func commentSignature(t *testing.T, fid *identity.FullIdentity, token []byte, parentID uint32, comment string) string {
	t.Helper()
	tk := hex.EncodeToString(token)
	msg := tk + strconv.FormatInt(int64(parentID), 10) + comment
	b := fid.SignMessage([]byte(msg))
	return hex.EncodeToString(b[:])
}

func commentDelSignature(t *testing.T, fid *identity.FullIdentity, token []byte, parentID uint32, reason string) string {
	t.Helper()
	tk := hex.EncodeToString(token)
	msg := tk + strconv.FormatInt(int64(parentID), 10) + reason
	b := fid.SignMessage([]byte(msg))
	return hex.EncodeToString(b[:])
}

// newTestCommentsPlugin returns a commentsPlugin that is setup for testing and
// a closure that cleans up the test data when invoked.
func newTestCommentsPlugin(t *testing.T) (*commentsPlugin, func()) {
	t.Helper()

	// Setup data dir
	dataDir, err := ioutil.TempDir("", "tlogbe.comments.test")
	if err != nil {
		t.Fatal(err)
	}

	// TODO Implement a test clients.TlogClient
	// Setup tlog client
	var tlog plugins.TlogClient

	// Setup plugin identity
	fid, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}

	// Setup comment plugins
	c, err := New(tlog, []backend.PluginSetting{}, dataDir, fid)
	if err != nil {
		t.Fatal(err)
	}

	return c, func() {
		err = os.RemoveAll(dataDir)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestCmdNew(t *testing.T) {
	p, cleanup := newTestCommentsPlugin(t)
	defer cleanup()

	// Setup test data
	fid, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	var (
		treeID int64
		token  []byte

		userID    = uuid.New().String()
		publicKey = fid.Public.String()
		comment   = "This is a comment."

		parentIDZero uint32
		// parerntIDInvalid uint32 = 99
	)

	// Setup test cases
	var tests = []struct {
		description string
		treeID      int64
		token       []byte
		payload     comments.New
		wantErr     error
		wantReply   string
	}{
		{
			"invalid token",
			treeID,
			token,
			comments.New{
				UserID:    userID,
				Token:     "invalid",
				ParentID:  parentIDZero,
				Comment:   comment,
				PublicKey: publicKey,
				Signature: commentSignature(t, fid, token, parentIDZero, comment),
			},
			backend.PluginError{
				PluginID:  comments.PluginID,
				ErrorCode: int(comments.ErrorCodeTokenInvalid),
			},
			"",
		},
	}

	// Run test cases
	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			// Encode payload
			payload, err := json.Marshal(tc.payload)
			if err != nil {
				t.Fatal(err)
			}

			// Execute plugin command
			reply, err := p.cmdNew(tc.treeID, tc.token, string(payload))

			if tc.wantErr != nil {
				// We expect an error. Verify that the returned error is
				// correct.
				want := tc.wantErr.(backend.PluginError)
				var ue backend.PluginError
				switch {
				case errors.As(err, &ue) &&
					want.PluginID == ue.PluginID &&
					want.ErrorCode == ue.ErrorCode:
					// This is correct. Next test case.
					return
				default:
					// Unexpected error
					t.Errorf("got error %v, want error %v", err, tc.wantErr)
				}
			}

			// We expect a valid reply. Verify the reply.
			var nr comments.NewReply
			err = json.Unmarshal([]byte(reply), &nr)
			if err != nil {
				t.Errorf("invalid NewReply: %v", reply)
			}

			// TODO Verify reply payload
		})
	}
}
