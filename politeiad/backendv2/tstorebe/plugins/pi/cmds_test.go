// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pi

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"testing"

	"github.com/decred/politeia/politeiad/api/v1/identity"
	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/plugins/pi"
)

func TestCmdBillingStatus(t *testing.T) {
	// Setup pi plugin
	p, cleanup := newTestPiPlugin(t)
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
		token     = "45154fb45664714b"
		status    = pi.BillingStatusCompleted
		publicKey = fid.Public.String()

		msg        = token + strconv.Itoa(int(status))
		signatureb = fid.SignMessage([]byte(msg))
		signature  = hex.EncodeToString(signatureb[:])

		msgWithClosed        = token + strconv.Itoa(int(pi.BillingStatusClosed))
		signaturebWithClosed = fid.SignMessage([]byte(msgWithClosed))
		signatureWithClosed  = hex.EncodeToString(signaturebWithClosed[:])

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
		name  string // Test name
		token []byte
		sbs   pi.SetBillingStatus
		err   error // Expected error output
	}{
		{
			"payload token invalid",
			tokenb,
			setBillingStatus(t, fid,
				pi.SetBillingStatus{
					Token:  "zzz",
					Status: status,
					Reason: "",
				}),
			pluginError(pi.ErrorCodeTokenInvalid),
		},
		{
			"payload token does not match cmd token",
			tokenb,
			setBillingStatus(t, fid,
				pi.SetBillingStatus{
					Token:  "da70d0766348340c",
					Status: status,
					Reason: "",
				}),
			pluginError(pi.ErrorCodeTokenInvalid),
		},
		{
			"set billing status to active",
			tokenb,
			pi.SetBillingStatus{
				Token:     token,
				Status:    pi.BillingStatusActive,
				Reason:    "",
				PublicKey: publicKey,
				Signature: signature,
			},
			pluginError(pi.ErrorCodeBillingStatusChangeNotAllowed),
		},
		{
			"invalid billing status",
			tokenb,
			pi.SetBillingStatus{
				Token:     token,
				Status:    pi.BillingStatusT(9),
				Reason:    "",
				PublicKey: publicKey,
				Signature: signature,
			},
			pluginError(pi.ErrorCodeBillingStatusInvalid),
		},
		{
			"signature is not hex",
			tokenb,
			pi.SetBillingStatus{
				Token:     token,
				Status:    status,
				Reason:    "",
				PublicKey: publicKey,
				Signature: "zzz",
			},
			pluginError(pi.ErrorCodeSignatureInvalid),
		},
		{
			"signature is the wrong size",
			tokenb,
			pi.SetBillingStatus{
				Token:     token,
				Status:    status,
				Reason:    "",
				PublicKey: publicKey,
				Signature: "123456",
			},
			pluginError(pi.ErrorCodeSignatureInvalid),
		},
		{
			"signature is wrong",
			tokenb,
			pi.SetBillingStatus{
				Token:     token,
				Status:    status,
				Reason:    "",
				PublicKey: publicKey,
				Signature: signatureIsWrong,
			},
			pluginError(pi.ErrorCodeSignatureInvalid),
		},
		{
			"public key is not a hex",
			tokenb,
			pi.SetBillingStatus{
				Token:     token,
				Status:    status,
				Reason:    "",
				PublicKey: "",
				Signature: signature,
			},
			pluginError(pi.ErrorCodePublicKeyInvalid),
		},
		{
			"public key is the wrong length",
			tokenb,
			pi.SetBillingStatus{
				Token:     token,
				Status:    status,
				Reason:    "",
				PublicKey: "123456",
				Signature: signature,
			},
			pluginError(pi.ErrorCodePublicKeyInvalid),
		},
		{
			"set billing status to close without a reason",
			tokenb,
			pi.SetBillingStatus{
				Token:     token,
				Status:    pi.BillingStatusClosed,
				Reason:    "",
				PublicKey: publicKey,
				Signature: signatureWithClosed,
			},
			pluginError(pi.ErrorCodeBillingStatusChangeNotAllowed),
		},
	}

	// Run tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup command payload
			b, err := json.Marshal(tc.sbs)
			if err != nil {
				t.Fatal(err)
			}
			payload := string(b)

			// Decode the expected error into a PluginError. If
			// an error is being returned it should always be a
			// PluginError.
			var wantErrorCode pi.ErrorCodeT
			if tc.err != nil {
				var pe backend.PluginError
				if !errors.As(tc.err, &pe) {
					t.Fatalf("error is not a plugin error '%v'", tc.err)
				}
				wantErrorCode = pi.ErrorCodeT(pe.ErrorCode)
			}

			// Run test
			_, err = p.cmdBillingStatus(tc.token, payload)
			switch {
			case tc.err != nil && err == nil:
				// Wanted an error but didn't get one
				t.Errorf("want error '%v', got nil",
					pi.ErrorCodes[wantErrorCode])
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
				if pi.PluginID != gotErr.PluginID {
					t.Errorf("want plugin error with plugin ID '%v', got '%v'",
						pi.PluginID, gotErr.PluginID)
					return
				}

				gotErrorCode := pi.ErrorCodeT(gotErr.ErrorCode)
				if wantErrorCode != gotErrorCode {
					t.Errorf("want error '%v', got '%v'",
						pi.ErrorCodes[wantErrorCode],
						pi.ErrorCodes[gotErrorCode])
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

// setBillingStatus uses the provided arguments to return a SetBillingStatus
// with a valid PublicKey and Signature.
func setBillingStatus(t *testing.T, fid *identity.FullIdentity, sbs pi.SetBillingStatus) pi.SetBillingStatus {
	t.Helper()

	msg := sbs.Token + strconv.Itoa(int(sbs.Status)) + sbs.Reason
	sig := fid.SignMessage([]byte(msg))

	return pi.SetBillingStatus{
		Token:     sbs.Token,
		Status:    sbs.Status,
		Reason:    sbs.Reason,
		PublicKey: fid.Public.String(),
		Signature: hex.EncodeToString(sig[:]),
	}
}

// pluginError returns a backend PluginError for the provided pi ErrorCodeT.
func pluginError(e pi.ErrorCodeT) error {
	return backend.PluginError{
		PluginID:  pi.PluginID,
		ErrorCode: uint32(e),
	}
}
