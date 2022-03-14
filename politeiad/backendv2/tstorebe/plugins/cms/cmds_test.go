// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cms

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/decred/politeia/politeiad/api/v1/identity"
	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/plugins/cms"
)

func TestCmdInvoiceStatus(t *testing.T) {
	// Setup cms plugin
	p, cleanup := newTestCmsPlugin(t)
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
		status    = cms.InvoiceStatusApproved
		publicKey = fid.Public.String()

		msg        = token + string(status)
		signatureb = fid.SignMessage([]byte(msg))
		signature  = hex.EncodeToString(signatureb[:])

		msgWithClosed        = token + string(cms.InvoiceStatusRejected)
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
		sbs   cms.SetInvoiceStatus
		err   error // Expected error output
	}{
		{
			"payload token invalid",
			tokenb,
			setInvoiceStatus(t, fid,
				cms.SetInvoiceStatus{
					Token:  "zzz",
					Status: status,
					Reason: "",
				}),
			pluginError(cms.ErrorCodeTokenInvalid),
		},
		{
			"payload token does not match cmd token",
			tokenb,
			setInvoiceStatus(t, fid,
				cms.SetInvoiceStatus{
					Token:  "da70d0766348340c",
					Status: status,
					Reason: "",
				}),
			pluginError(cms.ErrorCodeTokenInvalid),
		},
		{
			"invalid invoice status",
			tokenb,
			cms.SetInvoiceStatus{
				Token:     token,
				Status:    cms.InvoiceStatusInvalid,
				Reason:    "",
				PublicKey: publicKey,
				Signature: signature,
			},
			pluginError(cms.ErrorCodeInvoiceStatusInvalid),
		},
		{
			"signature is not hex",
			tokenb,
			cms.SetInvoiceStatus{
				Token:     token,
				Status:    status,
				Reason:    "",
				PublicKey: publicKey,
				Signature: "zzz",
			},
			pluginError(cms.ErrorCodeSignatureInvalid),
		},
		{
			"signature is the wrong size",
			tokenb,
			cms.SetInvoiceStatus{
				Token:     token,
				Status:    status,
				Reason:    "",
				PublicKey: publicKey,
				Signature: "123456",
			},
			pluginError(cms.ErrorCodeSignatureInvalid),
		},
		{
			"signature is wrong",
			tokenb,
			cms.SetInvoiceStatus{
				Token:     token,
				Status:    status,
				Reason:    "",
				PublicKey: publicKey,
				Signature: signatureIsWrong,
			},
			pluginError(cms.ErrorCodeSignatureInvalid),
		},
		{
			"public key is not a hex",
			tokenb,
			cms.SetInvoiceStatus{
				Token:     token,
				Status:    status,
				Reason:    "",
				PublicKey: "",
				Signature: signature,
			},
			pluginError(cms.ErrorCodePublicKeyInvalid),
		},
		{
			"public key is the wrong length",
			tokenb,
			cms.SetInvoiceStatus{
				Token:     token,
				Status:    status,
				Reason:    "",
				PublicKey: "123456",
				Signature: signature,
			},
			pluginError(cms.ErrorCodePublicKeyInvalid),
		},
		{
			"set invoice status to rejected without a reason",
			tokenb,
			cms.SetInvoiceStatus{
				Token:     token,
				Status:    cms.InvoiceStatusRejected,
				Reason:    "",
				PublicKey: publicKey,
				Signature: signatureWithClosed,
			},
			pluginError(cms.ErrorCodeInvoiceStatusChangeNotAllowed),
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
			var wantErrorCode cms.ErrorCodeT
			if tc.err != nil {
				var pe backend.PluginError
				if !errors.As(tc.err, &pe) {
					t.Fatalf("error is not a plugin error '%v'", tc.err)
				}
				wantErrorCode = cms.ErrorCodeT(pe.ErrorCode)
			}

			// Run test
			_, err = p.cmdSetInvoiceStatus(tc.token, payload)
			switch {
			case tc.err != nil && err == nil:
				// Wanted an error but didn't get one
				t.Errorf("want error '%v', got nil",
					cms.ErrorCodes[wantErrorCode])
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
				if cms.PluginID != gotErr.PluginID {
					t.Errorf("want plugin error with plugin ID '%v', got '%v'",
						cms.PluginID, gotErr.PluginID)
					return
				}

				gotErrorCode := cms.ErrorCodeT(gotErr.ErrorCode)
				if wantErrorCode != gotErrorCode {
					t.Errorf("want error '%v', got '%v'",
						cms.ErrorCodes[wantErrorCode],
						cms.ErrorCodes[gotErrorCode])
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

// setInvoiceStatus uses the provided arguments to return a SetInvoiceStatus
// with a valid PublicKey and Signature.
func setInvoiceStatus(t *testing.T, fid *identity.FullIdentity, sbs cms.SetInvoiceStatus) cms.SetInvoiceStatus {
	t.Helper()

	msg := sbs.Token + string(sbs.Status) + sbs.Reason
	sig := fid.SignMessage([]byte(msg))

	return cms.SetInvoiceStatus{
		Token:     sbs.Token,
		Status:    sbs.Status,
		Reason:    sbs.Reason,
		PublicKey: fid.Public.String(),
		Signature: hex.EncodeToString(sig[:]),
	}
}

// pluginError returns a backend PluginError for the provided cms ErrorCodeT.
func pluginError(e cms.ErrorCodeT) error {
	return backend.PluginError{
		PluginID:  cms.PluginID,
		ErrorCode: uint32(e),
	}
}
