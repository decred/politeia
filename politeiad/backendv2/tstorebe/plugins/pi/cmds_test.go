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

// billingStatusTest contains the input and output for a test that tests
// the cmdBillingStatus func.
type billingStatusTest struct {
	name  string    // Test name
	input testInput // Input
	err   error     // Expected output
}

type testInput struct {
	token   []byte
	payload string
}

func TestCmdBillingStatus(t *testing.T) {
	// Setup pi plugin
	p, cleanup := newTestPiPlugin(t)
	defer cleanup()

	// Prepare list of tests with all user error paths.
	tests := []billingStatusTest{}
	var testToken = "45154fb45664714b"
	token, err := tokenDecode(testToken)
	if err != nil {
		t.Fatal(err)
	}

	// Set invalid payload token
	sbs := pi.SetBillingStatus{
		Status: pi.BillingStatusCompleted,
		Token:  "",
	}
	b, err := json.Marshal(sbs)
	if err != nil {
		t.Fatal(err)
	}
	invalidPayloadTokenTest := billingStatusTest{
		name: "invalid payload token",
		input: testInput{
			token:   token,
			payload: string(b),
		},
		err: backend.PluginError{
			PluginID:  pi.PluginID,
			ErrorCode: uint32(pi.ErrorCodeTokenInvalid),
		},
	}
	tests = append(tests, invalidPayloadTokenTest)

	// Set valid token on SetBillingStatus struct
	sbs.Token = testToken
	b, err = json.Marshal(sbs)
	if err != nil {
		t.Fatal(err)
	}
	invalidCmdTokenTest := billingStatusTest{
		name: "invalid cmd token",
		input: testInput{
			token:   []byte(""), // cmd token as empty string
			payload: string(b),
		},
		err: backend.PluginError{
			PluginID:  pi.PluginID,
			ErrorCode: uint32(pi.ErrorCodeTokenInvalid),
		},
	}
	tests = append(tests, invalidCmdTokenTest)

	// Invalid signature test
	invalidSignatureTest := billingStatusTest{
		name: "invalid signature",
		input: testInput{
			token:   token,
			payload: string(b),
		},
		err: backend.PluginError{
			PluginID:  pi.PluginID,
			ErrorCode: uint32(pi.ErrorCodeSignatureInvalid),
		},
	}
	tests = append(tests, invalidSignatureTest)

	// Invalid public key test
	//
	// Generate new indentity
	id, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	msg := sbs.Token + strconv.Itoa(int(sbs.Status)) + sbs.Reason
	signature := id.SignMessage([]byte(msg))
	sbs.Signature = hex.EncodeToString(signature[:])
	b, err = json.Marshal(sbs)
	if err != nil {
		t.Fatal(err)
	}
	invalidPublicKeyTest := billingStatusTest{
		name: "invalid publick key",
		input: testInput{
			token:   token,
			payload: string(b),
		},
		err: backend.PluginError{
			PluginID:  pi.PluginID,
			ErrorCode: uint32(pi.ErrorCodePublicKeyInvalid),
		},
	}
	tests = append(tests, invalidPublicKeyTest)

	// Test setting billing status to closed without
	// providing a reason.
	sbs.Status = pi.BillingStatusClosed
	msg = sbs.Token + strconv.Itoa(int(sbs.Status)) + sbs.Reason
	signature = id.SignMessage([]byte(msg))
	sbs.Signature = hex.EncodeToString(signature[:])
	sbs.PublicKey = id.Public.String()
	b, err = json.Marshal(sbs)
	if err != nil {
		t.Fatal(err)
	}
	closeWithoutReasonTest := billingStatusTest{
		name: "close without reason",
		input: testInput{
			token:   token,
			payload: string(b),
		},
		err: backend.PluginError{
			PluginID:  pi.PluginID,
			ErrorCode: uint32(pi.ErrorCodeBillingStatusChangeNotAllowed),
		},
	}
	tests = append(tests, closeWithoutReasonTest)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Decode the expected error into a PluginError. If
			// an error is being returned it should always be a
			// PluginError.
			var wantErrorCode pi.ErrorCodeT
			if test.err != nil {
				var pe backend.PluginError
				if !errors.As(test.err, &pe) {
					t.Fatalf("error is not a plugin error '%v'", test.err)
				}
				wantErrorCode = pi.ErrorCodeT(pe.ErrorCode)
			}

			// Run test
			_, err := p.cmdBillingStatus(test.input.token, test.input.payload)
			switch {
			case test.err != nil && err == nil:
				// Wanted an error but didn't get one
				t.Errorf("want error '%v', got nil",
					pi.ErrorCodes[wantErrorCode])
				return

			case test.err == nil && err != nil:
				// Wanted success but got an error
				t.Errorf("want error nil, got '%v'", err)
				return

			case test.err != nil && err != nil:
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

			case test.err == nil && err == nil:
				// Success; continue to next test
				return
			}
		})
	}

}
