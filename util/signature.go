// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package util

import (
	"encoding/hex"
	"fmt"

	"github.com/decred/politeia/politeiad/api/v1/identity"
)

type ErrorStatusT int

const (
	// Error codes
	ErrorStatusInvalid          ErrorStatusT = 0
	ErrorStatusPublicKeyInvalid ErrorStatusT = 1
	ErrorStatusSignatureInvalid ErrorStatusT = 2
)

// SignatureError represents an error that was caused while verifying a
// signature.
type SignatureError struct {
	ErrorCode    ErrorStatusT
	ErrorContext []string
}

// Error satisfies the error interface.
func (e SignatureError) Error() string {
	return fmt.Sprintf("signature error code: %v", e.ErrorCode)
}

// VerifySignature verifies a hex encoded Ed25519 signature.
func VerifySignature(signature, pubKey, msg string) error {
	sig, err := ConvertSignature(signature)
	if err != nil {
		return SignatureError{
			ErrorCode:    ErrorStatusSignatureInvalid,
			ErrorContext: []string{err.Error()},
		}
	}
	b, err := hex.DecodeString(pubKey)
	if err != nil {
		return SignatureError{
			ErrorCode:    ErrorStatusPublicKeyInvalid,
			ErrorContext: []string{"key is not hex"},
		}
	}
	pk, err := identity.PublicIdentityFromBytes(b)
	if err != nil {
		return SignatureError{
			ErrorCode:    ErrorStatusPublicKeyInvalid,
			ErrorContext: []string{err.Error()},
		}
	}
	if !pk.VerifyMessage([]byte(msg), sig) {
		return SignatureError{
			ErrorCode: ErrorStatusSignatureInvalid,
		}
	}
	return nil
}
