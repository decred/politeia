// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package util

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/dcrec/secp256k1/v3/ecdsa"
	"github.com/decred/dcrd/dcrutil/v3"
	"github.com/decred/dcrd/wire"
	"github.com/decred/politeia/politeiad/api/v1/identity"
)

// ErrorStatusT represents an error that occurred during signature validation.
type ErrorStatusT int

const (
	// ErrorStatusInvalid is an invalid error status.
	ErrorStatusInvalid ErrorStatusT = 0

	// ErrorStatusPublicKeyInvalid is returned when a public key is not
	// a hex encoded ed25519 public key.
	ErrorStatusPublicKeyInvalid ErrorStatusT = 1

	// ErrorStatusSignatureInvalid is returned when a signature is
	// either not a valid hex encoded ed25519 signature or the
	// signature is wrong for the provided public key and message.
	ErrorStatusSignatureInvalid ErrorStatusT = 2

	// errorStatusLast represents the last entry in the error statuses
	// list. It is used by a unit test to verify that all error codes
	// have a corresponding entry in the ErrorStatuses map. This error
	// code will never be returned.
	errorStatusLast ErrorStatusT = 3
)

// ErrorStatuses contains the human readable signature error messages.
var ErrorStatuses = map[ErrorStatusT]string{
	ErrorStatusInvalid:          "signature error invalid",
	ErrorStatusPublicKeyInvalid: "public key invalid",
	ErrorStatusSignatureInvalid: "signature invalid",
}

// SignatureError represents an error that was caused while verifying a
// signature.
type SignatureError struct {
	ErrorCode    ErrorStatusT
	ErrorContext string
}

// Error satisfies the error interface.
func (e SignatureError) Error() string {
	if e.ErrorContext == "" {
		return fmt.Sprintf("could not verify signature: %v",
			ErrorStatuses[e.ErrorCode])
	}
	return fmt.Sprintf("could not verify signature: %v: %v",
		ErrorStatuses[e.ErrorCode], e.ErrorContext)
}

// VerifySignature verifies a hex encoded Ed25519 signature.
func VerifySignature(signature, pubKey, msg string) error {
	sig, err := ConvertSignature(signature)
	if err != nil {
		return SignatureError{
			ErrorCode:    ErrorStatusSignatureInvalid,
			ErrorContext: err.Error(),
		}
	}
	b, err := hex.DecodeString(pubKey)
	if err != nil {
		return SignatureError{
			ErrorCode:    ErrorStatusPublicKeyInvalid,
			ErrorContext: "key is not hex",
		}
	}
	pk, err := identity.PublicIdentityFromBytes(b)
	if err != nil {
		return SignatureError{
			ErrorCode:    ErrorStatusPublicKeyInvalid,
			ErrorContext: err.Error(),
		}
	}
	if !pk.VerifyMessage([]byte(msg), sig) {
		return SignatureError{
			ErrorCode: ErrorStatusSignatureInvalid,
		}
	}
	return nil
}

// VerifyMessage verifies a message that was signed using a decred P2PKH
// address.
//
// Copied from:
// github.com/decred/dcrd/blob/0fc55252f912756c23e641839b1001c21442c38a/rpcserver.go#L5605
func VerifyMessage(address, message, signature string, net *chaincfg.Params) (bool, error) {
	// Decode the provided address.
	addr, err := dcrutil.DecodeAddress(address, net)
	if err != nil {
		return false, fmt.Errorf("Could not decode address: %v",
			err)
	}

	// Only P2PKH addresses are valid for signing.
	if _, ok := addr.(*dcrutil.AddressPubKeyHash); !ok {
		return false, fmt.Errorf("Address is not a pay-to-pubkey-hash "+
			"address: %v", address)
	}

	// Decode base64 signature.
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, fmt.Errorf("Malformed base64 encoding: %v", err)
	}

	// Validate the signature - this just shows that it was valid at all.
	// we will compare it with the key next.
	var buf bytes.Buffer
	wire.WriteVarString(&buf, 0, "Decred Signed Message:\n")
	wire.WriteVarString(&buf, 0, message)
	expectedMessageHash := chainhash.HashB(buf.Bytes())
	pk, wasCompressed, err := ecdsa.RecoverCompact(sig,
		expectedMessageHash)
	if err != nil {
		// Mirror Bitcoin Core behavior, which treats error in
		// RecoverCompact as invalid signature.
		return false, nil
	}

	// Reconstruct the pubkey hash.
	dcrPK := pk
	var serializedPK []byte
	if wasCompressed {
		serializedPK = dcrPK.SerializeCompressed()
	} else {
		serializedPK = dcrPK.SerializeUncompressed()
	}
	a, err := dcrutil.NewAddressSecpPubKey(serializedPK, net)
	if err != nil {
		// Again mirror Bitcoin Core behavior, which treats error in
		// public key reconstruction as invalid signature.
		return false, nil
	}

	// Return boolean if addresses match.
	return a.Address() == address, nil
}
