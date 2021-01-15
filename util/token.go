// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package util

import (
	"encoding/hex"
	"fmt"

	pdv1 "github.com/decred/politeia/politeiad/api/v1"
)

var (
	TokenTypeGit  = "git"
	TokenTypeTlog = "tlog"
)

func tokenIsFullLength(tokenType string, token []byte) bool {
	switch tokenType {
	case TokenTypeTlog:
		return len(token) == pdv1.TokenSizeTlog
	case TokenTypeGit:
		return len(token) == pdv1.TokenSizeGit
	default:
		e := fmt.Sprintf("invalid token type")
		panic(e)
	}
}

func TokenPrefixSize() int {
	// If the token prefix length is an odd number of characters then
	// padding would have needed to be added to it prior to decoding it
	// to hex to prevent a hex.ErrLenth (odd length hex string) error.
	// Account for this padding in the prefix size.
	var size int
	if pdv1.TokenPrefixLength%2 == 1 {
		// Add 1 to the length to account for padding
		size = (pdv1.TokenPrefixLength + 1) / 2
	} else {
		// No padding was required
		size = pdv1.TokenPrefixLength / 2
	}
	return size
}

// TokenPrefix returns the token prefix given the token.
func TokenPrefix(token []byte) string {
	return hex.EncodeToString(token)[:pdv1.TokenPrefixLength]
}

// TokenDecode decodes full length tokens. An error is returned if the token
// is not a valid full length, hex token.
func TokenDecode(tokenType, token string) ([]byte, error) {
	// Decode token
	t, err := hex.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("invalid hex")
	}

	// Verify token is full length
	if !tokenIsFullLength(tokenType, t) {
		return nil, fmt.Errorf("invalid token size")
	}

	return t, nil
}

// TokenDecodeAnyLength decodes both token prefixes and full length tokens.
func TokenDecodeAnyLength(tokenType, token string) ([]byte, error) {
	// Decode token. If provided token has odd length, add padding
	// to prevent a hex.ErrLength (odd length hex string) error.
	if len(token)%2 == 1 {
		token = token + "0"
	}
	t, err := hex.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("invalid hex")
	}

	// Verify token byte slice is either a token prefix or a valid
	// full length token.
	switch {
	case len(t) == TokenPrefixSize():
		// This is a token prefix. Token prefixes are the same size
		// regardless of token type.
	case tokenIsFullLength(TokenTypeGit, t):
		// Token is a valid git backend token
	case tokenIsFullLength(TokenTypeTlog, t):
		// Token is a valid tlog backend token
	default:
		return nil, fmt.Errorf("invalid token size")
	}

	return t, nil
}
