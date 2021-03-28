// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package util

import (
	"encoding/hex"
	"fmt"
	"regexp"

	pdv1 "github.com/decred/politeia/politeiad/api/v1"
	pdv2 "github.com/decred/politeia/politeiad/api/v2"
)

var (
	// TokenTypeGit represents a token from the politeiad git backend.
	TokenTypeGit = "git"

	// TokenTypeTstore represents a token from the politeiad tstore
	// backend.
	TokenTypeTstore = "tstore"

	// tokenRegexp is a regexp that matches short tokens and full
	// length tokens.
	tokenRegexp = regexp.MustCompile(fmt.Sprintf("^[0-9a-f]{%v,%v}$",
		pdv2.ShortTokenLength, pdv2.TokenSize*2))
)

// ShortTokenSize returns the size, in bytes, of a politeiad short token.
func ShortTokenSize() int {
	// If the short token length is an odd number of characters then
	// padding would have needed to be added to it prior to encoding it
	// to hex to prevent a hex.ErrLenth (odd length hex string) error.
	// This function accounts for this padding in the returned size.
	var size int
	if pdv1.TokenPrefixLength%2 == 1 {
		// Add 1 to the length to account for padding
		size = (pdv2.ShortTokenLength + 1) / 2
	} else {
		// No padding was required
		size = pdv2.ShortTokenLength / 2
	}
	return size
}

// ShortToken returns the short version of a token.
func ShortToken(token []byte) ([]byte, error) {
	s := ShortTokenSize()
	if len(token) < s {
		return nil, fmt.Errorf("token is not large enough")
	}
	return token[:s], nil
}

// ShortTokenString takes a hex encoded token and returns the shortened token
// for it.
func ShortTokenString(token string) (string, error) {
	if tokenRegexp.FindString(token) == "" {
		return "", fmt.Errorf("invalid token %v", tokenRegexp.String())
	}
	return token[:pdv2.ShortTokenLength], nil
}

// ShortTokenEncode returns the hex encoded shortened token.
func ShortTokenEncode(token []byte) (string, error) {
	t, err := ShortToken(token)
	if err != nil {
		return "", err
	}
	return TokenEncode(t), nil
}

// TokenIsFullLength returns whether a token is a valid, full length politeiad
// censorship token.
func TokenIsFullLength(tokenType string, token []byte) bool {
	switch tokenType {
	case TokenTypeGit:
		return len(token) == pdv1.TokenSize
	case TokenTypeTstore:
		return len(token) == pdv2.TokenSize
	default:
		panic("invalid token type")
	}
}

// TokenDecode decodes a full length token. An error is returned if the token
// is not a full length, hex token.
func TokenDecode(tokenType, token string) ([]byte, error) {
	// Verify token is valid
	if tokenRegexp.FindString(token) == "" {
		return nil, fmt.Errorf("invalid token %v", tokenRegexp.String())
	}

	// Decode token
	t, err := hex.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("invalid hex")
	}

	// Verify token is full length
	if !TokenIsFullLength(tokenType, t) {
		return nil, fmt.Errorf("invalid token size")
	}

	return t, nil
}

// TokenDecodeAnyLength decodes both short tokens and full length tokens.
func TokenDecodeAnyLength(tokenType, token string) ([]byte, error) {
	// Verify token is valid
	if tokenRegexp.FindString(token) == "" {
		return nil, fmt.Errorf("invalid token %v", tokenRegexp.String())
	}

	// Decode token. If provided token has odd length, add padding
	// to prevent a hex.ErrLength (odd length hex string) error.
	if len(token)%2 == 1 {
		token = token + "0"
	}
	t, err := hex.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("invalid hex")
	}

	// Verify token byte slice is either a short token or a full length
	// token.
	switch {
	case len(t) == ShortTokenSize():
		// This is a short token. Short tokens are the same size
		// regardless of token type.
	case tokenType == TokenTypeGit && TokenIsFullLength(TokenTypeGit, t):
		// Token is a valid git backend token
	case tokenType == TokenTypeTstore && TokenIsFullLength(TokenTypeTstore, t):
		// Token is a valid tstore backend token
	default:
		return nil, fmt.Errorf("invalid token size")
	}

	return t, nil
}

// TokenEncode returns the hex encoded token. Its possible that padding has
// been added to the token when it was originally decode in order to make it
// valid hex. This function checks for padding and removes it before encoding
// the token.
func TokenEncode(token []byte) string {
	t := hex.EncodeToString(token)
	if len(t) == pdv2.ShortTokenLength+1 {
		// This is a short token that has had padding added to it. Remove
		// the padding.
		t = t[:pdv2.ShortTokenLength]
	}
	return t
}

// TokenRegexp returns the string regexp that is used to match tokens.
func TokenRegexp() string {
	return tokenRegexp.String()
}
