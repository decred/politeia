// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package shared

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/agl/ed25519"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	v1 "github.com/decred/politeia/politeiawww/api/www/v1"
	wwwutil "github.com/decred/politeia/politeiawww/util"
	"github.com/decred/politeia/util"
	"golang.org/x/crypto/sha3"
)

var (
	// Global variables for shared commands
	cfg    *Config
	client *Client

	// errUserIdentityNotFound is emitted when a user identity is
	// required but the config object does not contain one.
	ErrUserIdentityNotFound = errors.New("user identity not found; " +
		"you must either create a new user or use the updateuserkey " +
		"command to generate a new identity for the logged in user")
)

// PrintJSON prints the passed in JSON using the style specified by the global
// config variable.
func PrintJSON(body interface{}) error {
	switch {
	case cfg.Silent:
		// Keep quiet
	case cfg.Verbose:
		// Verbose printing is handled by the http client
		// since it prints details like the url and response
		// codes.
	case cfg.RawJSON:
		// Print raw JSON with no formatting
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("Marshal: %v", err)
		}
		fmt.Printf("%v\n", string(b))
	default:
		// Pretty print the body
		b, err := json.MarshalIndent(body, "", "  ")
		if err != nil {
			return fmt.Errorf("MarshalIndent: %v", err)
		}
		fmt.Fprintf(os.Stdout, "%s\n", b)
	}

	return nil
}

// SignedMerkleRoot calculates the merkle root of the passed in list of files
// and metadata, signs the merkle root with the passed in identity and returns
// the signature.
func SignedMerkleRoot(files []v1.File, md []v1.Metadata, id *identity.FullIdentity) (string, error) {
	if len(files) == 0 {
		return "", fmt.Errorf("no proposal files found")
	}
	mr, err := wwwutil.MerkleRoot(files, md)
	if err != nil {
		return "", err
	}
	sig := id.SignMessage([]byte(mr))
	return hex.EncodeToString(sig[:]), nil
}

// DigestSHA3 returns the hex encoded SHA3-256 of a string.
func DigestSHA3(s string) string {
	h := sha3.New256()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}

// NewIdentity generates a new FullIdentity using randomly generated data to
// create the public/private key pair.
func NewIdentity() (*identity.FullIdentity, error) {
	b, err := util.Random(32)
	if err != nil {
		return nil, err
	}

	r := bytes.NewReader(b)
	pub, priv, err := ed25519.GenerateKey(r)
	if err != nil {
		return nil, err
	}

	id := &identity.FullIdentity{}
	copy(id.Public.Key[:], pub[:])
	copy(id.PrivateKey[:], priv[:])
	return id, nil
}

// SetConfig sets the global config variable.
func SetConfig(config *Config) {
	cfg = config
}

// SetClient sets the global client variable.
func SetClient(c *Client) {
	client = c
}
