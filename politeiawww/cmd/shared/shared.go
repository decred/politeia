// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package shared

import (
	"bytes"
	"encoding/base64"
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

	// ErrUserIdentityNotFound is emitted when a user identity is
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

// ValidateDigests receives a list of files and metadata to verify their
// digests. It compares digests that came with the file/md with digests
// calculated from their respective payloads.
func ValidateDigests(files []v1.File, md []v1.Metadata) error {
	// Validate file digests
	for _, f := range files {
		b, err := base64.StdEncoding.DecodeString(f.Payload)
		if err != nil {
			return fmt.Errorf("file: %v decode payload err %v",
				f.Name, err)
		}
		digest := util.Digest(b)
		d, ok := util.ConvertDigest(f.Digest)
		if !ok {
			return fmt.Errorf("file: %v invalid digest %v",
				f.Name, f.Digest)
		}
		if !bytes.Equal(digest, d[:]) {
			return fmt.Errorf("file: %v digests do not match",
				f.Name)
		}
	}
	// Validate metadata digests
	for _, v := range md {
		b, err := base64.StdEncoding.DecodeString(v.Payload)
		if err != nil {
			return fmt.Errorf("metadata: %v decode payload err %v",
				v.Hint, err)
		}
		digest := util.Digest(b)
		d, ok := util.ConvertDigest(v.Digest)
		if !ok {
			return fmt.Errorf("metadata: %v invalid digest %v",
				v.Hint, v.Digest)
		}
		if !bytes.Equal(digest, d[:]) {
			return fmt.Errorf("metadata: %v digests do not match metadata",
				v.Hint)
		}
	}
	return nil
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

// VerifyProposal verifies a proposal's merkle root, author signature, and
// censorship record.
func VerifyProposal(p v1.ProposalRecord, serverPubKey string) error {
	if len(p.Files) > 0 {
		// Verify digests
		err := ValidateDigests(p.Files, p.Metadata)
		if err != nil {
			return err
		}
		// Verify merkle root
		mr, err := wwwutil.MerkleRootWWW(p.Files, p.Metadata)
		if err != nil {
			return err
		}
		if mr != p.CensorshipRecord.Merkle {
			return fmt.Errorf("merkle roots do not match")
		}
	}

	// Verify proposal signature
	pid, err := util.IdentityFromString(p.PublicKey)
	if err != nil {
		return err
	}
	sig, err := util.ConvertSignature(p.Signature)
	if err != nil {
		return err
	}
	if !pid.VerifyMessage([]byte(p.CensorshipRecord.Merkle), sig) {
		return fmt.Errorf("could not verify proposal signature")
	}

	// Verify censorship record signature
	id, err := util.IdentityFromString(serverPubKey)
	if err != nil {
		return err
	}
	s, err := util.ConvertSignature(p.CensorshipRecord.Signature)
	if err != nil {
		return err
	}
	msg := []byte(p.CensorshipRecord.Merkle + p.CensorshipRecord.Token)
	if !id.VerifyMessage(msg, s) {
		return fmt.Errorf("could not verify censorship record signature")
	}

	return nil
}
