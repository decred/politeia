// Copyright (c) 2016-2017 Company 0, LLC.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// zkidentity package manages public and private identities.
package identity

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/agl/ed25519"
	"github.com/agl/ed25519/extra25519"
	"golang.org/x/crypto/curve25519"
)

var (
	prng = rand.Reader

	ErrNotEqual = errors.New("not equal")
)

const (
	privKeySize   = ed25519.PrivateKeySize
	SignatureSize = ed25519.SignatureSize
	pubKeySize    = ed25519.PublicKeySize
	IdentitySize  = 32
)

type FullIdentity struct {
	Public          PublicIdentity     // public key and identity
	PrivateKey      [privKeySize]byte  // private key, exported for marshaling
	PrivateIdentity [IdentitySize]byte // private key, exported for marshaling
}

func (fi *FullIdentity) Marshal() ([]byte, error) {
	b, err := json.Marshal(fi)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func UnmarshalFullIdentity(data []byte) (*FullIdentity, error) {
	fi := FullIdentity{}
	err := json.Unmarshal(data, &fi)
	if err != nil {
		return nil, err
	}

	return &fi, nil
}

type PublicIdentity struct {
	Name     string             // long name, e.g. John Doe
	Nick     string             // short name, e.g. jd
	Key      [pubKeySize]byte   // public key
	Identity [IdentitySize]byte // public identity
}

func New(name, nick string) (*FullIdentity, error) {
	fi := FullIdentity{}
	pub, priv, err := ed25519.GenerateKey(prng)
	if err != nil {
		return nil, err
	}

	// move keys in place
	copy(fi.Public.Key[:], pub[:])
	copy(fi.PrivateKey[:], priv[:])
	zero(pub[:])
	zero(priv[:])

	// obtain identities
	extra25519.PrivateKeyToCurve25519(&fi.PrivateIdentity, &fi.PrivateKey)
	curve25519.ScalarBaseMult(&fi.Public.Identity, &fi.PrivateIdentity)

	fi.Public.Name = name
	fi.Public.Nick = nick

	return &fi, nil
}

func LoadFullIdentity(filename string) (*FullIdentity, error) {
	idx, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	id, err := UnmarshalFullIdentity(idx)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal identity")
	}

	return id, nil
}

func (fi *FullIdentity) Save(filename string) error {
	id, err := fi.Marshal()
	if err != nil {
		return fmt.Errorf("could not marshal identity")
	}
	err = ioutil.WriteFile(filename, id, 0600)
	if err != nil {
		return err
	}

	return nil
}

func (fi *FullIdentity) SignMessage(message []byte) [SignatureSize]byte {
	signature := ed25519.Sign(&fi.PrivateKey, message)
	return *signature
}

func UnmarshalPublicIdentity(data []byte) (*PublicIdentity, error) {
	pi := PublicIdentity{}
	err := json.Unmarshal(data, &pi)
	if err != nil {
		return nil, err
	}

	return &pi, nil
}

func LoadPublicIdentity(filename string) (*PublicIdentity, error) {
	idx, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	id, err := UnmarshalPublicIdentity(idx)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal public identity")
	}

	return id, nil
}

func (p PublicIdentity) VerifyMessage(msg []byte, sig [SignatureSize]byte) bool {
	return ed25519.Verify(&p.Key, msg, &sig)
}

func (p PublicIdentity) String() string {
	return hex.EncodeToString(p.Identity[:])
}

func (p PublicIdentity) Fingerprint() string {
	return base64.StdEncoding.EncodeToString(p.Identity[:])
}

func (p *PublicIdentity) Marshal() ([]byte, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (pi *PublicIdentity) SavePublicIdentity(filename string) error {
	id, err := pi.Marshal()
	if err != nil {
		return fmt.Errorf("could not marshal public identity")
	}
	err = ioutil.WriteFile(filename, id, 0600)
	if err != nil {
		return err
	}

	return nil
}

// Zero out a byte slice.
func zero(in []byte) {
	if in == nil {
		return
	}
	for i := 0; i < len(in); i++ {
		in[i] ^= in[i]
	}
}
