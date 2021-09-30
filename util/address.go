// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package util

import (
	"decred.org/dcrwallet/wallet/udb"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/dcrec"
	"github.com/decred/dcrd/dcrutil/v3"
	"github.com/decred/dcrd/hdkeychain/v3"
)

// DeriveChildAddress derives a child address using the provided xpub and
// index.
func DeriveChildAddress(params *chaincfg.Params, xpub string, index uint32) (string, error) {
	// Parse the extended public key.
	acctKey, err := hdkeychain.NewKeyFromString(xpub, params)
	if err != nil {
		return "", err
	}

	// Derive the appropriate branch key.
	branchKey, err := acctKey.Child(udb.ExternalBranch)
	if err != nil {
		return "", err
	}

	// Derive the child address.
	key, err := branchKey.Child(index)
	if err != nil {
		return "", err
	}
	pkh := dcrutil.Hash160(key.SerializedPubKey())
	addr, err := dcrutil.NewAddressPubKeyHash(pkh, params, dcrec.STEcdsaSecp256k1)
	if err != nil {
		return "", err
	}

	return addr.Address(), nil
}
