// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package util

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

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

// DcrStringToAtoms converts a DCR amount as a string into a uint64
// representing atoms. Supported input variations: "1", ".1", "0.1".
func DcrStringToAtoms(dcrstr string) (uint64, error) {
	match, err := regexp.MatchString("(\\d*\\.)*\\d+", dcrstr)
	if err != nil {
		return 0, err
	}
	if !match {
		return 0, fmt.Errorf("invalid DCR amount: %v", dcrstr)
	}

	var dcrsplit []string
	if strings.Contains(dcrstr, ".") {
		dcrsplit = strings.Split(dcrstr, ".")
		if len(dcrsplit[0]) == 0 {
			dcrsplit[0] = "0"
		}
	} else {
		dcrsplit = []string{dcrstr, "0"}
	}

	whole, err := strconv.ParseUint(dcrsplit[0], 10, 64)
	if err != nil {
		return 0, err
	}

	dcrsplit[1] += "00000000"
	fraction, err := strconv.ParseUint(dcrsplit[1][0:8], 10, 64)
	if err != nil {
		return 0, err
	}

	return ((whole * 1e8) + fraction), nil
}
