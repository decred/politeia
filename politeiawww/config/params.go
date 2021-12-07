// Copyright (c) 2013-2014 The btcsuite developers
// Copyright (c) 2015-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package config

import (
	"github.com/decred/dcrd/chaincfg/v3"
)

// ChainParams is used to group parameters for various networks such as the
// main network and test networks.
type ChainParams struct {
	*chaincfg.Params
	WalletRPCServerPort string
}

// MainNetParams contains parameters specific to the main network
// (wire.MainNet).  NOTE: The RPC port is intentionally different than the
// reference implementation because dcrd does not handle wallet requests.  The
// separate wallet process listens on the well-known port and forwards requests
// it does not handle on to dcrd.  This approach allows the wallet process
// to emulate the full reference implementation RPC API.
var MainNetParams = ChainParams{
	Params:              chaincfg.MainNetParams(),
	WalletRPCServerPort: "9111",
}

// TestNet3Params contains parameters specific to the test network (version 0)
// (wire.TestNet).  NOTE: The RPC port is intentionally different than the
// reference implementation - see the mainNetParams comment for details.
var TestNet3Params = ChainParams{
	Params:              chaincfg.TestNet3Params(),
	WalletRPCServerPort: "19111",
}

// SimNetParams contains parameters specific to the simulation test network
// (wire.SimNet).
var SimNetParams = ChainParams{
	Params:              chaincfg.SimNetParams(),
	WalletRPCServerPort: "19558",
}
