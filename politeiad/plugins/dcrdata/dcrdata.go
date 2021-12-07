// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package dcrdata provides a plugin for querying the dcrdata block explorer.
package dcrdata

const (
	// PluginID is the unique identifier for this plugin.
	PluginID = "dcrdata"

	// Plugin commands
	CmdBestBlock    = "bestblock"    // Get best block
	CmdBlockDetails = "blockdetails" // Get details of a block
	CmdTicketPool   = "ticketpool"   // Get ticket pool
	CmdTxsTrimmed   = "txstrimmed"   // Get trimmed transactions
)

// Plugin setting keys can be used to specify custom plugin settings. Default
// plugin setting values can be overridden by providing a plugin setting key
// and value to the plugin on startup.
const (
	// SettingKeyHostHTTP is the plugin setting key for the plugin
	// setting SettingHostHTTP.
	SettingKeyHostHTTP = "hosthttp"

	// SettingKeyHostWS is the plugin setting key for the plugin
	// setting SettingHostWS.
	SettingKeyHostWS = "hostws"
)

// Plugin setting default values. These can be overridden by providing a plugin
// setting key and value to the plugin on startup.
const (
	// SettingHostHTTPMainNet is the default dcrdata mainnet http host.
	SettingHostHTTPMainNet = "https://dcrdata.decred.org"

	// SettingHostHTTPTestNet is the default dcrdata testnet http host.
	SettingHostHTTPTestNet = "https://testnet.decred.org"

	// SettingHostHTTPSimNet is the default dcrdata testnet http host.
	SettingHostHTTPSimNet = "http://localhost:17779"

	// SettingHostWSMainNet is the default dcrdata mainnet websocket
	// host.
	SettingHostWSMainNet = "wss://dcrdata.decred.org/ps"

	// SettingHostWSTestNet is the default dcrdata testnet websocket
	// host.
	SettingHostWSTestNet = "wss://testnet.decred.org/ps"

	// SettingHostWSTestNet is the default dcrdata testnet websocket
	// host.
	SettingHostWSSimNet = "ws://localhost:17779/ps"
)

// StatusT represents a dcrdata connection status. Some commands will returned
// cached results and the connection status to let the caller know that the
// cached data may be stale. It is the callers responsibility to determine the
// correct course of action when dcrdata cannot be reached.
type StatusT uint32

const (
	// StatusInvalid is an invalid connection status.
	StatusInvalid StatusT = 0

	// StatusConnected is returned when the dcrdata connection is ok.
	StatusConnected StatusT = 1

	// StatusDisconnected is returned when dcrdata cannot be reached.
	StatusDisconnected StatusT = 2
)

// BestBlock requests best block data. If dcrdata cannot be reached then the
// data from the most recent cached best block will be returned along with a
// status of StatusDisconnected. It is the callers responsibility to determine
// if the stale best block height should be used.
type BestBlock struct{}

// BestBlockReply is the reply to the BestBlock command.
type BestBlockReply struct {
	Status StatusT `json:"status"`
	Height uint32  `json:"height"`
}

// TicketPoolInfo models data about ticket pool.
type TicketPoolInfo struct {
	Height  uint32   `json:"height"`
	Size    uint32   `json:"size"`
	Value   float64  `json:"value"`
	ValAvg  float64  `json:"valavg"`
	Winners []string `json:"winners"`
}

// BlockDataBasic models primary information about a block.
type BlockDataBasic struct {
	Height     uint32  `json:"height"`
	Size       uint32  `json:"size"`
	Hash       string  `json:"hash"`
	Difficulty float64 `json:"diff"`
	StakeDiff  float64 `json:"sdiff"`
	Time       int64   `json:"time"` // UNIX timestamp
	NumTx      uint32  `json:"txlength"`
	MiningFee  *int64  `json:"fees,omitempty"`
	TotalSent  *int64  `json:"totalsent,omitempty"`
	// TicketPoolInfo may be nil for side chain blocks.
	PoolInfo *TicketPoolInfo `json:"ticketpool,omitempty"`
}

// BlockDetails retrieves the block details for the provided block height.
type BlockDetails struct {
	Height uint32 `json:"height"`
}

// BlockDetailsReply is the reply to the block details command.
type BlockDetailsReply struct {
	Block BlockDataBasic `json:"block"`
}

// TicketPool requests the lists of tickets in the ticket pool at a specified
// block hash.
type TicketPool struct {
	BlockHash string `json:"blockhash"`
}

// TicketPoolReply is the reply to the TicketPool command.
type TicketPoolReply struct {
	Tickets []string `json:"tickets"` // Ticket hashes
}

// ScriptSig models a signature script. It is defined separately since it only
// applies to non-coinbase. Therefore the field in the Vin structure needs to
// be a pointer.
type ScriptSig struct {
	Asm string `json:"asm"`
	Hex string `json:"hex"`
}

// Vin models parts of the tx data. It is defined separately since
// getrawtransaction, decoderawtransaction, and searchrawtransaction use the
// same structure.
type Vin struct {
	Coinbase    string     `json:"coinbase"`
	Stakebase   string     `json:"stakebase"`
	Txid        string     `json:"txid"`
	Vout        uint32     `json:"vout"`
	Tree        int8       `json:"tree"`
	Sequence    uint32     `json:"sequence"`
	AmountIn    float64    `json:"amountin"`
	BlockHeight uint32     `json:"blockheight"`
	BlockIndex  uint32     `json:"blockindex"`
	ScriptSig   *ScriptSig `json:"scriptsig"`
}

// ScriptPubKey is the script public key data.
type ScriptPubKey struct {
	Asm       string   `json:"asm"`
	Hex       string   `json:"hex"`
	ReqSigs   int32    `json:"reqSigs,omitempty"`
	Type      string   `json:"type"`
	Addresses []string `json:"addresses,omitempty"`
	CommitAmt *float64 `json:"commitamt,omitempty"`
}

// TxInputID specifies a transaction input as hash:vin_index.
type TxInputID struct {
	Hash  string `json:"hash"`
	Index uint32 `json:"index"`
}

// Vout defines a transaction output.
type Vout struct {
	Value               float64      `json:"value"`
	N                   uint32       `json:"n"`
	Version             uint16       `json:"version"`
	ScriptPubKeyDecoded ScriptPubKey `json:"scriptpubkeydecoded"`
	Spend               *TxInputID   `json:"spend,omitempty"`
}

// TrimmedTx models data to resemble to result of the decoderawtransaction RPC.
type TrimmedTx struct {
	TxID     string `json:"txid"`
	Version  int32  `json:"version"`
	Locktime uint32 `json:"locktime"`
	Expiry   uint32 `json:"expiry"`
	Vin      []Vin  `json:"vin"`
	Vout     []Vout `json:"vout"`
}

// TxsTrimmed requests the trimmed transaction information for the provided
// transaction IDs.
type TxsTrimmed struct {
	TxIDs []string `json:"txids"`
}

// TxsTrimmedReply is the reply to the TxsTrimmed command.
type TxsTrimmedReply struct {
	Txs []TrimmedTx `json:"txs"`
}
