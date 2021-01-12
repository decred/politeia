// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package dcrdata provides a plugin for retrieving data from the dcrdata block
// explorer.
package dcrdata

import (
	"encoding/json"
)

type StatusT int

const (
	ID = "dcrdata"

	// Plugin commands
	CmdBestBlock    = "bestblock"    // Get best block
	CmdBlockDetails = "blockdetails" // Get details of a block
	CmdTicketPool   = "ticketpool"   // Get ticket pool
	CmdTxsTrimmed   = "txstrimmed"   // Get trimmed transactions

	// Default plugin settings
	DefaultHostHTTPMainNet = "https://dcrdata.decred.org"
	DefaultHostHTTPTestNet = "https://testnet.decred.org"
	DefaultHostWSMainNet   = "wss://dcrdata.decred.org/ps"
	DefaultHostWSTestNet   = "wss://testnet.decred.org/ps"

	// Dcrdata connection statuses.
	//
	// Some commands will return cached results with the connection
	// status when dcrdata cannot be reached. It is the callers
	// responsibility to determine the correct course of action when
	// dcrdata cannot be reached.
	StatusInvalid      StatusT = 0
	StatusConnected    StatusT = 1
	StatusDisconnected StatusT = 2
)

// BestBlock requests best block data. If dcrdata cannot be reached then the
// data from the most recent cached best block will be returned along with a
// status of StatusDisconnected. It is the callers responsibility to determine
// if the stale best block height should be used.
type BestBlock struct{}

// EncodeBestBlock encodes an BestBlock into a JSON byte slice.
func EncodeBestBlock(bb BestBlock) ([]byte, error) {
	return json.Marshal(bb)
}

// DecodeBestBlock decodes a JSON byte slice into a BestBlock.
func DecodeBestBlock(payload []byte) (*BestBlock, error) {
	var bb BestBlock
	err := json.Unmarshal(payload, &bb)
	if err != nil {
		return nil, err
	}
	return &bb, nil
}

// BestBlockReply is the reply to the BestBlock command.
type BestBlockReply struct {
	Status StatusT `json:"status"`
	Height uint32  `json:"height"`
}

// EncodeBestBlockReply encodes an BestBlockReply into a JSON byte slice.
func EncodeBestBlockReply(bbr BestBlockReply) ([]byte, error) {
	return json.Marshal(bbr)
}

// DecodeBestBlockReply decodes a JSON byte slice into a BestBlockReply.
func DecodeBestBlockReply(payload []byte) (*BestBlockReply, error) {
	var bbr BestBlockReply
	err := json.Unmarshal(payload, &bbr)
	if err != nil {
		return nil, err
	}
	return &bbr, nil
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
	TotalSent  *int64  `json:"total_sent,omitempty"`
	// TicketPoolInfo may be nil for side chain blocks.
	PoolInfo *TicketPoolInfo `json:"ticket_pool,omitempty"`
}

// BlockDetails fetched the block details for the provided block height.
type BlockDetails struct {
	Height uint32 `json:"height"`
}

// EncodeBlockDetails encodes an BlockDetails into a JSON byte slice.
func EncodeBlockDetails(bd BlockDetails) ([]byte, error) {
	return json.Marshal(bd)
}

// DecodeBlockDetails decodes a JSON byte slice into a BlockDetails.
func DecodeBlockDetails(payload []byte) (*BlockDetails, error) {
	var bd BlockDetails
	err := json.Unmarshal(payload, &bd)
	if err != nil {
		return nil, err
	}
	return &bd, nil
}

// BlockDetailsReply is the reply to the block details command.
type BlockDetailsReply struct {
	Block BlockDataBasic `json:"block"`
}

// EncodeBlockDetailsReply encodes an BlockDetailsReply into a JSON byte slice.
func EncodeBlockDetailsReply(bdr BlockDetailsReply) ([]byte, error) {
	return json.Marshal(bdr)
}

// DecodeBlockDetailsReply decodes a JSON byte slice into a BlockDetailsReply.
func DecodeBlockDetailsReply(payload []byte) (*BlockDetailsReply, error) {
	var bdr BlockDetailsReply
	err := json.Unmarshal(payload, &bdr)
	if err != nil {
		return nil, err
	}
	return &bdr, nil
}

// TicketPool requests the lists of tickets in the ticket for at the provided
// block hash.
type TicketPool struct {
	BlockHash string `json:"blockhash"`
}

// EncodeTicketPool encodes an TicketPool into a JSON byte slice.
func EncodeTicketPool(tp TicketPool) ([]byte, error) {
	return json.Marshal(tp)
}

// DecodeTicketPool decodes a JSON byte slice into a TicketPool.
func DecodeTicketPool(payload []byte) (*TicketPool, error) {
	var tp TicketPool
	err := json.Unmarshal(payload, &tp)
	if err != nil {
		return nil, err
	}
	return &tp, nil
}

// TicketPoolReply is the reply to the TicketPool command.
type TicketPoolReply struct {
	Tickets []string `json:"tickets"` // Ticket hashes
}

// EncodeTicketPoolReply encodes an TicketPoolReply into a JSON byte slice.
func EncodeTicketPoolReply(tpr TicketPoolReply) ([]byte, error) {
	return json.Marshal(tpr)
}

// DecodeTicketPoolReply decodes a JSON byte slice into a TicketPoolReply.
func DecodeTicketPoolReply(payload []byte) (*TicketPoolReply, error) {
	var tpr TicketPoolReply
	err := json.Unmarshal(payload, &tpr)
	if err != nil {
		return nil, err
	}
	return &tpr, nil
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
	ScriptSig   *ScriptSig `json:"scriptSig"`
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
	Index uint32 `json:"vin_index"`
}

// Vout defines a transaction output.
type Vout struct {
	Value               float64      `json:"value"`
	N                   uint32       `json:"n"`
	Version             uint16       `json:"version"`
	ScriptPubKeyDecoded ScriptPubKey `json:"scriptPubKey"`
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

// EncodeTxsTrimmed encodes an TxsTrimmed into a JSON byte slice.
func EncodeTxsTrimmed(tt TxsTrimmed) ([]byte, error) {
	return json.Marshal(tt)
}

// DecodeTxsTrimmed decodes a JSON byte slice into a TxsTrimmed.
func DecodeTxsTrimmed(payload []byte) (*TxsTrimmed, error) {
	var tt TxsTrimmed
	err := json.Unmarshal(payload, &tt)
	if err != nil {
		return nil, err
	}
	return &tt, nil
}

// TxsTrimmedReply is the reply to the TxsTrimmed command.
type TxsTrimmedReply struct {
	Txs []TrimmedTx `json:"txs"`
}

// EncodeTxsTrimmedReply encodes an TxsTrimmedReply into a JSON byte slice.
func EncodeTxsTrimmedReply(ttr TxsTrimmedReply) ([]byte, error) {
	return json.Marshal(ttr)
}

// DecodeTxsTrimmedReply decodes a JSON byte slice into a TxsTrimmedReply.
func DecodeTxsTrimmedReply(payload []byte) (*TxsTrimmedReply, error) {
	var ttr TxsTrimmedReply
	err := json.Unmarshal(payload, &ttr)
	if err != nil {
		return nil, err
	}
	return &ttr, nil
}
