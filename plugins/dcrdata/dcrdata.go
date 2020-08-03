// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package dcrdata

import "encoding/json"

type StatusT int

const (
	Version uint32 = 1
	ID             = "dcrdata"

	// Plugin commands
	CmdBestBlock = "bestblock"

	// Dcrdata connection statuses.
	//
	// Some commands will return cached results with the connection
	// status when dcrdata cannot be reached. It is the callers
	// responsibilty to determine the correct course of action when
	// dcrdata cannot be reached.
	StatusInvalid      StatusT = 0
	StatusConnected    StatusT = 1
	StatusDisconnected StatusT = 2
)

// BestBlock requests the best block. If dcrdata cannot be reached then the
// most recent cached best block will be returned along with a status of
// StatusDisconnected. It is the callers responsibility to determine if the
// stale best block should be used.
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
	Status    StatusT `json:"status"`
	BestBlock uint32  `json:"bestblock"`
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
