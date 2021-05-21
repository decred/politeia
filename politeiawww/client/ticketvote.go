// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package client

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/decred/dcrd/chaincfg/v3"
	backend "github.com/decred/politeia/politeiad/backendv2"
	tkv1 "github.com/decred/politeia/politeiawww/api/ticketvote/v1"
	"github.com/decred/politeia/util"
)

// TicketVotePolicy sends a ticketvote v1 Policy request to politeiawww.
func (c *Client) TicketVotePolicy() (*tkv1.PolicyReply, error) {
	resBody, err := c.makeReq(http.MethodPost,
		tkv1.APIRoute, tkv1.RoutePolicy, nil)
	if err != nil {
		return nil, err
	}

	var pr tkv1.PolicyReply
	err = json.Unmarshal(resBody, &pr)
	if err != nil {
		return nil, err
	}

	return &pr, nil
}

// TicketVoteAuthorize sends a ticketvote v1 Authorize request to politeiawww.
func (c *Client) TicketVoteAuthorize(a tkv1.Authorize) (*tkv1.AuthorizeReply, error) {
	resBody, err := c.makeReq(http.MethodPost,
		tkv1.APIRoute, tkv1.RouteAuthorize, a)
	if err != nil {
		return nil, err
	}

	var ar tkv1.AuthorizeReply
	err = json.Unmarshal(resBody, &ar)
	if err != nil {
		return nil, err
	}

	return &ar, nil
}

// TicketVoteStart sends a ticketvote v1 Start request to politeiawww.
func (c *Client) TicketVoteStart(s tkv1.Start) (*tkv1.StartReply, error) {
	resBody, err := c.makeReq(http.MethodPost,
		tkv1.APIRoute, tkv1.RouteStart, s)
	if err != nil {
		return nil, err
	}

	var sr tkv1.StartReply
	err = json.Unmarshal(resBody, &sr)
	if err != nil {
		return nil, err
	}

	return &sr, nil
}

// TicketVoteCastBallot sends a ticketvote v1 CastBallot request to
// politeiawww.
func (c *Client) TicketVoteCastBallot(cb tkv1.CastBallot) (*tkv1.CastBallotReply, error) {
	resBody, err := c.makeReq(http.MethodPost,
		tkv1.APIRoute, tkv1.RouteCastBallot, cb)
	if err != nil {
		return nil, err
	}

	var cbr tkv1.CastBallotReply
	err = json.Unmarshal(resBody, &cbr)
	if err != nil {
		return nil, err
	}

	return &cbr, nil
}

// TicketVoteDetails sends a ticketvote v1 Details request to politeiawww.
func (c *Client) TicketVoteDetails(d tkv1.Details) (*tkv1.DetailsReply, error) {
	resBody, err := c.makeReq(http.MethodPost,
		tkv1.APIRoute, tkv1.RouteDetails, d)
	if err != nil {
		return nil, err
	}

	var dr tkv1.DetailsReply
	err = json.Unmarshal(resBody, &dr)
	if err != nil {
		return nil, err
	}

	return &dr, nil
}

// TicketVoteResults sends a ticketvote v1 Results request to politeiawww.
func (c *Client) TicketVoteResults(r tkv1.Results) (*tkv1.ResultsReply, error) {
	resBody, err := c.makeReq(http.MethodPost,
		tkv1.APIRoute, tkv1.RouteResults, r)
	if err != nil {
		return nil, err
	}

	var rr tkv1.ResultsReply
	err = json.Unmarshal(resBody, &rr)
	if err != nil {
		return nil, err
	}

	return &rr, nil
}

// TicketVoteSummaries sends a ticketvote v1 Summaries request to politeiawww.
func (c *Client) TicketVoteSummaries(s tkv1.Summaries) (*tkv1.SummariesReply, error) {
	resBody, err := c.makeReq(http.MethodPost,
		tkv1.APIRoute, tkv1.RouteSummaries, s)
	if err != nil {
		return nil, err
	}

	var sr tkv1.SummariesReply
	err = json.Unmarshal(resBody, &sr)
	if err != nil {
		return nil, err
	}

	return &sr, nil
}

// TicketVoteSubmissions sends a ticketvote v1 Submissions request to
// politeiawww.
func (c *Client) TicketVoteSubmissions(s tkv1.Submissions) (*tkv1.SubmissionsReply, error) {
	resBody, err := c.makeReq(http.MethodPost,
		tkv1.APIRoute, tkv1.RouteSubmissions, s)
	if err != nil {
		return nil, err
	}

	var sr tkv1.SubmissionsReply
	err = json.Unmarshal(resBody, &sr)
	if err != nil {
		return nil, err
	}

	return &sr, nil
}

// TicketVoteInventory sends a ticketvote v1 Inventory request to politeiawww.
func (c *Client) TicketVoteInventory(i tkv1.Inventory) (*tkv1.InventoryReply, error) {
	resBody, err := c.makeReq(http.MethodPost,
		tkv1.APIRoute, tkv1.RouteInventory, i)
	if err != nil {
		return nil, err
	}

	var ir tkv1.InventoryReply
	err = json.Unmarshal(resBody, &ir)
	if err != nil {
		return nil, err
	}

	return &ir, nil
}

// TicketVoteTimestamps sends a ticketvote v1 Timestamps request to
// politeiawww.
func (c *Client) TicketVoteTimestamps(t tkv1.Timestamps) (*tkv1.TimestampsReply, error) {
	resBody, err := c.makeReq(http.MethodPost,
		tkv1.APIRoute, tkv1.RouteTimestamps, t)
	if err != nil {
		return nil, err
	}

	var tr tkv1.TimestampsReply
	err = json.Unmarshal(resBody, &tr)
	if err != nil {
		return nil, err
	}

	return &tr, nil
}

// TicketVoteTimestampVerify verifies that the provided ticketvote v1 Timestamp
// is valid.
func TicketVoteTimestampVerify(t tkv1.Timestamp) error {
	return backend.VerifyTimestamp(convertVoteTimestamp(t))
}

// TicketVoteTimestampsVerify verifies that all timestamps in the ticketvote
// v1 TimestampsReply are valid.
func TicketVoteTimestampsVerify(tr tkv1.TimestampsReply) error {
	// Verify authorization timestamps
	for k, v := range tr.Auths {
		err := TicketVoteTimestampVerify(v)
		if err != nil {
			return fmt.Errorf("verify authorization %v timestamp: %v", k, err)
		}
	}

	// Verify vote details timestamp
	if tr.Details != nil {
		err := TicketVoteTimestampVerify(*tr.Details)
		if err != nil {
			return fmt.Errorf("verify vote details timestamp: %v", err)
		}
	}

	// Verify vote timestamps
	for k, v := range tr.Votes {
		err := TicketVoteTimestampVerify(v)
		if err != nil {
			return fmt.Errorf("verify vote %v timestamp: %v", k, err)
		}
	}

	return nil
}

// AuthDetailsVerify verifies the action, signature, and receipt of the
// provided ticketvote v1 AuthDetails.
func AuthDetailsVerify(a tkv1.AuthDetails, serverPublicKey string) error {
	// Verify action
	switch tkv1.AuthActionT(a.Action) {
	case tkv1.AuthActionAuthorize, tkv1.AuthActionRevoke:
		// These are allowed; continue
	default:
		return fmt.Errorf("invalid auth action '%v'", a.Action)
	}

	// Verify signature
	msg := a.Token + strconv.FormatUint(uint64(a.Version), 10) + a.Action
	err := util.VerifySignature(a.Signature, a.PublicKey, msg)
	if err != nil {
		return fmt.Errorf("verify signature: %v", err)
	}

	// Verify receipt
	err = util.VerifySignature(a.Receipt, serverPublicKey, a.Signature)
	if err != nil {
		return fmt.Errorf("verify receipt: %v", err)
	}

	return nil
}

// VoteDetailsVerify verifies the signature and receipt of the provided
// ticketvote v1 VoteDetails.
func VoteDetailsVerify(vd tkv1.VoteDetails, serverPublicKey string) error {
	// Verify client signature
	b, err := json.Marshal(vd.Params)
	if err != nil {
		return err
	}
	msg := hex.EncodeToString(util.Digest(b))
	err = util.VerifySignature(vd.Signature, vd.PublicKey, msg)
	if err != nil {
		return fmt.Errorf("could not verify signature: %v", err)
	}

	// Make sure we have valid vote bits.
	switch {
	case vd.Params.Token == "":
		return fmt.Errorf("token not found")
	case vd.Params.Mask == 0:
		return fmt.Errorf("mask not found")
	case len(vd.Params.Options) == 0:
		return fmt.Errorf("vote options not found")
	}

	// Verify server receipt
	msg = vd.Signature + vd.StartBlockHash
	err = util.VerifySignature(vd.Receipt, serverPublicKey, msg)
	if err != nil {
		return fmt.Errorf("could not verify receipt: %v", err)
	}

	return nil
}

// CastVoteDetailsVerify verifies the receipt of the provided ticketvote v1
// CastVoteDetails.
func CastVoteDetailsVerify(cvd tkv1.CastVoteDetails, serverPublicKey string) error {
	// The network must be ascertained in order to verify the
	// signature. We can do this by looking at the P2PKH prefix.
	var net *chaincfg.Params
	switch cvd.Address[:2] {
	case "Ds":
		// Mainnet
		net = chaincfg.MainNetParams()
	case "Ts":
		// Testnet
		net = chaincfg.TestNet3Params()
	case "Ss":
		// Simnet
		net = chaincfg.SimNetParams()
	default:
		return fmt.Errorf("unknown p2pkh address %v", cvd.Address)
	}

	// Verify signature. The signature must be converted from hex to
	// base64. This is what the verify message function expects.
	msg := cvd.Token + cvd.Ticket + cvd.VoteBit
	b, err := hex.DecodeString(cvd.Signature)
	if err != nil {
		return fmt.Errorf("signature invalid hex")
	}
	sig := base64.StdEncoding.EncodeToString(b)
	validated, err := util.VerifyMessage(cvd.Address, msg, sig, net)
	if err != nil {
		return err
	}
	if !validated {
		return fmt.Errorf("invalid cast vote signature")
	}

	// Verify receipt
	err = util.VerifySignature(cvd.Receipt, serverPublicKey, cvd.Signature)
	if err != nil {
		return fmt.Errorf("could not verify receipt: %v", err)
	}

	return nil
}

func convertVoteProof(p tkv1.Proof) backend.Proof {
	return backend.Proof{
		Type:       p.Type,
		Digest:     p.Digest,
		MerkleRoot: p.MerkleRoot,
		MerklePath: p.MerklePath,
		ExtraData:  p.ExtraData,
	}
}

func convertVoteTimestamp(t tkv1.Timestamp) backend.Timestamp {
	proofs := make([]backend.Proof, 0, len(t.Proofs))
	for _, v := range t.Proofs {
		proofs = append(proofs, convertVoteProof(v))
	}
	return backend.Timestamp{
		Data:       t.Data,
		Digest:     t.Digest,
		TxID:       t.TxID,
		MerkleRoot: t.MerkleRoot,
		Proofs:     proofs,
	}
}
