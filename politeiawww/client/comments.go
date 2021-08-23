// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package client

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	backend "github.com/decred/politeia/politeiad/backendv2"
	cmv1 "github.com/decred/politeia/politeiawww/api/comments/v1"
	"github.com/decred/politeia/util"
)

// CommentPolicy sends a comments v1 Policy request to politeiawww.
func (c *Client) CommentPolicy() (*cmv1.PolicyReply, error) {
	resBody, err := c.makeReq(http.MethodPost,
		cmv1.APIRoute, cmv1.RoutePolicy, nil)
	if err != nil {
		return nil, err
	}

	var pr cmv1.PolicyReply
	err = json.Unmarshal(resBody, &pr)
	if err != nil {
		return nil, err
	}

	return &pr, nil
}

// CommentNew sends a comments v1 New request to politeiawww.
func (c *Client) CommentNew(n cmv1.New) (*cmv1.NewReply, error) {
	resBody, err := c.makeReq(http.MethodPost,
		cmv1.APIRoute, cmv1.RouteNew, n)
	if err != nil {
		return nil, err
	}

	var nr cmv1.NewReply
	err = json.Unmarshal(resBody, &nr)
	if err != nil {
		return nil, err
	}

	return &nr, nil
}

// CommentVote sends a comments v1 Vote request to politeiawww.
func (c *Client) CommentVote(v cmv1.Vote) (*cmv1.VoteReply, error) {
	resBody, err := c.makeReq(http.MethodPost,
		cmv1.APIRoute, cmv1.RouteVote, v)
	if err != nil {
		return nil, err
	}

	var vr cmv1.VoteReply
	err = json.Unmarshal(resBody, &vr)
	if err != nil {
		return nil, err
	}

	return &vr, nil
}

// CommentDel sends a comments v1 Del request to politeiawww.
func (c *Client) CommentDel(d cmv1.Del) (*cmv1.DelReply, error) {
	resBody, err := c.makeReq(http.MethodPost,
		cmv1.APIRoute, cmv1.RouteDel, d)
	if err != nil {
		return nil, err
	}

	var dr cmv1.DelReply
	err = json.Unmarshal(resBody, &dr)
	if err != nil {
		return nil, err
	}

	return &dr, nil
}

// CommentCount sends a comments v1 Count request to politeiawww.
func (c *Client) CommentCount(cc cmv1.Count) (*cmv1.CountReply, error) {
	resBody, err := c.makeReq(http.MethodPost,
		cmv1.APIRoute, cmv1.RouteCount, cc)
	if err != nil {
		return nil, err
	}

	var cr cmv1.CountReply
	err = json.Unmarshal(resBody, &cr)
	if err != nil {
		return nil, err
	}

	return &cr, nil
}

// Comments sends a comments v1 Comments request to politeiawww.
func (c *Client) Comments(cm cmv1.Comments) (*cmv1.CommentsReply, error) {
	resBody, err := c.makeReq(http.MethodPost,
		cmv1.APIRoute, cmv1.RouteComments, cm)
	if err != nil {
		return nil, err
	}

	var cr cmv1.CommentsReply
	err = json.Unmarshal(resBody, &cr)
	if err != nil {
		return nil, err
	}

	return &cr, nil
}

// CommentVotes sends a comments v1 Votes request to politeiawww.
func (c *Client) CommentVotes(v cmv1.Votes) (*cmv1.VotesReply, error) {
	resBody, err := c.makeReq(http.MethodPost,
		cmv1.APIRoute, cmv1.RouteVotes, v)
	if err != nil {
		return nil, err
	}

	var vr cmv1.VotesReply
	err = json.Unmarshal(resBody, &vr)
	if err != nil {
		return nil, err
	}

	return &vr, nil
}

// CommentTimestamps sends a comments v1 Timestamps request to politeiawww.
func (c *Client) CommentTimestamps(t cmv1.Timestamps) (*cmv1.TimestampsReply, error) {
	resBody, err := c.makeReq(http.MethodPost,
		cmv1.APIRoute, cmv1.RouteTimestamps, t)
	if err != nil {
		return nil, err
	}

	var tr cmv1.TimestampsReply
	err = json.Unmarshal(resBody, &tr)
	if err != nil {
		return nil, err
	}

	return &tr, nil
}

// commentDelVerify verifies the signature of a comment that has been deleted.
// The signature will be from the deletion event, not the original comment
// submission.
func commentDelVerify(c cmv1.Comment, serverPublicKey string) error {
	if !c.Deleted {
		return fmt.Errorf("not a deleted comment")
	}

	// Verify delete action. The deletion signature is of the
	// State+Token+CommentID+Reason.
	msg := strconv.FormatUint(uint64(c.State), 10) + c.Token +
		strconv.FormatUint(uint64(c.CommentID), 10) + c.Reason
	err := util.VerifySignature(c.Signature, c.PublicKey, msg)
	if err != nil {
		return fmt.Errorf("unable to verify comment %v del signature: %v",
			c.CommentID, err)
	}

	// Verify receipt. Receipt is the server signature of the client
	// signature.
	err = util.VerifySignature(c.Receipt, serverPublicKey, c.Signature)
	if err != nil {
		return fmt.Errorf("unable to verify comment %v receipt: %v",
			c.CommentID, err)
	}

	return nil
}

// CommentVerify verifies the comment signature and receipt. If the comment
// has been deleted then the deletion signature and receipt will be verified.
func CommentVerify(c cmv1.Comment, serverPublicKey string) error {
	if c.Deleted {
		return commentDelVerify(c, serverPublicKey)
	}

	// Verify comment. The signature is the client signature of the
	// State + Token + ParentID + Comment + ExtraData + ExtraDataHint.
	msg := strconv.FormatUint(uint64(c.State), 10) + c.Token +
		strconv.FormatUint(uint64(c.ParentID), 10) + c.Comment +
		c.ExtraData + c.ExtraDataHint
	err := util.VerifySignature(c.Signature, c.PublicKey, msg)
	if err != nil {
		return fmt.Errorf("unable to verify comment %v signature: %v",
			c.CommentID, err)
	}

	// Verify receipt. The receipt is the server signature of the
	// client signature.
	err = util.VerifySignature(c.Receipt, serverPublicKey, c.Signature)
	if err != nil {
		return fmt.Errorf("unable to verify comment %v receipt: %v",
			c.CommentID, err)
	}

	return nil
}

// CommentTimestampVerify verifies that all timestamps in the provided
// CommentTimestamp are valid.
func CommentTimestampVerify(ct cmv1.CommentTimestamp) error {
	// Verify comment adds
	for i, ts := range ct.Adds {
		err := backend.VerifyTimestamp(convertCommentTimestamp(ts))
		if err != nil {
			if err == backend.ErrNotTimestamped {
				return err
			}
			return fmt.Errorf("verify comment add timestamp %v: %v", i, err)
		}
	}

	// Verify comment del if one exists
	if ct.Del == nil {
		return nil
	}
	err := backend.VerifyTimestamp(convertCommentTimestamp(*ct.Del))
	if err != nil {
		if err == backend.ErrNotTimestamped {
			return err
		}
		return fmt.Errorf("verify comment del timestamp: %v", err)
	}

	return nil
}

// CommentTimestampsVerify verifies that all timestamps in a comments v1
// TimestampsReply are valid. The IDs of comments that have not been anchored
// yet are returned.
func CommentTimestampsVerify(tr cmv1.TimestampsReply) ([]uint32, error) {
	notTimestamped := make([]uint32, 0, len(tr.Comments))
	for cid, v := range tr.Comments {
		err := CommentTimestampVerify(v)
		if err != nil {
			if err == backend.ErrNotTimestamped {
				notTimestamped = append(notTimestamped, cid)
				continue
			}
			return nil, fmt.Errorf("unable to verify comment %v timestamp: %v",
				cid, err)
		}
	}
	return notTimestamped, nil
}

func convertCommentProof(p cmv1.Proof) backend.Proof {
	return backend.Proof{
		Type:       p.Type,
		Digest:     p.Digest,
		MerkleRoot: p.MerkleRoot,
		MerklePath: p.MerklePath,
		ExtraData:  p.ExtraData,
	}
}

func convertCommentTimestamp(t cmv1.Timestamp) backend.Timestamp {
	proofs := make([]backend.Proof, 0, len(t.Proofs))
	for _, v := range t.Proofs {
		proofs = append(proofs, convertCommentProof(v))
	}
	return backend.Timestamp{
		Data:       t.Data,
		Digest:     t.Digest,
		TxID:       t.TxID,
		MerkleRoot: t.MerkleRoot,
		Proofs:     proofs,
	}
}
