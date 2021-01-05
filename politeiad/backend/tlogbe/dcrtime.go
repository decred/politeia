// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package tlogbe

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	dcrtime "github.com/decred/dcrtime/api/v2"
	"github.com/decred/dcrtime/merkle"
	"github.com/decred/politeia/util"
)

// dcrtimeClient is a client for interacting with the dcrtime API.
type dcrtimeClient struct {
	host     string
	certPath string
	http     *http.Client
}

// isDigestSHA256 returns whether the provided digest is a valid SHA256 digest.
func isDigestSHA256(digest string) bool {
	return dcrtime.RegexpSHA256.MatchString(digest)
}

// makeReq makes an http request to a dcrtime method and route, serializing the
// provided object as the request body. The response body is returned as a byte
// slice.
func (c *dcrtimeClient) makeReq(method string, route string, v interface{}) ([]byte, error) {
	var (
		reqBody []byte
		err     error
	)
	if v != nil {
		reqBody, err = json.Marshal(v)
		if err != nil {
			return nil, err
		}
	}

	fullRoute := c.host + route

	log.Tracef("%v %v", method, fullRoute)

	req, err := http.NewRequest(method, fullRoute, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}

	r, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		e, err := util.GetErrorFromJSON(r.Body)
		if err != nil {
			return nil, fmt.Errorf("%v", r.Status)
		}
		return nil, fmt.Errorf("%v: %v", r.Status, e)
	}

	respBody := util.ConvertBodyToByteArray(r.Body, false)
	return respBody, nil
}

// timestampBatch posts digests to the dcrtime v2 batch timestamp route.
func (c *dcrtimeClient) timestampBatch(id string, digests []string) (*dcrtime.TimestampBatchReply, error) {
	log.Tracef("timestampBatch: %v %v", id, digests)

	// Setup request
	for _, v := range digests {
		if !isDigestSHA256(v) {
			return nil, fmt.Errorf("invalid digest: %v", v)
		}
	}
	tb := dcrtime.TimestampBatch{
		ID:      id,
		Digests: digests,
	}

	// Send request
	respBody, err := c.makeReq(http.MethodPost, dcrtime.TimestampBatchRoute, tb)
	if err != nil {
		return nil, err
	}

	// Decode reply
	var tbr dcrtime.TimestampBatchReply
	err = json.Unmarshal(respBody, &tbr)
	if err != nil {
		return nil, err
	}

	return &tbr, nil
}

// verifyBatch returns the data to verify that a digest was included in a
// dcrtime timestamp. This function verifies the merkle path and merkle root of
// all successful timestamps. The caller is responsible for checking the result
// code and handling digests that failed to be timestamped.
//
// Note the Result in the reply will be set to OK as soon as the digest is
// waiting to be anchored. All the ChainInformation fields will be populated
// once the digest has been included in a dcr transaction, except for the
// ChainTimestamp field. The ChainTimestamp field is only populated once the
// dcr transaction has 6 confirmations.
func (c *dcrtimeClient) verifyBatch(id string, digests []string) (*dcrtime.VerifyBatchReply, error) {
	log.Tracef("verifyBatch: %v %v", id, digests)

	// Setup request
	for _, v := range digests {
		if !isDigestSHA256(v) {
			return nil, fmt.Errorf("invalid digest: %v", v)
		}
	}
	vb := dcrtime.VerifyBatch{
		ID:      id,
		Digests: digests,
	}

	// Send request
	respBody, err := c.makeReq(http.MethodPost, dcrtime.VerifyBatchRoute, vb)
	if err != nil {
		return nil, err
	}

	// Decode reply
	var vbr dcrtime.VerifyBatchReply
	err = json.Unmarshal(respBody, &vbr)
	if err != nil {
		return nil, err
	}

	// Verify the merkle path and the merkle root of the timestamps
	// that were successful. The caller is responsible for handling
	// the digests that failed be timestamped.
	for _, v := range vbr.Digests {
		if v.Result != dcrtime.ResultOK {
			// Nothing to verify
			continue
		}

		// Verify merkle path
		root, err := merkle.VerifyAuthPath(&v.ChainInformation.MerklePath)
		if err != nil {
			if errors.Is(err, merkle.ErrEmpty) {
				// A dcr transaction has not been sent yet so there is
				// nothing to verify.
				continue
			}
			return nil, fmt.Errorf("VerifyAuthPath %v: %v", v.Digest, err)
		}

		// Verify merkle root
		merkleRoot, err := hex.DecodeString(v.ChainInformation.MerkleRoot)
		if err != nil {
			return nil, fmt.Errorf("invalid merkle root: %v", err)
		}
		if !bytes.Equal(merkleRoot, root[:]) {
			return nil, fmt.Errorf("invalid merkle root %v: got %x, want %x",
				v.Digest, merkleRoot, root[:])
		}
	}

	return &vbr, nil
}

// newDcrtimeClient returns a new dcrtimeClient.
func newDcrtimeClient(host, certPath string) (*dcrtimeClient, error) {
	c, err := util.NewHTTPClient(false, certPath)
	if err != nil {
		return nil, err
	}
	return &dcrtimeClient{
		host:     host,
		certPath: certPath,
		http:     c,
	}, nil
}
