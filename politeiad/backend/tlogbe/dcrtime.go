package tlogbe

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	dcrtime "github.com/decred/dcrtime/api/v2"
	"github.com/decred/dcrtime/merkle"
	"github.com/decred/politeia/util"
)

var (
	// TODO flip skipVerify to false when done testing
	skipVerify = true
	httpClient = &http.Client{
		Timeout: 1 * time.Minute,
		Transport: &http.Transport{
			IdleConnTimeout:       1 * time.Minute,
			ResponseHeaderTimeout: 1 * time.Minute,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: skipVerify,
			},
		},
	}
)

// isDigest returns whether the provided digest is a valid SHA256 digest.
func isDigest(digest string) bool {
	return dcrtime.RegexpSHA256.MatchString(digest)
}

// timestampBatch posts the provided digests to the dcrtime v2 batch timestamp
// route.
func timestampBatch(host, id string, digests []string) (*dcrtime.TimestampBatchReply, error) {
	log.Tracef("timestampBatch: %v %v %v", host, id, digests)

	// Validate digests
	for _, v := range digests {
		if !isDigest(v) {
			return nil, fmt.Errorf("invalid digest: %v", v)
		}
	}

	// Setup request
	tb := dcrtime.TimestampBatch{
		ID:      id,
		Digests: digests,
	}
	b, err := json.Marshal(tb)
	if err != nil {
		return nil, err
	}

	// Send request
	route := host + dcrtime.TimestampBatchRoute
	r, err := httpClient.Post(route, "application/json", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	// Handle response
	if r.StatusCode != http.StatusOK {
		e, err := util.GetErrorFromJSON(r.Body)
		if err != nil {
			return nil, fmt.Errorf("%v", r.Status)
		}
		return nil, fmt.Errorf("%v: %v", r.Status, e)
	}
	var tbr dcrtime.TimestampBatchReply
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&tbr); err != nil {
		return nil, fmt.Errorf("decode TimestampBatchReply: %v", err)
	}

	return &tbr, nil
}

// verifyBatch returns the data to verify that a digest was included in a
// dcrtime timestamp. This function verifies the merkle path and merkle root of
// all successful timestamps. The caller is responsible for check the result
// code and handling digests that failed to be timestamped.
//
// Note the Result in the reply will be set to OK as soon as the digest is
// waiting to be anchored. All the ChainInformation fields will be populated
// once the digest has been included in a dcr transaction, except for the
// ChainTimestamp field. The ChainTimestamp field is only populated once the
// dcr transaction has 6 confirmations.
func verifyBatch(host, id string, digests []string) (*dcrtime.VerifyBatchReply, error) {
	log.Tracef("verifyBatch: %v %v %v", host, id, digests)

	// Validate digests
	for _, v := range digests {
		if !isDigest(v) {
			return nil, fmt.Errorf("invalid digest: %v", v)
		}
	}

	// Setup request
	vb := dcrtime.VerifyBatch{
		ID:      id,
		Digests: digests,
	}
	b, err := json.Marshal(vb)
	if err != nil {
		return nil, err
	}

	// Send request
	route := host + dcrtime.VerifyBatchRoute
	r, err := httpClient.Post(route, "application/json", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	// Handle response
	if r.StatusCode != http.StatusOK {
		e, err := util.GetErrorFromJSON(r.Body)
		if err != nil {
			return nil, fmt.Errorf("%v", r.Status)
		}
		return nil, fmt.Errorf("%v: %v", r.Status, e)
	}
	var vbr dcrtime.VerifyBatchReply
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&vbr); err != nil {
		return nil, fmt.Errorf("decode VerifyBatchReply: %v", err)
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
