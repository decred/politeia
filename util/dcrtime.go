package util

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/decred/dcrtime/api/v1"
	"github.com/decred/dcrtime/merkle"
)

var (
	skipVerify = false
	httpClient = &http.Client{
		Transport: &http.Transport{
			IdleConnTimeout: 60 * time.Second,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: skipVerify,
			},
		},
	}
)

// isTimestamp determines if a string is a valid SHA256 digest.
func isDigest(digest string) bool {
	return v1.RegexpSHA256.MatchString(digest)
}

func defaultTestnetHost() string {
	return "https://" + NormalizeAddress(v1.DefaultTestnetTimeHost,
		v1.DefaultTestnetTimePort)
}

func defaultMainnetHost() string {
	return "https://" + NormalizeAddress(v1.DefaultMainnetTimeHost,
		v1.DefaultMainnetTimePort)
}

// XXX duplicate function
// getError returns the error that is embedded in a JSON reply.
func getError(r io.Reader) (string, error) {
	var e interface{}
	decoder := json.NewDecoder(r)
	if err := decoder.Decode(&e); err != nil {
		return "", err
	}
	m, ok := e.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("Could not decode response")
	}
	rError, ok := m["error"]
	if !ok {
		return "", fmt.Errorf("No error response")
	}
	return fmt.Sprintf("%v", rError), nil
}

// Timestamp sends a Timestamp request to the provided host.  The caller is
// responsible for assembling the host string based on what net to use.
func Timestamp(host string, digests []*[sha256.Size]byte) error {
	// batch uploads
	ts := v1.Timestamp{
		ID:      "politeia",
		Digests: make([]string, 0, len(digests)),
	}
	for _, digest := range digests {
		ts.Digests = append(ts.Digests, hex.EncodeToString(digest[:]))
	}
	b, err := json.Marshal(ts)
	if err != nil {
		return err
	}

	r, err := httpClient.Post(host+v1.TimestampRoute, "application/json",
		bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		e, err := getError(r.Body)
		if err != nil {
			return fmt.Errorf("%v", r.Status)
		}
		return fmt.Errorf("%v: %v", r.Status, e)
	}

	// Decode response.
	var tsReply v1.TimestampReply
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&tsReply); err != nil {
		return fmt.Errorf("Could node decode TimestampReply: %v", err)
	}

	for i, result := range tsReply.Results {
		if result == v1.ResultExistsError {
			// Been alread anchored so ignore.
			continue
		}
		if result != v1.ResultOK {
			msg, ok := v1.Result[result]
			if !ok {
				msg = "UNKNOWN ERROR"
			}
			return fmt.Errorf("anchor (%v): %v", i, msg)
		}
	}

	return nil
}

// Verify sends a dcrtime Verify command to the provided host.  It checks and
// validates the entire reply.  A single failure is considered terminal and an
// error is returned.  If the reply is valid it is returned to the caller for
// further processing.  This means that the caller can be assured that all
// checks have been done and the data is readily usable.
func Verify(host string, digests []string) (*v1.VerifyReply, error) {
	ver := v1.Verify{
		ID: "politeia",
	}

	for _, digest := range digests {
		if isDigest(digest) {
			ver.Digests = append(ver.Digests, digest)
			continue
		}

		return nil, fmt.Errorf("not a valid digest: %v", digest)
	}

	// Convert Verify to JSON
	b, err := json.Marshal(ver)
	if err != nil {
		return nil, err
	}

	r, err := httpClient.Post(host+v1.VerifyRoute, "application/json",
		bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		e, err := getError(r.Body)
		if err != nil {
			return nil, fmt.Errorf("%v", r.Status)
		}
		return nil, fmt.Errorf("%v: %v", r.Status, e)
	}

	// Decode response.
	var vr v1.VerifyReply
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&vr); err != nil {
		return nil, fmt.Errorf("Could node decode VerifyReply: %v", err)
	}

	for _, v := range vr.Digests {
		_, ok := v1.Result[v.Result]
		if !ok {
			return nil, fmt.Errorf("%v invalid error code %v",
				v.Digest, v.Result)
		}

		// Verify merkle path.
		root, err := merkle.VerifyAuthPath(&v.ChainInformation.MerklePath)
		if err != nil {
			if err != merkle.ErrEmpty {
				return nil, fmt.Errorf("%v invalid auth path "+
					"%v", v.Digest, err)
			}
			return nil, fmt.Errorf("%v Not anchored", v.Digest)
		}

		// Verify merkle root.
		merkleRoot, err := hex.DecodeString(v.ChainInformation.MerkleRoot)
		if err != nil {
			return nil, fmt.Errorf("invalid merkle root: %v", err)
		}
		// This is silly since we check against returned root.
		if !bytes.Equal(root[:], merkleRoot) {
			return nil, fmt.Errorf("%v invalid merkle root",
				v.Digest)
		}

		// All good
	}

	return &vr, nil
}
