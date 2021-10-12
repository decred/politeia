// Copyright (c) 2017-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"

	v1 "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/politeiad/api/v1/identity"
	"github.com/decred/politeia/util"
)

// getIdentity fetches the remote identity from politeiad and saves it to
// disk. politeiawww loads it from disk on future startups during config
// initialization.
func getIdentity(rpcHost, rpcCert, rpcIdentityFile, interactive string) error {
	id, err := remoteIdentity(false, rpcHost, rpcCert)
	if err != nil {
		return err
	}

	// Pretty print identity.
	log.Infof("Identity fetched from politeiad")
	log.Infof("Key        : %x", id.Key)
	log.Infof("Fingerprint: %v", id.Fingerprint())

	if interactive == "" {
		// Ask user if we like this identity
		log.Infof("Press enter to save to %v or ctrl-c to abort",
			rpcIdentityFile)
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		if err = scanner.Err(); err != nil {
			return err
		}
	} else {
		log.Infof("Saving identity to %v", rpcIdentityFile)
	}

	// Save identity
	err = os.MkdirAll(filepath.Dir(rpcIdentityFile), 0700)
	if err != nil {
		return err
	}
	err = id.SavePublicIdentity(rpcIdentityFile)
	if err != nil {
		return err
	}
	log.Infof("Identity saved to: %v", rpcIdentityFile)

	return nil
}

// remoteIdentity fetches the identity from politeiad.
func remoteIdentity(skipTLSVerify bool, host, cert string) (*identity.PublicIdentity, error) {
	challenge, err := util.Random(v1.ChallengeSize)
	if err != nil {
		return nil, err
	}
	id, err := json.Marshal(v1.Identity{
		Challenge: hex.EncodeToString(challenge),
	})
	if err != nil {
		return nil, err
	}

	c, err := util.NewHTTPClient(skipTLSVerify, cert)
	if err != nil {
		return nil, err
	}
	r, err := c.Post(host+v1.IdentityRoute, "application/json",
		bytes.NewReader(id))
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

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	var ir v1.IdentityReply
	err = json.Unmarshal(body, &ir)
	if err != nil {
		return nil, fmt.Errorf("Could node unmarshal IdentityReply: %v",
			err)
	}

	// Convert and verify server identity
	identity, err := identity.PublicIdentityFromString(ir.PublicKey)
	if err != nil {
		return nil, err
	}

	err = util.VerifyChallenge(identity, challenge, ir.Response)
	if err != nil {
		return nil, err
	}

	return identity, nil
}
