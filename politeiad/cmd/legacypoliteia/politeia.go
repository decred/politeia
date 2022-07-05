// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	v1 "github.com/decred/politeia/politeiawww/api/www/v1"
)

// politeia.go contains API requests to the politeia API.

const (
	politeiaHost = "https://proposals.decred.org/api"
)

// userByID retrieves and returns the user object from the politeia API using
// the provided user ID.
func userByID(c *http.Client, userID string) (*v1.User, error) {
	url := politeiaHost + "/v1/user/" + userID
	r, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	var udr v1.UserDetailsReply
	err = json.Unmarshal(body, &udr)
	if err != nil {
		return nil, err
	}

	return &udr.User, nil
}

// userByPubKey retrieves and returns the user object from the politeia API
// using the provided public key.
func userByPubKey(c *http.Client, pubkey string) (*v1.AbridgedUser, error) {
	url := politeiaHost + "/v1/users?publickey=" + pubkey
	r, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	var ur v1.UsersReply
	err = json.Unmarshal(body, &ur)
	if err != nil {
		return nil, err
	}

	if len(ur.Users) == 0 {
		return nil, fmt.Errorf("no user found for pubkey %v", pubkey)
	}

	return &ur.Users[0], nil
}
