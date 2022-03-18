// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
)

// politeia.go contains all API requests to the politeia API.

const (
	politeiaHost = "https://proposals.decred.org/api"
)

// getUserIDByPubKey retrieves the user ID from the politeia API for the
// provided public key and returns it.
func (c *convertCmd) getUserIDByPubKey(userPubKey string) (string, error) {
	u, err := c.getUserByPubKey(userPubKey)
	if err != nil {
		return "", err
	}
	return u.ID, nil
}

// userReply is politeiawww's reply to the users request.
type usersReply struct {
	TotalUsers   uint64 `json:"totalusers,omitempty"`
	TotalMatches uint64 `json:"totalmatches"`
	Users        []user `json:"users"`
}

// user is returned from the politeiawww API.
type user struct {
	ID       string `json:"id"`
	Email    string `json:"email,omitempty"`
	Username string `json:"username"`
}

// getUserByPubKey makes a call to the politeia API requesting the user
// with the provided public key.
func (c *convertCmd) getUserByPubKey(pubkey string) (*user, error) {
	url := politeiaHost + "/v1/users?publickey=" + pubkey
	r, err := c.client.Get(url)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	var ur usersReply
	err = json.Unmarshal(body, &ur)
	if err != nil {
		return nil, err
	}

	if len(ur.Users) == 0 {
		return nil, fmt.Errorf("no user found for pubkey %v", pubkey)
	}

	return &ur.Users[0], nil
}
