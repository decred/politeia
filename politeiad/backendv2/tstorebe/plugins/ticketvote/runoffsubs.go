// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import (
	"encoding/json"
	"strings"

	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
	"github.com/decred/politeia/util"
	"github.com/pkg/errors"
)

const (
	// runoffSubKey is the key-value store key for a runoff
	// submissions cache entry.
	//
	// {shorttoken} is replaced with the record's short token.
	runoffSubsKey = pluginID + "-{shorttoken}-runoffsubs-v1"
)

// runoffSubs contains the list of runoff vote submissions for the parent
// record.
//
// The token in the runoffSubsKey is the token of the parent record. The tokens
// list in this struct is the list of all vetted submissions that have linked
// to the parent record using the VoteMetadata LinkTo field. This includes
// records with an archived record status. Censored records are removed from
// the list.
type runoffSubs struct {
	Parent string              `json:"parent"` // Parent token
	Subs   map[string]struct{} `json:"tokens"` // Submission tokens
}

// newRunoffSubs returns a new runoffSubs.
func newRunoffSubs(parent string) *runoffSubs {
	return &runoffSubs{
		Parent: parent,
		Subs:   make(map[string]struct{}, 256),
	}
}

// add adds a token to the submissions list.
func (r *runoffSubs) add(token string) {
	r.Subs[token] = struct{}{}

	log.Debugf("Runoff submission %v added to submissions list %v",
		token, r.Parent)
}

// del deletes a token from the submissions list.
func (r *runoffSubs) del(token string) {
	delete(r.Subs, token)

	log.Debugf("Runoff submission %v deleted from submissions list %v",
		token, r.Parent)
}

// save saves the runoffSubs to the cache.
func (r *runoffSubs) save(tstore plugins.TstoreClient) error {
	// Get kv store key
	key, err := getRunoffSubsKey(r.Parent)
	if err != nil {
		return err
	}

	// Encode payload
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}

	// Save the payload. This could be the first time
	// the record subs is being save for this record.
	c := tstore.CacheClient(false)
	kv := map[string][]byte{key: b}
	err = c.Update(kv)
	if err == store.ErrNotFound {
		// A runoff subs has not been save
		// for this record yet. Insert one.
		err = c.Insert(kv)
	}
	return err
}

// getRunoffSubs returns the runoffSubs for a record. A new runoffSubs will be
// returned if one does not exist yet.
func getRunoffSubs(tstore plugins.TstoreClient, token string) (*runoffSubs, error) {
	// Get kv store key
	key, err := getRunoffSubsKey(token)
	if err != nil {
		return nil, err
	}

	// Get blob from the kv store
	c := tstore.CacheClient(false)
	b, err := c.Get(key)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// A runoffSubs does not exist for this
			// record yet. Return a new one.
			return newRunoffSubs(token), nil
		}
		return nil, err
	}

	// Decode blob
	var rs runoffSubs
	err = json.Unmarshal(b, &rs)
	if err != nil {
		return nil, err
	}

	return &rs, nil
}

// getRunoffSubsKey returns the key for a record's cached runoff submissions
// list.
func getRunoffSubsKey(token string) (string, error) {
	shortToken, err := util.ShortTokenString(token)
	if err != nil {
		return "", err
	}
	k := strings.Replace(runoffSubsKey, "{shorttoken}", shortToken, 1)
	return k, nil
}
