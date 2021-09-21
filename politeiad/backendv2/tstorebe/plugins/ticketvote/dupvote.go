// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import (
	"strings"

	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
)

const (
	// dupVoteKey is the key-value store for a empty vote record that
	// is used to verify that a ticket is not attempting to vote more
	// than one time.
	dupVoteKey = pluginID + "-{token}-dupvote-{ticket}"
)

// saveVoteToDupsCache inserts a dup vote entry into the cache.
func saveVoteToDupsCache(tstore plugins.TstoreClient, token, ticket string) error {
	c := tstore.CacheClient(false)
	kv := map[string][]byte{
		getDupVoteKey(token, ticket): []byte{},
	}
	return c.Insert(kv)
}

// voteIsDuplicate returns whether the provided ticket has already been used to
// cast a vote.
func voteIsDuplicate(tstore plugins.TstoreClient, token, ticket string) (bool, error) {
	c := tstore.CacheClient(false)
	_, err := c.Get(getDupVoteKey(token, ticket))
	if err == store.ErrNotFound {
		// Cached dup vote does not exist.
		// This vote is not a duplicate.
		return false, nil
	}
	if err != nil {
		return false, err
	}

	// Dup vote entry exists
	return true, nil
}

// getDupVoteKey returns the dupVoteKey for the provided token and ticket.
func getDupVoteKey(token, ticket string) string {
	k := strings.Replace(dupVoteKey, "{token}", token, 1)
	return strings.Replace(k, "{ticket}", ticket, 1)
}
