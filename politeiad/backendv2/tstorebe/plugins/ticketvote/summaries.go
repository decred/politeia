// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/plugins/ticketvote"
	"github.com/decred/politeia/util"
)

var (
	// errSummaryNotFound is returned when a vote summary is not found in the
	// cache for a record.
	errSummaryNotFound = errors.New("summary not found")
)

// summariesClient provides an API for interacting with the vote summaries
// cache. The data is saved to the TstoreClient provided plugin cache.
//
// Vote summaries are only cached once the vote has finished and additional
// updates to the record's vote data are no longer possible.
//
// tstore does not provide plugins with a sql transaction that can be used
// to execute multiple database requests atomically during cache updates.
// Concurrent access must be controlled locally using a mutex, but since the
// summaries are only written once and never updated, we don't need to worry
// about concurrency issues.
type summariesClient struct {
	tstore plugins.TstoreClient
}

// newSummariesClient returns a new summariesClient.
func newSummariesClient(tstore plugins.TstoreClient) *summariesClient {
	return &summariesClient{
		tstore: tstore,
	}
}

// Save saves a vote summary to the cache.
func (c *summariesClient) Save(token string, s ticketvote.SummaryReply) error {
	key, err := buildSummaryKey(token)
	if err != nil {
		return err
	}
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	err = c.tstore.CachePut(map[string][]byte{key: b}, false)
	if err != nil {
		return err
	}

	log.Debugf("Vote summary saved for %v", token)

	return nil
}

// Get retrieves a vote summary from the cache.
//
// An errSummaryNotFound is returned if a vote summary is not found in the
// cache for the record.
func (c *summariesClient) Get(token string) (*ticketvote.SummaryReply, error) {
	key, err := buildSummaryKey(token)
	if err != nil {
		return nil, err
	}
	entries, err := c.tstore.CacheGet([]string{key})
	if err != nil {
		return nil, err
	}
	b, ok := entries[key]
	if !ok {
		return nil, errSummaryNotFound
	}
	var sr ticketvote.SummaryReply
	err = json.Unmarshal(b, &sr)
	if err != nil {
		return nil, err
	}
	return &sr, nil
}

const (
	// summaryKey is the key-value store key for an entry in the vote summaries
	// cache. Each vote summary entry is saved as an individual database entry.
	// The "{shorttoken}" is replaced with the record's short token.
	summaryKey = "summary-{shorttoken}"
)

// buildSummaryKey returns the key-value store key for an entry in the vote
// summaries cache.
func buildSummaryKey(token string) (string, error) {
	s, err := util.ShortTokenString(token)
	if err != nil {
		return "", err
	}
	return strings.Replace(summaryKey, "{shorttoken}", s, 1), nil
}
