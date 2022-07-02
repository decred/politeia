// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/util"
)

// subs contains the list of runoff vote submissions for a parent record. Every
// parent record with submissions will have a subs entry in the plugin cache.
//
// When a parent record hosts a runoff vote, child records can declare their
// intent to participate in the runoff vote using the VoteMetadata LinkTo
// field. The cached submissions list for the parent record is updated when the
// child record is made public.
//
// The submissions list will only contain public records. If a public record
// is part of the submissions list and then is updated to a non-public status,
// it's removed from the submissions list.
//
// See the subsClient structure for more information on how caching is handled.
type subs struct {
	Tokens map[string]struct{} `json:"tokens"`
}

// newSubs returns a new subs.
func newSubs() *subs {
	return &subs{
		Tokens: make(map[string]struct{}),
	}
}

// Add adds a record token to the submissions list.
func (s *subs) Add(token string) {
	s.Tokens[token] = struct{}{}
}

// Del deletes a record token from the submissions list.
func (s *subs) Del(token string) {
	delete(s.Tokens, token)
}

// subsClient provides an API for interacting with the runoff vote submissions
// cache. The data is savedd to the TstoreClient provided plugin cache.
//
// A mutex is required because tstore does not provide plugins with a sql
// transaction that can be used to execute multiple database requests
// atomically. Concurrent access to the subs cache during updates must be
// control locally using a mutex for now.
type subsClient struct {
	sync.Mutex
	tstore plugins.TstoreClient
}

// newSubsClient returns a new subsClient.
func newSubsClient(tstore plugins.TstoreClient) *subsClient {
	return &subsClient{
		tstore: tstore,
	}
}

// Add adds a runoff vote submission to the cached submissions list for the
// parent record.
//
// Plugin writes are not currently executed using a sql transaction, which
// means that there is no way to unwind previous writes if this cache update
// fails. For this reason, we panic instead of returning an error so that the
// sysadmin is alerted that the cache is incoherent and needs to be rebuilt.
//
// This function is concurrency safe.
func (c *subsClient) Add(parent, sub string) error {
	c.Lock()
	defer c.Unlock()

	err := c.add(parent, sub)
	if err != nil {
		e := fmt.Sprintf("%v %v: %v", parent, sub, err)
		panic(e)
	}

	log.Debugf("Sub %v added to runoff vote subs list %v", sub, parent)

	return nil
}

// Del deletes a runoff vote submission from the cached submissions list for
// the parent record.
//
// Plugin writes are not currently executed using a sql transaction, which
// means that there is no way to unwind previous writes if this cache update
// fails. For this reason, we panic instead of returning an error so that the
// sysadmin is alerted that the cache is incoherent and needs to be rebuilt.
//
// This function is concurrency safe.
func (c *subsClient) Del(parent, sub string) error {
	c.Lock()
	defer c.Unlock()

	err := c.del(parent, sub)
	if err != nil {
		e := fmt.Sprintf("%v %v: %v", parent, sub, err)
		panic(e)
	}

	log.Debugf("Sub %v deleted from runoff vote subs list %v", sub, parent)

	return nil
}

// DelEntry deletes a runoff vote submissions list from the cache. The full
// cache entry is deleted.
//
// This function is concurrency safe.
func (c *subsClient) DelEntry(parent string) error {
	c.Lock()
	defer c.Unlock()

	key, err := buildSubsKey(parent)
	if err != nil {
		return err
	}
	err = c.tstore.CacheDel([]string{key})
	if err != nil {
		return err
	}

	log.Debugf("Vote subs cache entry deleted %v", parent)

	return nil
}

// Get retrieves a runoff vote submissions list from the cache.
//
// A new subs is returned if a cache entry is not found for the record.
//
// This function is concurrency safe.
func (c *subsClient) Get(parent string) (*subs, error) {
	key, err := buildSubsKey(parent)
	if err != nil {
		return nil, err
	}
	entries, err := c.tstore.CacheGet([]string{key})
	if err != nil {
		return nil, err
	}
	b, ok := entries[key]
	if !ok {
		return newSubs(), nil
	}
	var s subs
	err = json.Unmarshal(b, &s)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// add adds a runoff vote submission to the cached submissions list for the
// parent record.
//
// This function is not concurrency safe. It must be called with the mutex
// locked.
func (c *subsClient) add(parent, sub string) error {
	s, err := c.Get(parent)
	if err != nil {
		return err
	}
	s.Add(sub)
	return c.save(parent, *s)
}

// del deletes a runoff vote submission from the cached submissions list for
// the parent record.
//
// This function is not concurrency safe. It must be called with the mutex
// locked.
func (c *subsClient) del(parent, sub string) error {
	s, err := c.Get(parent)
	if err != nil {
		return err
	}
	s.Del(sub)
	return c.save(parent, *s)
}

// save saves a sub to the tstore provided plugin cache.
func (c *subsClient) save(parent string, s subs) error {
	key, err := buildSubsKey(parent)
	if err != nil {
		return err
	}
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return c.tstore.CachePut(map[string][]byte{key: b}, false)
}

const (
	// subsKey is the key-value store key for an entry in the submissions cache.
	subsKey = "subs-{shorttoken}"
)

// buildSubsKey returns the submissions cache key for a record.
//
// The short token is used in the file path so that the submissions list can be
// retrieved using either the full token or the short token.
func buildSubsKey(parent string) (string, error) {
	t, err := util.ShortTokenString(parent)
	if err != nil {
		return "", err
	}
	return strings.Replace(subsKey, "{shorttoken}", t, 1), nil
}
