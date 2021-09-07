// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package usermd

import (
	"encoding/json"
	"strings"

	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/store"
	"github.com/decred/politeia/politeiad/plugins/usermd"
	"github.com/pkg/errors"
)

const (
	// userCacheKey is the format that the key-value store key uses
	// for the userCache data. The "{userid}" is replaced by the real
	// user ID.
	userCacheKey = usermd.PluginID + "-{userid}"
)

// userCache contains cached user metadata for an individual user. The data is
// saved to the tstore key-value cache with the user ID encoded in the key.
//
// The Unvetted and Vetted fields contain the records that have been submitted
// by the user. All record tokens are sorted by the timestamp of the state
// change (unvetted/vetted) from oldest to newest.
type userCache struct {
	Unvetted []string `json:"unvetted"`
	Vetted   []string `json:"vetted"`
}

// userCache returns the userCache for the specified user.
func (p *usermdPlugin) userCache(tstore plugins.TstoreClient, userID string) (*userCache, error) {
	// Get cache client
	c := tstore.CacheClient(true)

	// Get cached data
	key := getUserCacheKey(userID)
	blobs, err := c.GetBatch([]string{key})
	if err != nil {
		return nil, err
	}
	b, ok := blobs[key]
	if !ok {
		// Cache entry does't exist. Return an empty one.
		return &userCache{
			Unvetted: []string{},
			Vetted:   []string{},
		}, nil
	}

	// Decode cached blob
	var uc userCache
	err = json.Unmarshal(b, &uc)
	if err != nil {
		return nil, err
	}

	return &uc, nil
}

// userCacheSave saves the provided userCache object to the tstore cache.
func (p *usermdPlugin) userCacheSave(tstore plugins.TstoreClient, userID string, uc userCache) error {
	b, err := json.Marshal(uc)
	if err != nil {
		return err
	}
	// Encrypt the user cache so that unvetted data
	// is not leaked.
	c := tstore.CacheClient(true)
	kv := map[string][]byte{getUserCacheKey(userID): b}
	err = c.Update(kv)
	if errors.Is(err, store.ErrNotFound) {
		// An entry doesn't exist in the kv
		// store yet. Insert a new one.
		err = c.Insert(kv)
	}
	return err
}

// userCacheAddToken adds a token to a user cache.
func (p *usermdPlugin) userCacheAddToken(tstore plugins.TstoreClient, userID string, state backend.StateT, token string) error {
	// Get current user data
	uc, err := p.userCache(tstore, userID)
	if err != nil {
		return err
	}

	// Add token
	switch state {
	case backend.StateUnvetted:
		uc.Unvetted = append(uc.Unvetted, token)
	case backend.StateVetted:
		uc.Vetted = append(uc.Vetted, token)
	default:
		return errors.Errorf("invalid state %v", state)
	}

	// Save changes
	err = p.userCacheSave(tstore, userID, *uc)
	if err != nil {
		return err
	}

	log.Debugf("User cache add %v %v %v", backend.States[state], userID, token)

	return nil
}

// userCacheDelToken deletes a token from a user cache.
func (p *usermdPlugin) userCacheDelToken(tstore plugins.TstoreClient, userID string, state backend.StateT, token string) error {
	// Get current user data
	uc, err := p.userCache(tstore, userID)
	if err != nil {
		return err
	}

	switch state {
	case backend.StateUnvetted:
		tokens, err := delToken(uc.Vetted, token)
		if err != nil {
			return err
		}
		uc.Unvetted = tokens
	case backend.StateVetted:
		tokens, err := delToken(uc.Vetted, token)
		if err != nil {
			return err
		}
		uc.Vetted = tokens
	default:
		return errors.Errorf("invalid state %v", state)
	}

	// Save changes
	err = p.userCacheSave(tstore, userID, *uc)
	if err != nil {
		return err
	}

	log.Debugf("User cache del %v %v %v", backend.States[state], userID, token)

	return nil
}

// userCacheMoveTokenToVetted moves a record token from the unvetted to vetted
// list in the userCache.
func (p *usermdPlugin) userCacheMoveTokenToVetted(tstore plugins.TstoreClient, userID string, token string) error {
	// Get current user data
	uc, err := p.userCache(tstore, userID)
	if err != nil {
		return err
	}

	// Del token from unvetted
	uc.Unvetted, err = delToken(uc.Unvetted, token)
	if err != nil {
		return err
	}

	// Add token to vetted
	uc.Vetted = append(uc.Vetted, token)

	// Save changes
	err = p.userCacheSave(tstore, userID, *uc)
	if err != nil {
		return err
	}

	log.Debugf("User cache move to vetted %v %v", userID, token)

	return nil
}

// delToken deletes the tokenToDel from the tokens list. An error is returned
// if the token is not found.
func delToken(tokens []string, tokenToDel string) ([]string, error) {
	// Find token index
	var i int
	var found bool
	for k, v := range tokens {
		if v == tokenToDel {
			i = k
			found = true
			break
		}
	}
	if !found {
		return nil, errors.Errorf("user token not found %v", tokenToDel)
	}

	// Del token (linear time)
	copy(tokens[i:], tokens[i+1:])  // Shift t[i+1:] left one index
	tokens[len(tokens)-1] = ""      // Erase last element
	tokens = tokens[:len(tokens)-1] // Truncate slice

	return tokens, nil
}

// getUserCacheKey returns the key-value store key for a userCache object.
func getUserCacheKey(userID string) string {
	return strings.Replace(userCacheKey, "{userid}", userID, 1)
}
