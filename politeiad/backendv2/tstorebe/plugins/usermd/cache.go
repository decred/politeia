// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package usermd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	backend "github.com/decred/politeia/politeiad/backendv2"
)

const (
	// fnUserCache is the filename for the cached userCache data that
	// is saved to the plugin data dir.
	fnUserCache = "{userid}.json"
)

// userCache contains cached user metadata. The userCache JSON is saved to disk
// in the user plugin data dir. The user ID is included in the filename.
//
// The Unvetted and Vetted fields contain the records that have been submitted
// by the user. All record tokens are sorted by the timestamp of their most
// recent status change from newest to oldest.
type userCache struct {
	Unvetted []string `json:"unvetted"`
	Vetted   []string `json:"vetted"`
}

// userCachePath returns the filepath to the userCache for the specified user.
func (p *usermdPlugin) userCachePath(userID string) string {
	fn := strings.Replace(fnUserCache, "{userid}", userID, 1)
	return filepath.Join(p.dataDir, fn)
}

// userCacheLocked returns the userCache for the specified user.
//
// This function must be called WITH the lock held.
func (p *usermdPlugin) userCacheLocked(userID string) (*userCache, error) {
	fp := p.userCachePath(userID)
	b, err := ioutil.ReadFile(fp)
	if err != nil {
		var e *os.PathError
		if errors.As(err, &e) && !os.IsExist(err) {
			// File does't exist. Return an empty userCache.
			return &userCache{
				Unvetted: []string{},
				Vetted:   []string{},
			}, nil
		}
	}

	var uc userCache
	err = json.Unmarshal(b, &uc)
	if err != nil {
		return nil, err
	}

	return &uc, nil
}

// userCacheLocked returns the userCache for the specified user.
//
// This function must be called WITHOUT the lock held.
func (p *usermdPlugin) userCache(userID string) (*userCache, error) {
	p.Lock()
	defer p.Unlock()

	return p.userCacheLocked(userID)
}

// userCacheSaveLocked saves the provided userCache to the plugin data dir.
//
// This function must be called WITH the lock held.
func (p *usermdPlugin) userCacheSaveLocked(userID string, uc userCache) error {
	b, err := json.Marshal(uc)
	if err != nil {
		return err
	}

	fp := p.userCachePath(userID)
	return ioutil.WriteFile(fp, b, 0664)
}

// userCacheAddToken adds a token to a user cache.
//
// This function must be called WITHOUT the lock held.
func (p *usermdPlugin) userCacheAddToken(userID string, state backend.StateT, token string) error {
	p.Lock()
	defer p.Unlock()

	// Get current user data
	uc, err := p.userCacheLocked(userID)
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
		return fmt.Errorf("invalid state %v", state)
	}

	// Save changes
	err = p.userCacheSaveLocked(userID, *uc)
	if err != nil {
		return err
	}

	log.Debugf("User cache add %v %v %v", backend.States[state], userID, token)

	return nil
}

// userCacheDelToken deletes a token from a user cache.
//
// This function must be called WITHOUT the lock held.
func (p *usermdPlugin) userCacheDelToken(userID string, state backend.StateT, token string) error {
	p.Lock()
	defer p.Unlock()

	// Get current user data
	uc, err := p.userCacheLocked(userID)
	if err != nil {
		return err
	}

	switch state {
	case backend.StateUnvetted:
		tokens, err := delToken(uc.Vetted, token)
		if err != nil {
			return fmt.Errorf("delToken %v %v: %v",
				userID, state, err)
		}
		uc.Unvetted = tokens
	case backend.StateVetted:
		tokens, err := delToken(uc.Vetted, token)
		if err != nil {
			return fmt.Errorf("delToken %v %v: %v",
				userID, state, err)
		}
		uc.Vetted = tokens
	default:
		return fmt.Errorf("invalid state %v", state)
	}

	// Save changes
	err = p.userCacheSaveLocked(userID, *uc)
	if err != nil {
		return err
	}

	log.Debugf("User cache del %v %v %v", backend.States[state], userID, token)

	return nil
}

// userCacheMoveTokenToVetted moves a record token from the unvetted to vetted
// list in the userCache.
func (p *usermdPlugin) userCacheMoveTokenToVetted(userID string, token string) error {
	p.Lock()
	defer p.Unlock()

	// Get current user data
	uc, err := p.userCacheLocked(userID)
	if err != nil {
		return err
	}

	// Del token from unvetted
	uc.Unvetted, err = delToken(uc.Unvetted, token)
	if err != nil {
		return fmt.Errorf("delToken %v: %v", userID, err)
	}

	// Add token to vetted
	uc.Vetted = append(uc.Vetted, token)

	// Save changes
	err = p.userCacheSaveLocked(userID, *uc)
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
		return nil, fmt.Errorf("user token not found %v", tokenToDel)
	}

	// Del token (linear time)
	copy(tokens[i:], tokens[i+1:])  // Shift t[i+1:] left one index
	tokens[len(tokens)-1] = ""      // Erase last element
	tokens = tokens[:len(tokens)-1] // Truncate slice

	return tokens, nil
}
