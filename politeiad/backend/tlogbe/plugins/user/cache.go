// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package user

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

const (
	// fnUserCache is the filename for the cached userCache data that
	// is saved to the plugin data dir.
	fnUserCache = "{userid}.json"
)

// userCache contains cached user metadata. The userCache JSON is saved to disk
// in the user plugin data dir. The user ID is included in the filename.
type userCache struct {
	// Tokens contains a list of all record tokens that have been
	// submitted by this user, ordered newest to oldest.
	Tokens []string `json:"tokens"`
}

// userCachePath returns the filepath to the cached userCache struct for the
// specified user.
func (p *userPlugin) userCachePath(userID string) string {
	fn := strings.Replace(fnUserCache, "{userid}", userID, 1)
	return filepath.Join(p.dataDir, fn)
}

// userCacheWithLock returns the cached userCache struct for the specified
// user.
//
// This function must be called WITH the lock held.
func (p *userPlugin) userCacheWithLock(userID string) (*userCache, error) {
	fp := p.userCachePath(userID)
	b, err := ioutil.ReadFile(fp)
	if err != nil {
		var e *os.PathError
		if errors.As(err, &e) && !os.IsExist(err) {
			// File does't exist. Return an empty userCache.
			return &userCache{
				Tokens: []string{},
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

// userCache returns the cached userCache struct for the specified user.
//
// This function must be called WITHOUT the lock held.
func (p *userPlugin) userCache(userID string) (*userCache, error) {
	p.Lock()
	defer p.Unlock()

	return p.userCacheWithLock(userID)
}

// userCacheSaveWithLock saves the provided userCache to the pi plugin data dir.
//
// This function must be called WITH the lock held.
func (p *userPlugin) userCacheSaveWithLock(userID string, uc userCache) error {
	b, err := json.Marshal(uc)
	if err != nil {
		return err
	}

	fp := p.userCachePath(userID)
	return ioutil.WriteFile(fp, b, 0664)
}

// userCacheAddToken adds the provided token to the cached userCache for the
// provided user.
//
// This function must be called WITHOUT the lock held.
func (p *userPlugin) userCacheAddToken(userID string, token string) error {
	p.Lock()
	defer p.Unlock()

	// Get current user data
	uc, err := p.userCacheWithLock(userID)
	if err != nil {
		return err
	}

	// Add token
	uc.Tokens = append(uc.Tokens, token)

	// Save changes
	return p.userCacheSaveWithLock(userID, *uc)
}
