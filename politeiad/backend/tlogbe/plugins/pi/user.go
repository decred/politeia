// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pi

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

const (
	// fnUserData is the filename for the cached userData that is
	// saved to the pi plugin data dir.
	fnUserData = "{userid}.json"
)

// userData contains cached pi plugin data for a specific user. The userData
// JSON is saved to disk in the pi plugin data dir. The user ID is included in
// the filename.
type userData struct {
	// Tokens contains a list of all the proposals that have been
	// submitted by this user. This data is cached so that the
	// ProposalInv command can filter proposals by user ID.
	Tokens []string `json:"tokens"`
}

// userDataPath returns the filepath to the cached userData struct for the
// specified user.
func (p *piPlugin) userDataPath(userID string) string {
	fn := strings.Replace(fnUserData, "{userid}", userID, 1)
	return filepath.Join(p.dataDir, fn)
}

// userDataWithLock returns the cached userData struct for the specified user.
//
// This function must be called WITH the lock held.
func (p *piPlugin) userDataWithLock(userID string) (*userData, error) {
	fp := p.userDataPath(userID)
	b, err := ioutil.ReadFile(fp)
	if err != nil {
		var e *os.PathError
		if errors.As(err, &e) && !os.IsExist(err) {
			// File does't exist. Return an empty userData.
			return &userData{
				Tokens: []string{},
			}, nil
		}
	}

	var ud userData
	err = json.Unmarshal(b, &ud)
	if err != nil {
		return nil, err
	}

	return &ud, nil
}

// userData returns the cached userData struct for the specified user.
//
// This function must be called WITHOUT the lock held.
func (p *piPlugin) userData(userID string) (*userData, error) {
	p.Lock()
	defer p.Unlock()

	return p.userDataWithLock(userID)
}

// userDataSaveWithLock saves the provided userData to the pi plugin data dir.
//
// This function must be called WITH the lock held.
func (p *piPlugin) userDataSaveWithLock(userID string, ud userData) error {
	b, err := json.Marshal(ud)
	if err != nil {
		return err
	}

	fp := p.userDataPath(userID)
	return ioutil.WriteFile(fp, b, 0664)
}

// userDataAddToken adds the provided token to the cached userData for the
// provided user.
//
// This function must be called WITHOUT the lock held.
func (p *piPlugin) userDataAddToken(userID string, token string) error {
	p.Lock()
	defer p.Unlock()

	// Get current user data
	ud, err := p.userDataWithLock(userID)
	if err != nil {
		return err
	}

	// Add token
	ud.Tokens = append(ud.Tokens, token)

	// Save changes
	return p.userDataSaveWithLock(userID, *ud)
}
