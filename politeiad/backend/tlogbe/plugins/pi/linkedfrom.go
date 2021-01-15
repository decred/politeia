// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/decred/politeia/util"
)

const (
	// fnLinkedFrom is the filename for the cached linkedFrom data that
	// is saved to the pi plugin data dir.
	fnLinkedFrom = "{tokenprefix}-linkedfrom.json"
)

// linkedFrom is the the structure that is updated and cached for proposal A
// when proposal B links to proposal A. Proposals can link to one another using
// the ProposalMetadata LinkTo field. The linkedFrom list contains all
// proposals that have linked to proposal A. The list will only contain public
// proposals. The linkedFrom list is saved to disk in the pi plugin data dir,
// specifying the parent proposal token in the filename.
//
// Example: the linked from list for an RFP proposal will contain all public
// RFP submissions. The cached list can be found in the pi plugin data dir
// at the path specified by linkedFromPath().
type linkedFrom struct {
	Tokens map[string]struct{} `json:"tokens"`
}

// linkedFromPath returns the path to the linkedFrom list for the provided
// proposal token. The token prefix is used in the file path so that the linked
// from list can be retrieved using either the full token or the token prefix.
func (p *piPlugin) linkedFromPath(token []byte) string {
	t := util.TokenPrefix(token)
	fn := strings.Replace(fnLinkedFrom, "{tokenprefix}", t, 1)
	return filepath.Join(p.dataDir, fn)
}

// linkedFromWithLock return the linkedFrom list for the provided proposal
// token.
//
// This function must be called WITH the lock held.
func (p *piPlugin) linkedFromWithLock(token []byte) (*linkedFrom, error) {
	fp := p.linkedFromPath(token)
	b, err := ioutil.ReadFile(fp)
	if err != nil {
		var e *os.PathError
		if errors.As(err, &e) && !os.IsExist(err) {
			// File does't exist. Return an empty linked from list.
			return &linkedFrom{
				Tokens: make(map[string]struct{}),
			}, nil
		}
	}

	var lf linkedFrom
	err = json.Unmarshal(b, &lf)
	if err != nil {
		return nil, err
	}

	return &lf, nil
}

// linkedFrom return the linkedFrom list for the provided proposal token.
//
// This function must be called WITHOUT the lock held.
func (p *piPlugin) linkedFrom(token []byte) (*linkedFrom, error) {
	p.Lock()
	defer p.Unlock()

	return p.linkedFromWithLock(token)
}

// linkedFromSaveWithLock saves the provided linkedFrom list to the pi plugin
// data dir.
//
// This function must be called WITH the lock held.
func (p *piPlugin) linkedFromSaveWithLock(token []byte, lf linkedFrom) error {
	b, err := json.Marshal(lf)
	if err != nil {
		return err
	}
	fp := p.linkedFromPath(token)
	return ioutil.WriteFile(fp, b, 0664)
}

// linkedFromAdd updates the cached linkedFrom list for the parentToken, adding
// the childToken to the list.
//
// This function must be called WITHOUT the lock held.
func (p *piPlugin) linkedFromAdd(parentToken, childToken string) error {
	p.Lock()
	defer p.Unlock()

	// Verify tokens
	parent, err := util.TokenDecode(util.TokenTypeTlog, parentToken)
	if err != nil {
		return err
	}
	_, err = util.TokenDecode(util.TokenTypeTlog, childToken)
	if err != nil {
		return err
	}

	// Get existing linked from list
	lf, err := p.linkedFromWithLock(parent)
	if err != nil {
		return fmt.Errorf("linkedFromWithLock %x: %v", parent, err)
	}

	// Update list
	lf.Tokens[childToken] = struct{}{}

	// Save list
	return p.linkedFromSaveWithLock(parent, *lf)
}

// linkedFromDel updates the cached linkedFrom list for the parentToken,
// deleting the childToken from the list.
//
// This function must be called WITHOUT the lock held.
func (p *piPlugin) linkedFromDel(parentToken, childToken string) error {
	p.Lock()
	defer p.Unlock()

	// Verify tokens
	parent, err := util.TokenDecode(util.TokenTypeTlog, parentToken)
	if err != nil {
		return err
	}
	_, err = util.TokenDecode(util.TokenTypeTlog, childToken)
	if err != nil {
		return err
	}

	// Get existing linked from list
	lf, err := p.linkedFromWithLock(parent)
	if err != nil {
		return fmt.Errorf("linkedFromWithLock %x: %v", parent, err)
	}

	// Update list
	delete(lf.Tokens, childToken)

	// Save list
	return p.linkedFromSaveWithLock(parent, *lf)
}
