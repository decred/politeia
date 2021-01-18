// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import (
	"encoding/json"
	"errors"
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

// linkedFrom is the the structure that is updated and cached for record A when
// record B links to record A. Recordss can link to one another using the
// VoteMetadata LinkTo field. The linkedFrom list contains all records that
// have linked to record A. The list will only contain public records. The
// linkedFrom list is saved to disk in the ticketvote plugin data dir, with the
// parent record token in the filename.
//
// Example: the linked from list for a runoff vote parent record will contain
// all public runoff vote submissions.
type linkedFrom struct {
	Tokens map[string]struct{} `json:"tokens"`
}

// linkedFromPath returns the path to the linkedFrom list for the provided
// record token. The token prefix is used in the file path so that the linked
// from list can be retrieved using either the full token or the token prefix.
func (p *ticketVotePlugin) linkedFromPath(token []byte) string {
	t := util.TokenPrefix(token)
	fn := strings.Replace(fnLinkedFrom, "{tokenprefix}", t, 1)
	return filepath.Join(p.dataDir, fn)
}

// linkedFromWithLock return the linked from list for a record token. If a
// linked from list does not exist for the token then an empty list will be
// returned.
//
// This function must be called WITH the lock held.
func (p *ticketVotePlugin) linkedFromWithLock(token []byte) (*linkedFrom, error) {
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

// linkedFrom return the linked from list for a record token. If a linked from
// list does not exist for the token then an empty list will be returned.
//
// This function must be called WITHOUT the lock held.
func (p *ticketVotePlugin) linkedFrom(token []byte) (*linkedFrom, error) {
	p.Lock()
	defer p.Unlock()

	return p.linkedFromWithLock(token)
}

// linkedFromSaveWithLock saves a linkedFrom to the plugin data dir.
//
// This function must be called WITH the lock held.
func (p *ticketVotePlugin) linkedFromSaveWithLock(token []byte, lf linkedFrom) error {
	b, err := json.Marshal(lf)
	if err != nil {
		return err
	}
	fp := p.linkedFromPath(token)
	return ioutil.WriteFile(fp, b, 0664)
}

// linkedFromAdd updates the cached linkedFrom list for the parentToken, adding
// the childToken to the list. The full length token MUST be used.
//
// This function must be called WITHOUT the lock held.
func (p *ticketVotePlugin) linkedFromAdd(parentToken, childToken string) error {
	p.Lock()
	defer p.Unlock()

	// Verify tokens
	parent, err := tokenDecode(parentToken)
	if err != nil {
		return err
	}
	_, err = tokenDecode(childToken)
	if err != nil {
		return err
	}

	// Get existing linked from list
	lf, err := p.linkedFromWithLock(parent)
	if err != nil {
		return err
	}

	// Update list
	lf.Tokens[childToken] = struct{}{}

	// Save list
	err = p.linkedFromSaveWithLock(parent, *lf)
	if err != nil {
		return err
	}

	log.Debugf("Linked from list updated. Child %v added to parent %v",
		childToken, parentToken)

	return nil
}

// linkedFromDel updates the cached linkedFrom list for the parentToken,
// deleting the childToken from the list.
//
// This function must be called WITHOUT the lock held.
func (p *ticketVotePlugin) linkedFromDel(parentToken, childToken string) error {
	p.Lock()
	defer p.Unlock()

	// Verify tokens
	parent, err := tokenDecode(parentToken)
	if err != nil {
		return err
	}
	_, err = tokenDecode(childToken)
	if err != nil {
		return err
	}

	// Get existing linked from list
	lf, err := p.linkedFromWithLock(parent)
	if err != nil {
		return err
	}

	// Update list
	delete(lf.Tokens, childToken)

	// Save list
	err = p.linkedFromSaveWithLock(parent, *lf)
	if err != nil {
		return err
	}

	log.Debugf("Linked from list updated. Child %v deleted from parent %v",
		childToken, parentToken)

	return nil
}
