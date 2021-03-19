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
	// fnSubmissions is the filename for the cached submissions data
	// that is saved to the plugin data dir.
	fnSubmissions = "{shorttoken}-submissions.json"
)

// submissions is the the structure that is updated and cached for record A
// when record B links to record A in order to participate in a runoff vote.
// Record A must be a runoff vote parent record. Record B declares its intent
// on being a runoff vote submission using the VoteMetadata LinkTo field. The
// submissions list contains all records that have linked to record A. The list
// will only contain public records. The submissions list is saved to disk in
// the ticketvote plugin data dir, with the parent record token in the
// filename.
type submissions struct {
	Tokens map[string]struct{} `json:"tokens"`
}

// submissionsCachePath returns the path to the submissions list for the
// provided record token. The short token is used in the file path so that the
// submissions list can be retrieved using either the full token or the short
// token.
func (p *ticketVotePlugin) submissionsCachePath(token []byte) (string, error) {
	t, err := util.ShortTokenEncode(token)
	if err != nil {
		return "", err
	}
	fn := strings.Replace(fnSubmissions, "{shorttoken}", t, 1)
	return filepath.Join(p.dataDir, fn), nil
}

// submissionsCacheWithLock return the submissions list for a record token. If
// a submissions list does not exist for the token then an empty list will be
// returned.
//
// This function must be called WITH the lock held.
func (p *ticketVotePlugin) submissionsCacheWithLock(token []byte) (*submissions, error) {
	fp, err := p.submissionsCachePath(token)
	if err != nil {
		return nil, err
	}
	b, err := ioutil.ReadFile(fp)
	if err != nil {
		var e *os.PathError
		if errors.As(err, &e) && !os.IsExist(err) {
			// File does't exist. Return an empty submissions list.
			return &submissions{
				Tokens: make(map[string]struct{}),
			}, nil
		}
	}

	var s submissions
	err = json.Unmarshal(b, &s)
	if err != nil {
		return nil, err
	}

	return &s, nil
}

// submissionsCache return the submissions list for a record token. If a linked
// from list does not exist for the token then an empty list will be returned.
//
// This function must be called WITHOUT the lock held.
func (p *ticketVotePlugin) submissionsCache(token []byte) (*submissions, error) {
	p.mtxSubs.Lock()
	defer p.mtxSubs.Unlock()

	return p.submissionsCacheWithLock(token)
}

// submissionsCacheSaveWithLock saves a submissions to the plugin data dir.
//
// This function must be called WITH the lock held.
func (p *ticketVotePlugin) submissionsCacheSaveWithLock(token []byte, s submissions) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	fp, err := p.submissionsCachePath(token)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(fp, b, 0664)
}

// submissionsCacheAdd updates the cached submissions list for the parentToken,
// adding the childToken to the list. The full length token MUST be used.
//
// This function must be called WITHOUT the lock held.
func (p *ticketVotePlugin) submissionsCacheAdd(parentToken, childToken string) error {
	p.mtxSubs.Lock()
	defer p.mtxSubs.Unlock()

	// Verify tokens
	parent, err := tokenDecode(parentToken)
	if err != nil {
		return err
	}
	_, err = tokenDecode(childToken)
	if err != nil {
		return err
	}

	// Get existing submissions list
	s, err := p.submissionsCacheWithLock(parent)
	if err != nil {
		return err
	}

	// Update list
	s.Tokens[childToken] = struct{}{}

	// Save list
	err = p.submissionsCacheSaveWithLock(parent, *s)
	if err != nil {
		return err
	}

	log.Debugf("Submissions list add: child %v added to parent %v",
		childToken, parentToken)

	return nil
}

// submissionsCacheDel updates the cached submissions list for the parentToken,
// deleting the childToken from the list.
//
// This function must be called WITHOUT the lock held.
func (p *ticketVotePlugin) submissionsCacheDel(parentToken, childToken string) error {
	p.mtxSubs.Lock()
	defer p.mtxSubs.Unlock()

	// Verify tokens
	parent, err := tokenDecode(parentToken)
	if err != nil {
		return err
	}
	_, err = tokenDecode(childToken)
	if err != nil {
		return err
	}

	// Get existing submissions list
	s, err := p.submissionsCacheWithLock(parent)
	if err != nil {
		return err
	}

	// Update list
	delete(s.Tokens, childToken)

	// Save list
	err = p.submissionsCacheSaveWithLock(parent, *s)
	if err != nil {
		return err
	}

	log.Debugf("Submissions list del: child %v deleted from parent %v",
		childToken, parentToken)

	return nil
}
