// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package usermd

import (
	"encoding/json"

	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/plugins/usermd"
)

// cmdAuthor returns the user ID of a record's author.
func (p *usermdPlugin) cmdAuthor(tstore plugins.TstoreClient, token []byte) (string, error) {
	// Get user metadata
	r, err := tstore.RecordPartial(token, 0, nil, true)
	if err != nil {
		return "", err
	}
	um, err := userMetadataDecode(r.Metadata)
	if err != nil {
		return "", err
	}

	// Prepare reply
	ar := usermd.AuthorReply{
		UserID: um.UserID,
	}
	reply, err := json.Marshal(ar)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// cmdUserRecords retrieves the tokens of all records that were submitted by
// the provided user ID. The returned tokens are sorted from newest to oldest.
func (p *usermdPlugin) cmdUserRecords(payload string) (string, error) {
	// Decode payload
	var ur usermd.UserRecords
	err := json.Unmarshal([]byte(payload), &ur)
	if err != nil {
		return "", err
	}

	// Get user records
	uc, err := p.userCache(ur.UserID)
	if err != nil {
		return "", err
	}

	// The tokens in the user cache are ordered oldest to
	// newest. We need to return them newest to oldest.
	var (
		unvetted = make([]string, 0, len(uc.Unvetted))
		vetted   = make([]string, 0, len(uc.Vetted))
	)
	for i := len(uc.Unvetted) - 1; i >= 0; i-- {
		unvetted = append(unvetted, uc.Unvetted[i])
	}
	for i := len(uc.Vetted) - 1; i >= 0; i-- {
		vetted = append(vetted, uc.Vetted[i])
	}

	// Prepare reply
	urr := usermd.UserRecordsReply{
		Unvetted: unvetted,
		Vetted:   vetted,
	}
	reply, err := json.Marshal(urr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}
