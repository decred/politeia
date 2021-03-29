// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package usermd

import (
	"encoding/json"

	"github.com/decred/politeia/politeiad/plugins/usermd"
)

// cmdAuthor returns the user ID of a record's author.
func (p *usermdPlugin) cmdAuthor(token []byte) (string, error) {
	// Get user metadata
	r, err := p.tstore.RecordPartial(token, 0, nil, true)
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

	// Prepare reply
	urr := usermd.UserRecordsReply{
		Unvetted: uc.Unvetted,
		Vetted:   uc.Vetted,
	}
	reply, err := json.Marshal(urr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}
