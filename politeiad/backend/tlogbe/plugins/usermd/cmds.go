// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package usermd

import (
	"encoding/json"

	"github.com/decred/politeia/politeiad/plugins/usermd"
)

func (p *userPlugin) cmdAuthor(treeID int64) (string, error) {
	log.Tracef("cmdAuthor: %v", treeID)

	// Get user metadata
	r, err := p.tlog.RecordLatest(treeID)
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

func (p *userPlugin) cmdUserRecords(payload string) (string, error) {
	log.Tracef("cmdUserRecords: %v", payload)

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
		Records: uc.Tokens,
	}
	reply, err := json.Marshal(urr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}
