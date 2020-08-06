// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package codetracker

import (
	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
)

// CodeTracker interface for getting Code Stats from a git based code tracking
// site (Github/Gitlab etc).
type CodeTracker interface {
	// Update updates the code stats for a (organization, repo)
	Update(org, repo string) error

	// UserInfo returns pull request, review and commit information about
	// a given user over a given start and stop time.
	UserInfo(org, username string, start, end int) (*cms.UserInformationResult, error)
}
