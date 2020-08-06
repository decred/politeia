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
	Update(string, string) error                                                  // Use implementation to update the user-information.
	UserInformation(string, string, int, int) (*cms.UserInformationResult, error) // Request user codestats information based on received data.
}
