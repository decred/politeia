// Copyright (c) 2021-2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build !go1.18
// +build !go1.18

package version

// vcsCommitID returns an empty string for all Go versions prior to 1.18 since
// the information is not availalbe in binaries prior to that version.
func vcsCommitID() string {
	return ""
}
