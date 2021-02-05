// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import "time"

const (
	// timeFormat contains the reference time format that is used
	// throughout this CLI tool. This format is how timestamps are
	// printed when we want to print the human readable version.
	//
	// Mon Jan 2 15:04:05 -0700 MST 2006
	timeFormat = "01/02/2006 3:04pm MST"
)

// timestampFromUnix converts a unix timestamp into a human readable timestamp
// string formatted according to the timeFormat global variable.
func timestampFromUnix(unixTime int64) string {
	t := time.Unix(unixTime, 0)
	return t.Format(timeFormat)
}
