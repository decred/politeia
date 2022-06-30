// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"time"
)

const (
	// timeFormat contains the reference format that is used to print a human
	// readable timestamp.
	//
	// Reference date: "Mon Jan 2 15:04:05 2006"
	timeFormat = "2 Jan 2006 3:04:05pm"
)

// formatUnix formats a unix timestamp into a human readable string that is
// formatted according to the timeFormat global variable.
func formatUnix(unixTime int64) string {
	t := time.Unix(unixTime, 0)
	return t.Format(timeFormat)
}
