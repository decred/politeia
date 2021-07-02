// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/decred/politeia/util"
)

// printf prints the provided string to stdout if the global config settings
// allows for it.
func printf(s string, args ...interface{}) {
	switch {
	case cfg.Verbose, cfg.RawJSON:
		// These are handled by the politeiawwww client
	case cfg.Silent:
		// Do nothing
	default:
		// Print to stdout
		fmt.Printf(s, args...)
	}
}

// printJSON pretty prints the provided structure if the global config settings
// allow for it.
func printJSON(v interface{}) {
	printf("%v\n", util.FormatJSON(v))
}

// byteCountSI converts the provided bytes to a string representation of the
// closest SI unit (kB, MB, GB, etc).
func byteCountSI(b int64) string {
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB",
		float64(b)/float64(div), "kMGTPE"[exp])
}

// printInPlace prints the provided text to stdout in a way that overwrites the
// existing stdout text. This function can be called multiple times. Each
// subsequent call will overwrite the existing text that was printed to stdout.
func printInPlace(s string) {
	printf("\033[2K\r%s", s)
}
