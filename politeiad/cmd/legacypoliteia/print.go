// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import "fmt"

// printInPlace prints the provided text to stdout in a way that overwrites the
// existing stdout text. This function can be called multiple times. Each
// subsequent call will overwrite the existing text that was printed to stdout.
func printInPlace(s string) {
	fmt.Printf("\033[2K\r%s", s)
}
