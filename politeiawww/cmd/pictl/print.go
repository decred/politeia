// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

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

// printInPlace prints the provided text to stdout in a way that overwrites the
// existing stdout text. This function can be called multiple times. Each
// subsequent call will overwrite the existing text that was printed to stdout.
func printInPlace(s string) {
	fmt.Printf("\033[2K\r%s", s)
}

// addIndent adds indentation to the beginning of each line of the provided
// string. The indentInSpaces argument is the number of spaces that will be
// inserted into each line.
//
// Example: addIndent("hello,\nworld!\n", 2) -> "  hello,\n  world!\n"
func addIndent(s string, indentInSpaces uint) string {
	// Setup indent string
	var b strings.Builder
	for i := 0; i < int(indentInSpaces); i++ {
		b.WriteString(" ")
	}
	indent := b.String()

	// Add indentation after each new line
	r := strings.NewReplacer("\n", "\n"+indent)
	ss := r.Replace(s)

	// Remove trailing spaces
	ss = strings.TrimSpace(ss)

	// Add indent to the first line
	return indent + ss
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

// dollars converts an int64 price in cents into a human readable dollar
// string.
//
// | Input     | Output          |
// |-----------------------------|
// | 130000000 | "$1,300,000.00" |
// | 13000000  | "$130,000.00"   |
// | 130000    | "$1,300.00"     |
// | 13000     | "$130.00"       |
// | 78        | "$0.78"         |
// | 9         | "$0.09"         |
// | 0         | "$0.00"         |
// | -9        | "-$0.09"        |
// | -78       | "-$0.78"        |
// | -13000000 | "-$130,000.00"  |
func dollars(cents int64) string {
	// Get the value in dollars.
	dollars := float64(cents) / 100

	// Initialize the buffer to store the string result.
	var buf bytes.Buffer

	// Check for a negative value.
	if dollars < 0 {
		buf.WriteString("-")
		// Convert the negative value to a positive value.
		// The code below can only handle positive values.
		dollars = 0 - dollars
	}
	buf.WriteString("$")

	// Convert the dollar value into a string and split it into a
	// integer and decimal. This is done so that commas can be added
	// to the integer.
	var (
		f       = strconv.FormatFloat(dollars, 'f', -1, 64)
		s       = strings.Split(f, ".")
		integer = s[0]

		// The value may or may not have a decimal. Default to 0.
		decimal = ".00"
	)
	if len(s) > 1 {
		// The value includes a decimal. Overwrite the default.
		decimal = "." + s[1]
	}

	// Write the integer to the buffer one character at a time. Commas
	// are inserted in their appropriate places.
	//
	// Examples
	// "100000" to "100,000"
	// "1000000" to "1,000,000"
	for i, c := range integer {
		// A comma should be inserted if the character index is divisible
		// by 3 when counting from the right side of the string.
		divByThree := (len(integer)-i)%3 == 0

		// A comma should never be inserted for the first character.
		// Ex: "100000" should not be ",100,000"
		if divByThree && i > 0 {
			buf.WriteString(",")
		}

		// Write the character to the buffer.
		buf.WriteRune(c)
	}

	// Write the decimal to the buffer.
	buf.WriteString(decimal)

	return buf.String()
}
