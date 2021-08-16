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
	fmt.Printf("\033[2K\r%s", s)
}

// dollars converts an int64 price in cents into a human readable dollar
// string.
//
// | Input     | Output          |
// |-----------------------------|
// | 13000     | "$130.00"       |
// | 130000    | "$1,300.00"     |
// | 13000000  | "$130,000.00"   |
// | -13000000 | "-$130,000.00"  |
// | 130000000 | "$1,300,000.00" |
// | 78        | "$0.78"         |
// | -78       | "-$0.78"        |
// | 78        | "$0.78"         |
// | 9         | "$0.09"         |
// | -9        | "-$0.09"        |

func dollars(cents int64) string {
	// Get the value in dollars
	dollarsValue := float64(cents) / 100

	// Initialize the buffer to store the string result .
	// Check for a negative value
	var buf bytes.Buffer
	if dollarsValue < 0 {
		buf.WriteString("-")
		// Convert the negative value to a positive value. The code
		// below can only handle positive values.
		dollarsValue = 0 - dollarsValue
	}
	buf.WriteString("$")

	// Split the value into integer and decimal
	parts := strings.Split(strconv.FormatFloat(dollarsValue, 'f', -1, 64), ".")

	// Process the integer part
	var position int
	var integerPart = parts[0]

	// If the integerPart is not divisible by 3. Write to the buffer the surplus
	if len(integerPart)%3 != 0 {
		position += len(integerPart) % 3
		buf.WriteString(integerPart[:position])
		buf.WriteString(",")
	}
	// Write to the buffer the divisible by 3 number part
	for ; position < len(integerPart); position += 3 {
		buf.WriteString(integerPart[position : position+3])
		buf.WriteString(",")
	}
	buf.Truncate(buf.Len() - 1)

	// Process the decimals part
	buf.WriteString(".")
	if len(parts) > 1 {
		buf.WriteString(parts[1])
	} else {
		buf.WriteString("00")
	}
	return buf.String()
}
