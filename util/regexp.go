// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package util

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
)

// Regexp returns a compiled Regexp for the provided parameters.
func Regexp(supportedChars []string, lengthMin, lengthMax uint64) (*regexp.Regexp, error) {
	// Match beginning of string
	var b bytes.Buffer
	b.WriteString("^")

	// Set allowed character set
	b.WriteString("[")
	for _, v := range supportedChars {
		switch v {
		case `\`, `"`, "[", "]", "^", "-", " ":
			// These characters must be escaped
			b.WriteString(`\` + v)
		default:
			b.WriteString(v)
		}
	}
	b.WriteString("]")

	// Set min and max length
	min := strconv.FormatUint(lengthMin, 10)
	max := strconv.FormatUint(lengthMax, 10)
	b.WriteString(fmt.Sprintf("{%v,%v}", min, max))

	// Match end of string
	b.WriteString("$")

	// Compile regexp
	r, err := regexp.Compile(b.String())
	if err != nil {
		return nil, err
	}

	return r, nil
}
