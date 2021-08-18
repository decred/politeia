// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"testing"
)

func TestDollars(t *testing.T) {
	var tests = []struct {
		cents   int64
		dollars string
	}{
		{130000000, "$1,300,000.00"},
		{13000023, "$130,000.23"},
		{13000000, "$130,000.00"},
		{130000, "$1,300.00"},
		{13000, "$130.00"},
		{78, "$0.78"},
		{9, "$0.09"},
		{0, "$0.00"},
		{-9, "-$0.09"},
		{-78, "-$0.78"},
		{-13000000, "-$130,000.00"},
	}
	for _, tt := range tests {
		testName := fmt.Sprintf("%d", tt.cents)
		t.Run(testName, func(t *testing.T) {
			ans := dollars(tt.cents)
			if ans != tt.dollars {
				t.Errorf("got '%s' want '%s'", ans, tt.dollars)
			}
		})
	}
}
