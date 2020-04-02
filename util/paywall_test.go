// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package util_test

import (
	"github.com/thi4go/politeia/util"
	"testing"
)

func TestDcrStringToAmount(t *testing.T) {
	testCases := []struct {
		input         string
		output        uint64
		expectedError error
	}{
		{
			"0.1",
			1e7,
			nil,
		},
		{
			"0.15",
			1.5e7,
			nil,
		},
		{
			"000000.10000",
			1e7,
			nil,
		},
		{
			".1",
			1e7,
			nil,
		},
		{
			"1",
			1e8,
			nil,
		},
		{
			"1.0",
			1e8,
			nil,
		},
		{
			"500",
			5e10,
			nil,
		},
	}

	// test
	for _, testCase := range testCases {
		result, err := util.DcrStringToAmount(testCase.input)
		if err != testCase.expectedError {
			t.Errorf("Expected %v for input %s, got %v.",
				testCase.expectedError, testCase.input, err)
		}
		if err == nil {
			if result != testCase.output {
				t.Errorf("Expected %v for input %s, got %v.", testCase.output,
					testCase.input, result)
			}
		}
	}
}
