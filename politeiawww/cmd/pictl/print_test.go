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
		{13000, "$130.00"},
		{130000, "$1,300.00"},
		{13000000, "$130,000.00"},
		{130000000, "$1,300,000.00"},
		{78, "$0.78"},
		{-78, "-$0.78"},
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
