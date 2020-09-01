package main

import (
	"testing"

	www "github.com/decred/politeia/politeiawww/api/www/v1"
)

func TestProcessCodeStats(t *testing.T) {
	_, cleanup := newTestCMSwww(t)
	defer cleanup()

	var tests = []struct {
		name       string
		wantReply  www.VersionReply
		wantStatus int
		wantError  error
	}{
		{},
	}

	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
		})
	}
}
