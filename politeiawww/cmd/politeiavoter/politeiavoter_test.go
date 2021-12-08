// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"testing"
	"time"
)

func TestSetupVoteDuration(t *testing.T) {
	// Setup piv context
	p, cleanup := fakePiv(t, 0, 1)
	defer cleanup()

	// Setup tests
	var tests = []struct {
		name           string
		voteDuration   time.Duration
		hoursPrior     time.Duration
		timeLeftInVote time.Duration
		wantErr        bool
	}{
		{
			"provided vote duration exceeds remaining time",
			2 * time.Hour,
			0,
			1 * time.Hour,
			true,
		},
		{
			"calculated vote duration is under 24 hours",
			0,
			12 * time.Hour,
			35 * time.Hour,
			true,
		},
		{
			"vote duration provided success",
			1 * time.Hour,
			0,
			2 * time.Hour,
			false,
		},
		{
			"vote duration not provided success",
			0,
			12 * time.Hour,
			36 * time.Hour,
			false,
		},
	}

	// Run tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup piv config
			p.cfg.voteDuration = tc.voteDuration
			p.cfg.hoursPrior = tc.hoursPrior

			// Run test
			err := p.setupVoteDuration(tc.timeLeftInVote)
			switch {
			case err != nil && tc.wantErr:
				// Test passes
				return
			case err == nil && !tc.wantErr:
				// Test passes
				return
			default:
				// Test fails
				t.Errorf("got err %v, want err %v",
					err == nil, tc.wantErr)
			}
		})
	}
}
