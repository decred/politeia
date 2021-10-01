// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mail

import (
	"testing"
	"time"

	"github.com/decred/politeia/politeiawww/legacy/user"
	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
)

func TestFilterRecipients(t *testing.T) {
	// Setup test params
	var (
		rateLimit       = 3
		rateLimitPeriod = 100 * time.Second

		userNoHistory  = uuid.New() // No email history yet
		userUnderLimit = uuid.New() // Under rate limit by more than 1
		userNearLimit  = uuid.New() // Under rate limit by 1
		userAtLimit    = uuid.New() // At rate limit

		// userAtLimitExpired is a user that is at the email rate limit
		// but the emails were sent in a previous rate limit period,
		// meaning the user's email history should be reset and they
		// should continue to receive emails.
		userAtLimitExpired = uuid.New()

		emailNoHistory      = "no_history@email.com"
		emailUnderLimit     = "under_limit@email.com"
		emailNearLimit      = "near_limit@email.com"
		emailAtLimit        = "at_limit@email.com"
		emailAtLimitExpired = "at_limit_expired@email.com"

		// The following timestamps are within the current rate limit
		// period.
		now   = time.Now()
		time1 = now.Unix() - 1 // 1 second in the past
		time2 = now.Unix() - 2 // 2 seconds in the past
		time3 = now.Unix() - 3 // 3 seconds in the past

		// The following timestamps are expired, meaning they occurred in
		// a previous rate limit period and should not be counted as part
		// of the current rate limit period.
		expired  = now.Add(-rateLimitPeriod)
		expired1 = expired.Unix() - 1 // 1 second expired
		expired2 = expired.Unix() - 2 // 2 seconds expired
		expired3 = expired.Unix() - 3 // 3 seconds expired

		// histories contains the emails histories that will be seeded
		// in the MailerDB for the test.
		histories = map[uuid.UUID]user.EmailHistory{
			userUnderLimit: {
				Timestamps:       []int64{time1},
				LimitWarningSent: false,
			},

			userNearLimit: {
				Timestamps:       []int64{time2, time1},
				LimitWarningSent: false,
			},

			userAtLimit: {
				Timestamps:       []int64{time3, time2, time1},
				LimitWarningSent: true,
			},

			userAtLimitExpired: {
				Timestamps:       []int64{expired3, expired2, expired1},
				LimitWarningSent: true,
			},
		}

		// emails contains the email list that will be provided to the
		// filterRecipients function for the test.
		emails = map[uuid.UUID]string{
			userNoHistory:      emailNoHistory,
			userUnderLimit:     emailUnderLimit,
			userNearLimit:      emailNearLimit,
			userAtLimit:        emailAtLimit,
			userAtLimitExpired: emailAtLimitExpired,
		}
	)

	// Setup test mail client
	c := newTestClient(rateLimit, rateLimitPeriod, histories)

	// Run test
	fr, err := c.filterRecipients(emails)
	if err != nil {
		t.Error(err)
	}

	// Put the valid and warning lists into maps for easy verification
	// that a value has been included.
	var (
		valid   = make(map[string]struct{}, len(fr.valid))
		warning = make(map[string]struct{}, len(fr.warning))
	)
	for _, v := range fr.valid {
		valid[v] = struct{}{}
	}
	for _, v := range fr.warning {
		warning[v] = struct{}{}
	}

	// Verify valid emails list. This should contain the users:
	// noHistory, underLimit, nearLimit, atLimitExpired.
	_, ok := valid[emailNoHistory]
	if !ok {
		t.Errorf("user with no email history was not found in the "+
			"valid emails list: %v", fr.valid)
	}

	_, ok = valid[emailUnderLimit]
	if !ok {
		t.Errorf("user with email history under the rate limit was "+
			"not found in the valid emails list: %v", fr.valid)
	}

	_, ok = valid[emailNearLimit]
	if !ok {
		t.Errorf("user with email history under the rate limit by 1 "+
			"was not found in the valid emails list: %v", fr.valid)
	}

	_, ok = valid[emailAtLimitExpired]
	if !ok {
		t.Errorf("user with email history at the rate limit but expired "+
			"was not found in the valid emails list: %v", fr.valid)
	}

	if len(fr.valid) != 4 {
		t.Errorf("valid emails list length want 4, got %v: %v",
			len(fr.valid), fr.valid)
	}

	// Verify warning emails. The only user that hit the rate limit
	// this invocation and thus should be in the warning emails list
	// is the nearLimit user.
	_, ok = warning[emailNearLimit]
	switch {
	case !ok:
		t.Errorf("user that hit the rate limit was not found in the "+
			"warning emails list: %v", fr.warning)

	case len(fr.warning) != 1:
		t.Errorf("warning emails list length want 1, got %v: %v",
			len(fr.warning), fr.warning)
	}

	eh, ok := fr.histories[userNoHistory]
	switch {
	case !ok:
		t.Errorf("user with no email history was not found in the " +
			"histories list")

	case len(eh.Timestamps) != 1:
		t.Errorf("histories length for user with no email history: "+
			"want 1, got %v", len(eh.Timestamps))

	case eh.LimitWarningSent:
		t.Errorf("limit warning sent for user with no email history: " +
			"want false, got true")
	}

	// Verify returned email history for underLimit user
	eh, ok = fr.histories[userUnderLimit]
	switch {
	case !ok:
		t.Errorf("user with email history under the rate limit was " +
			"not found in the histories list")

	case len(eh.Timestamps) != 2:
		t.Errorf("histories length for user under the rate limit: "+
			"want 2, got %v", len(eh.Timestamps))

	case eh.LimitWarningSent:
		t.Errorf("limit warning sent for user with email history " +
			"under the rate limit: want false, got true")
	}

	// Verify returned email history for nearLimit user
	eh, ok = fr.histories[userNearLimit]
	switch {
	case !ok:
		t.Errorf("user with email history under the rate limit " +
			"by one was not found in the histories list")

	case len(eh.Timestamps) != 3:
		t.Errorf("histories length for user under the rate limit "+
			"by one: want 3, got %v", len(eh.Timestamps))

	case !eh.LimitWarningSent:
		t.Errorf("limit warning sent for user with email history " +
			"under the rate limit by one: want true, got false")
	}

	// Verify returned email history for atLimitExpired user
	eh, ok = fr.histories[userAtLimitExpired]
	switch {
	case !ok:
		t.Errorf("user with email history at the rate limit but " +
			"expired was not found in the histories list")

	case len(eh.Timestamps) != 1:
		t.Errorf("histories length for user under the rate limit: "+
			"want 1, got %v", len(eh.Timestamps))

	case eh.LimitWarningSent:
		t.Errorf("limit warning sent for user with email history " +
			"at the rate limit but expired: want false, got true")
	}

	// Verify the filtered histories does not contain unexpected
	// histories.
	if len(fr.histories) != 4 {
		t.Errorf("filtered histories length: want 4, got %v",
			len(fr.histories))
	}
}

func TestFilterTimestamps(t *testing.T) {
	// Timestamps that are expired based on the default rate limit period,
	// and that must not be contained on the output if passed as input.
	minus24h := time.Now().Add(-(24 * time.Hour)).Unix()
	minus26h := time.Now().Add(-(26 * time.Hour)).Unix()
	minus28h := time.Now().Add(-(28 * time.Hour)).Unix()
	minus36h := time.Now().Add(-(36 * time.Hour)).Unix()
	minus42h := time.Now().Add(-(42 * time.Hour)).Unix()

	// Timestamps that are still valid and within the default rate limit period,
	// and that must be contained on the output if passed as input.
	minus12h := time.Now().Add(-(12 * time.Hour)).Unix()
	minus14h := time.Now().Add(-(14 * time.Hour)).Unix()
	minus16h := time.Now().Add(-(16 * time.Hour)).Unix()

	// Setup test cases
	var tests = []struct {
		name    string
		in      []int64
		wantOut []int64
	}{
		{
			"remove all timestamps",
			[]int64{minus24h, minus36h, minus42h},
			[]int64{},
		},
		{
			"remove stale timestamps",
			[]int64{minus12h, minus26h, minus28h},
			[]int64{minus12h},
		},
		{
			"no timestamps to remove",
			[]int64{minus12h, minus14h, minus16h},
			[]int64{minus12h, minus14h, minus16h},
		},
	}

	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			out := filterTimestamps(v.in, defaultRateLimitPeriod)

			// Verify if the function output matches the expected output.
			diff := cmp.Diff(out, v.wantOut)
			if diff != "" {
				t.Errorf("got/want diff: \n%v", diff)
			}
		})
	}
}

// newTestClient returns a new client that is setup for testing. The caller can
// optionally provide a list of email histories to seed the testMailerDB with
// on intialization.
func newTestClient(rateLimit int, rateLimitPeriod time.Duration, histories map[uuid.UUID]user.EmailHistory) *client {
	return &client{
		smtp:            nil,
		mailName:        "test",
		mailAddress:     "test@email.com",
		mailerDB:        user.NewTestMailerDB(histories),
		disabled:        false,
		rateLimit:       rateLimit,
		rateLimitPeriod: rateLimitPeriod,
	}
}
