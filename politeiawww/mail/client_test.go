// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mail

import (
	"testing"
	"time"

	"github.com/decred/politeia/politeiawww/user"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"
)

// newClientTest returns a client used for testing purposes.
func newClientTest() *client {
	testMailerDB := user.NewTestMailerDB()

	return &client{
		smtp:        nil,
		mailName:    "test",
		mailAddress: "test@email.com",
		mailerDB:    testMailerDB,
		limit:       3,
		disabled:    false,
	}
}

func TestFilterRecipients(t *testing.T) {
	c := newClientTest()

	// Mock initial data
	histories := make(map[uuid.UUID]user.EmailHistory, 5)

	// Valid recipients mock
	nowUnix := time.Now().Unix()
	validUserID := uuid.New()
	validUserEmail := "valid@email.com"
	histories[validUserID] = user.EmailHistory{
		Timestamps: []int64{
			nowUnix,
			time.Now().Add(-(cooldown)).Unix(),
			time.Now().Add(-(cooldown)).Unix(),
		},
		LimitWarningSent: false,
	}
	validUserID2 := uuid.New()
	validUserEmail2 := "valid2@email.com"
	histories[validUserID2] = user.EmailHistory{
		Timestamps: []int64{
			time.Now().Add(-(cooldown)).Unix(),
			time.Now().Add(-(cooldown)).Unix(),
			time.Now().Add(-(cooldown)).Unix(),
		},
		LimitWarningSent: false,
	}

	// Invalid recipients mock
	invalidUserID := uuid.New()
	invalidUserEmail := "invalid@email.com"
	histories[invalidUserID] = user.EmailHistory{
		Timestamps:       []int64{nowUnix, nowUnix, nowUnix},
		LimitWarningSent: false,
	}
	invalidUserID2 := uuid.New()
	invalidUserEmail2 := "invalid2@email.com"
	histories[invalidUserID2] = user.EmailHistory{
		Timestamps: []int64{
			time.Now().Add(-(12 * time.Hour)).Unix(),
			time.Now().Add(-(12 * time.Hour)).Unix(),
			time.Now().Add(-(12 * time.Hour)).Unix(),
		},
		LimitWarningSent: false,
	}

	invalidUserID3 := uuid.New()
	invalidUserEmail3 := "invalid3@email.com"
	histories[invalidUserID3] = user.EmailHistory{
		Timestamps:       []int64{nowUnix, nowUnix, nowUnix},
		LimitWarningSent: true,
	}

	// Save mocked data
	err := c.mailerDB.EmailHistoriesSave(histories)
	if err != nil {
		t.Fatalf("EmailHistoriesSave: %v", err)
	}

	// Test cases helper variables

	// Test case: only invalid recipients
	wantHistories := make(map[uuid.UUID]user.EmailHistory, 2)
	wantHistories[invalidUserID] = user.EmailHistory{
		Timestamps:       histories[invalidUserID].Timestamps,
		LimitWarningSent: true,
	}
	wantHistories[invalidUserID2] = user.EmailHistory{
		Timestamps:       histories[invalidUserID2].Timestamps,
		LimitWarningSent: true,
	}
	iRecipients := map[uuid.UUID]string{
		invalidUserID:  invalidUserEmail,
		invalidUserID2: invalidUserEmail2,
	}
	iResult := filteredRecipients{
		valid:     nil,
		invalid:   []string{invalidUserEmail, invalidUserEmail2},
		histories: wantHistories,
	}

	// Test case: only invalid recipients that have received limit warning
	ilRecipients := map[uuid.UUID]string{
		invalidUserID3: invalidUserEmail3,
	}
	ilResult := filteredRecipients{
		valid:     nil,
		invalid:   nil,
		histories: map[uuid.UUID]user.EmailHistory{},
	}

	// Test case: only valid recipients
	wantHistories = make(map[uuid.UUID]user.EmailHistory, 2)
	wantHistories[validUserID] = user.EmailHistory{
		Timestamps:       []int64{nowUnix, nowUnix},
		LimitWarningSent: false,
	}
	wantHistories[validUserID2] = user.EmailHistory{
		Timestamps:       []int64{nowUnix},
		LimitWarningSent: false,
	}
	vRecipients := map[uuid.UUID]string{
		validUserID:  validUserEmail,
		validUserID2: validUserEmail2,
	}
	vResult := filteredRecipients{
		valid:     []string{validUserEmail, validUserEmail2},
		invalid:   nil,
		histories: wantHistories,
	}

	// Test case: valid and invalid recipients
	wantHistories = make(map[uuid.UUID]user.EmailHistory, 4)
	wantHistories[validUserID] = user.EmailHistory{
		Timestamps:       []int64{nowUnix, nowUnix},
		LimitWarningSent: false,
	}
	wantHistories[validUserID2] = user.EmailHistory{
		Timestamps:       []int64{nowUnix},
		LimitWarningSent: false,
	}
	wantHistories[invalidUserID] = user.EmailHistory{
		Timestamps:       histories[invalidUserID].Timestamps,
		LimitWarningSent: true,
	}
	wantHistories[invalidUserID2] = user.EmailHistory{
		Timestamps:       histories[invalidUserID2].Timestamps,
		LimitWarningSent: true,
	}
	viRecipients := map[uuid.UUID]string{
		validUserID:    validUserEmail,
		validUserID2:   validUserEmail2,
		invalidUserID:  invalidUserEmail,
		invalidUserID2: invalidUserEmail2,
	}
	viResult := filteredRecipients{
		valid:     []string{validUserEmail, validUserEmail2},
		invalid:   []string{invalidUserEmail, invalidUserEmail2},
		histories: wantHistories,
	}

	// Test case: recipients without an email history
	randomEmail := "random@email.com"
	randomEmail2 := "random2@email.com"
	randomID := uuid.New()
	randomID2 := uuid.New()
	wantHistories = make(map[uuid.UUID]user.EmailHistory, 2)
	wantHistories[randomID] = user.EmailHistory{
		Timestamps:       []int64{nowUnix},
		LimitWarningSent: false,
	}
	wantHistories[randomID2] = user.EmailHistory{
		Timestamps:       []int64{nowUnix},
		LimitWarningSent: false,
	}
	rRecipients := map[uuid.UUID]string{
		randomID:  randomEmail,
		randomID2: randomEmail2,
	}
	rResult := filteredRecipients{
		valid:     []string{randomEmail, randomEmail2},
		invalid:   nil,
		histories: wantHistories,
	}

	// Setup test cases
	var tests = []struct {
		name       string
		recipients map[uuid.UUID]string
		wantResult *filteredRecipients
	}{
		{
			"only invalid recipients",
			iRecipients,
			&iResult,
		},
		{
			"only invalid recipients that have received limit warning",
			ilRecipients,
			&ilResult,
		},
		{
			"only valid recipients",
			vRecipients,
			&vResult,
		},
		{
			"valid and invalid recipients",
			viRecipients,
			&viResult,
		},
		{
			"recipients without an email history",
			rRecipients,
			&rResult,
		},
	}

	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			filtered, err := c.filterRecipients(v.recipients)
			if err != nil {
				t.Fatalf("filterRecipients: %v", err)
			}

			// Sort slices with cmpopts before comparing the diffs.
			less := func(a, b string) bool { return a < b }

			// Compare results with desired ones from test case.
			diff := cmp.Diff(filtered.valid, v.wantResult.valid,
				cmpopts.SortSlices(less))
			if diff != "" {
				t.Errorf("got/want diff: \n%v", diff)
			}
			diff = cmp.Diff(filtered.invalid, v.wantResult.invalid,
				cmpopts.SortSlices(less))
			if diff != "" {
				t.Errorf("got/want diff: \n%v", diff)
			}
			diff = cmp.Diff(filtered.histories, v.wantResult.histories,
				cmpopts.SortSlices(less))
			if diff != "" {
				t.Errorf("got/want diff: \n%v", diff)
			}
		})
	}
}

func TestFilterTimestamps(t *testing.T) {
	// Setup test cases
	var tests = []struct {
		name    string
		in      []int64
		wantOut []int64
	}{
		{
			"remove all timestamps",
			[]int64{
				time.Now().Add(-(24 * time.Hour)).Unix(),
				time.Now().Add(-(36 * time.Hour)).Unix(),
				time.Now().Add(-(42 * time.Hour)).Unix(),
			},
			[]int64{},
		},
		{
			"remove stale timestamps",
			[]int64{
				time.Now().Add(-(12 * time.Hour)).Unix(),
				time.Now().Add(-(26 * time.Hour)).Unix(),
				time.Now().Add(-(28 * time.Hour)).Unix(),
			},
			[]int64{
				time.Now().Add(-(12 * time.Hour)).Unix(),
			},
		},
		{
			"no timestamps to remove",
			[]int64{
				time.Now().Add(-(12 * time.Hour)).Unix(),
				time.Now().Add(-(14 * time.Hour)).Unix(),
				time.Now().Add(-(16 * time.Hour)).Unix(),
			},
			[]int64{
				time.Now().Add(-(12 * time.Hour)).Unix(),
				time.Now().Add(-(14 * time.Hour)).Unix(),
				time.Now().Add(-(16 * time.Hour)).Unix(),
			},
		},
	}

	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			out := filterTimestamps(v.in, 24*time.Hour)

			// Compare result with desired one from test case
			diff := cmp.Diff(out, v.wantOut)
			if diff != "" {
				t.Errorf("got/want diff: \n%v", diff)
			}

		})
	}
}
