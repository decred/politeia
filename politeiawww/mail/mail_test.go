package mail

import (
	"sync"
	"testing"
	"time"

	"github.com/decred/politeia/politeiawww/user"
	"github.com/google/go-cmp/cmp"
)

// TestMailerDB implements the MailerDB interface that is used for testing
// purposes. It saves and retrieves data in memory to emulate the behaviour
// needed to test the mail package.
type TestMailerDB struct {
	sync.RWMutex

	histories map[string]user.EmailHistory
}

// EmailHistoriesSave implements the save function using the in memory cache
// for testing purposes.
//
// This function satisfies the MailerDB interface.
func (m *TestMailerDB) EmailHistoriesSave(histories map[string]user.EmailHistory) error {
	m.Lock()
	defer m.Unlock()

	for email, history := range histories {
		m.histories[email] = history
	}

	return nil
}

// EmailHistoriesGet implements the get function for the in memory cache used
// for testing purposes.
//
// This function satisfies the MailerDB interface.
func (m *TestMailerDB) EmailHistoriesGet(users []string) (map[string]user.EmailHistory, error) {
	m.RLock()
	defer m.RUnlock()

	histories := make(map[string]user.EmailHistory, len(users))
	for _, email := range users {
		h, ok := m.histories[email]
		if !ok {
			// User email history does not exist, skip adding this
			// entry to the returned user email history map.
			continue
		}
		histories[email] = h
	}
	return histories, nil
}

// newClientTest returns a client used for testing purposes.
func newClientTest() *client {
	testMailerDB := &TestMailerDB{
		histories: make(map[string]user.EmailHistory, 5),
	}

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
	histories := make(map[string]user.EmailHistory, 5)

	// Valid recipients mock
	nowUnix := time.Now().Unix()
	validEmail := "valid@email.com"
	histories[validEmail] = user.EmailHistory{
		Timestamps: []int64{
			nowUnix,
			time.Now().Add(-(cooldown)).Unix(),
			time.Now().Add(-(cooldown)).Unix(),
		},
		LimitWarningSent: false,
	}
	validEmail2 := "valid2@email.com"
	histories[validEmail2] = user.EmailHistory{
		Timestamps: []int64{
			time.Now().Add(-(cooldown)).Unix(),
			time.Now().Add(-(cooldown)).Unix(),
			time.Now().Add(-(cooldown)).Unix(),
		},
		LimitWarningSent: false,
	}

	// Invalid recipients mock
	invalidEmail := "invalid@email.com"
	histories[invalidEmail] = user.EmailHistory{
		Timestamps:       []int64{nowUnix, nowUnix, nowUnix},
		LimitWarningSent: false,
	}
	invalidEmail2 := "invalid2@email.com"
	histories[invalidEmail2] = user.EmailHistory{
		Timestamps: []int64{
			time.Now().Add(-(12 * time.Hour)).Unix(),
			time.Now().Add(-(12 * time.Hour)).Unix(),
			time.Now().Add(-(12 * time.Hour)).Unix(),
		},
		LimitWarningSent: false,
	}

	// Save mocked data
	err := c.mailerDB.EmailHistoriesSave(histories)
	if err != nil {
		t.Fatalf("EmailHistoriesSave: %v", err)
	}

	// Test cases helper variables
	type result struct {
		valid     []string
		invalid   []string
		histories map[string]user.EmailHistory
	}

	// Test case: only invalid recipients
	wantHistories := make(map[string]user.EmailHistory, 1)
	wantHistories[invalidEmail] = user.EmailHistory{
		Timestamps:       histories[invalidEmail].Timestamps,
		LimitWarningSent: true,
	}
	wantHistories[invalidEmail2] = user.EmailHistory{
		Timestamps:       histories[invalidEmail2].Timestamps,
		LimitWarningSent: true,
	}
	iResult := result{
		valid:     nil,
		invalid:   []string{invalidEmail, invalidEmail2},
		histories: wantHistories,
	}

	// Test case: only valid recipients
	wantHistories = make(map[string]user.EmailHistory, 2)
	wantHistories[validEmail] = user.EmailHistory{
		Timestamps:       []int64{nowUnix, nowUnix},
		LimitWarningSent: false,
	}
	wantHistories[validEmail2] = user.EmailHistory{
		Timestamps:       []int64{nowUnix},
		LimitWarningSent: false,
	}
	vResult := result{
		valid:     []string{validEmail, validEmail2},
		invalid:   nil,
		histories: wantHistories,
	}

	// Test case: valid and invalid recipients
	wantHistories = make(map[string]user.EmailHistory, 4)
	wantHistories[validEmail] = user.EmailHistory{
		Timestamps:       []int64{nowUnix, nowUnix},
		LimitWarningSent: false,
	}
	wantHistories[validEmail2] = user.EmailHistory{
		Timestamps:       []int64{nowUnix},
		LimitWarningSent: false,
	}
	wantHistories[invalidEmail] = user.EmailHistory{
		Timestamps:       histories[invalidEmail].Timestamps,
		LimitWarningSent: true,
	}
	wantHistories[invalidEmail2] = user.EmailHistory{
		Timestamps:       histories[invalidEmail2].Timestamps,
		LimitWarningSent: true,
	}
	viResult := result{
		valid:     []string{validEmail, validEmail2},
		invalid:   []string{invalidEmail, invalidEmail2},
		histories: wantHistories,
	}

	// Test case: recipients without an email history
	random := "random@email.com"
	random2 := "random2@email.com"
	wantHistories = make(map[string]user.EmailHistory, 2)
	wantHistories[random] = user.EmailHistory{
		Timestamps:       []int64{nowUnix},
		LimitWarningSent: false,
	}
	wantHistories[random2] = user.EmailHistory{
		Timestamps:       []int64{nowUnix},
		LimitWarningSent: false,
	}
	rResult := result{
		valid:     []string{random, random2},
		invalid:   nil,
		histories: wantHistories,
	}

	// Setup test cases
	var tests = []struct {
		name       string
		recipients []string
		wantResult result
	}{
		{
			"only invalid recipients",
			[]string{invalidEmail, invalidEmail2},
			iResult,
		},
		{
			"only valid recipients",
			[]string{validEmail, validEmail2},
			vResult,
		},
		{
			"valid and invalid recipients",
			[]string{validEmail, validEmail2, invalidEmail, invalidEmail2},
			viResult,
		},
		{
			"recipients without an email history",
			[]string{random, random2},
			rResult,
		},
	}

	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			valid, invalid, histories, err := c.filterRecipients(v.recipients)
			if err != nil {
				t.Fatalf("filterRecipients: %v", err)
			}

			// Compare results with desired ones from test case
			diff := cmp.Diff(valid, v.wantResult.valid)
			if diff != "" {
				t.Errorf("got/want diff: \n%v", diff)
			}
			diff = cmp.Diff(invalid, v.wantResult.invalid)
			if diff != "" {
				t.Errorf("got/want diff: \n%v", diff)
			}
			diff = cmp.Diff(histories, v.wantResult.histories)
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
