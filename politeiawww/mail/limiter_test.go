package mail

import (
	"fmt"
	"testing"
	"time"

	"github.com/decred/politeia/politeiawww/user"
	"github.com/decred/politeia/politeiawww/user/mock"
	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
)

func TestLimiter_IsEnabled(t *testing.T) {
	mm := &MailerMock{
		IsEnabledFunc: func() bool {
			return true
		},
	}
	limiter := NewLimiter(mm, nil, 3)

	got := limiter.IsEnabled()
	if diff := cmp.Diff(true, got); diff != "" {
		t.Error(diff)
	}
}

func TestLimiter_SendTo(t *testing.T) {
	const subject = "some subject"
	const body = "some body"

	const emailGood = "good"
	const emailIgnored = "ignored"
	const emailBad = "bad"

	userIDGood := uuid.New()
	userIDIgnored := uuid.New()
	userIDBad := uuid.New()

	currentTime := time.Now()
	ts1 := currentTime.Add(-1 * time.Hour)
	ts2 := currentTime.Add(-22 * time.Hour)
	ts3 := currentTime.Add(-23 * time.Hour)
	ts4 := currentTime.Add(-25 * time.Hour)

	historyGood := user.EmailHistory{
		SentTimestamps:   []time.Time{ts2, ts3, ts4},
		LimitWarningSent: false,
	}
	// Exceeds limit, warning has already been sent.
	historyIgnored := user.EmailHistory{
		SentTimestamps:   []time.Time{ts1, ts2, ts3, ts4},
		LimitWarningSent: true,
	}
	// Exceeds limit, warning hasn't yet been sent.
	historyBad := user.EmailHistory{
		SentTimestamps:   []time.Time{ts1, ts2, ts3, ts4},
		LimitWarningSent: false,
	}

	mm := &MailerMock{
		SendToFunc: func(s string, b string, rs []string) error {
			if diff := cmp.Diff(subject, s); diff != "" {
				return fmt.Errorf("unexpected s: %v", diff)
			}
			if diff := cmp.Diff(body, b); diff != "" {
				return fmt.Errorf("unexpected b: %v", diff)
			}

			if cmp.Equal([]string{emailGood}, rs) {
				return nil
			}
			if cmp.Equal([]string{emailBad}, rs) {
				return nil
			}
			return fmt.Errorf("unexpected rs: %v", rs)
		},
	}
	userDB := &mock.DatabaseMock{
		EmailHistoriesGet24hFunc: func(recipients []uuid.UUID) (map[uuid.UUID]user.EmailHistory, error) {
			if diff := cmp.Diff(3, len(recipients)); diff != "" {
				return nil, fmt.Errorf("expected only 3 recipients: %s", diff)
			}
			return map[uuid.UUID]user.EmailHistory{
				userIDGood:    historyGood,
				userIDIgnored: historyIgnored,
				userIDBad:     historyBad,
			}, nil
		},
		EmailHistoriesSave24hFunc: func(histories map[uuid.UUID]user.EmailHistory) error {
			if 1 != len(histories) {
				return fmt.Errorf("unexpected histories: %v", histories)
			}

			got, ok := histories[userIDGood]
			if ok {
				if false != got.LimitWarningSent {
					return fmt.Errorf("good history, LimitWarningSent, want: %t, got: %t",
						false, got.LimitWarningSent)
				}
				if 3 != len(got.SentTimestamps) {
					return fmt.Errorf("good history, SentTimestamps, want: %d, got: %d",
						3, len(got.SentTimestamps))
				}
				return nil
			}

			got, ok = histories[userIDBad]
			if ok {
				if true != got.LimitWarningSent {
					return fmt.Errorf("bad history, LimitWarningSent, want: %t, got: %t",
						true, got.LimitWarningSent)
				}
				if 4 != len(got.SentTimestamps) {
					return fmt.Errorf("bad history, SentTimestamps, want: %d, got: %d",
						4, len(got.SentTimestamps))
				}
				return nil
			}

			return fmt.Errorf("unexpected histories: %v", histories)
		},
	}
	limiter := NewLimiter(mm, userDB, 3)

	got := limiter.SendToUsers(subject, body, map[uuid.UUID]string{
		userIDGood:    emailGood,
		userIDIgnored: emailIgnored,
		userIDBad:     emailBad,
	})
	if diff := cmp.Diff(nil, got); diff != "" {
		t.Error(diff)
	}
}
