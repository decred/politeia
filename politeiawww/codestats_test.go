package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/codetracker"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/go-test/deep"
	"github.com/google/uuid"
)

func TestProcessUserCodeStats(t *testing.T) {
	p, cleanup := newTestCMSwww(t)
	defer cleanup()

	requestedUser := newCMSUser(t, p, false, true, cms.DomainTypeDeveloper,
		cms.ContractorTypeDirect)

	mockedCodeStats, _ := createMockedStats(requestedUser.GitHubName)
	// Create mocked code stats for testing expected response
	ncs := user.UpdateCMSCodeStats{
		UserCodeStats: mockedCodeStats,
	}
	payload, err := user.EncodeUpdateCMSCodeStats(ncs)
	if err != nil {
		t.Fatalf("unable to encode update code stats payload %v", err)
	}
	pc := user.PluginCommand{
		ID:      user.CMSPluginID,
		Command: user.CmdUpdateCMSUserCodeStats,
		Payload: string(payload),
	}
	_, err = p.db.PluginExec(pc)
	if err != nil {
		t.Fatalf("unable to execute update code stats payload %v", err)
	}

	noGithubNameSet := newCMSUser(t, p, false, false, cms.DomainTypeDeveloper,
		cms.ContractorTypeDirect)
	//sameDomainRequesting := newCMSUser(t, p, cms.DomainTypeDeveloper,
	//	cms.ContractorTypeDirect)
	differentDomain := newCMSUser(t, p, false, true, cms.DomainTypeMarketing,
		cms.ContractorTypeDirect)

	admin := newCMSUser(t, p, true, true, cms.DomainTypeDeveloper,
		cms.ContractorTypeDirect)

	nonCMSUser, _ := newUser(t, p, true, false)

	var tests = []struct {
		name       string
		params     cms.UserCodeStats
		wantError  error
		requesting *user.User
		wantReply  *cms.UserCodeStatsReply
	}{
		{
			"error invalid dates end before start",
			cms.UserCodeStats{
				UserID:    requestedUser.ID.String(),
				StartTime: 872842440,
				EndTime:   872841440,
			},
			www.UserError{
				ErrorCode: cms.ErrorStatusInvalidDatesRequested,
			},
			&admin.User,
			nil,
		},
		{
			"error invalid dates beyond 6 month window",
			cms.UserCodeStats{
				UserID:    requestedUser.ID.String(),
				StartTime: 872842440,
				EndTime:   1599748547,
			},
			www.UserError{
				ErrorCode: cms.ErrorStatusInvalidDatesRequested,
			},
			&admin.User,
			nil,
		},
		{
			"error can't find requested user id",
			cms.UserCodeStats{
				UserID:    uuid.New().String(),
				StartTime: 1599738547,
				EndTime:   1599748547,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusUserNotFound,
			},
			&admin.User,
			nil,
		},
		{
			"error can't find requesting cms user",
			cms.UserCodeStats{
				UserID:    requestedUser.ID.String(),
				StartTime: 1599738547,
				EndTime:   1599748547,
			},
			www.UserError{
				ErrorCode: www.ErrorStatusUserNotFound,
			},
			nonCMSUser,
			nil,
		},
		{
			"empty reply different domain non-admin",
			cms.UserCodeStats{
				UserID:    requestedUser.ID.String(),
				StartTime: 1599738547,
				EndTime:   1599748547,
			},
			nil,
			&differentDomain.User,
			&cms.UserCodeStatsReply{},
		},
		{
			"error can't find requesting cms user",
			cms.UserCodeStats{
				UserID:    noGithubNameSet.ID.String(),
				StartTime: 1599738547,
				EndTime:   1599748547,
			},
			www.UserError{
				ErrorCode: cms.ErrorStatusMissingCodeStatsUsername,
			},
			&admin.User,
			nil,
		},
	}

	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			reply, err := p.processUserCodeStats(v.params, v.requesting)
			got := errToStr(err)
			want := errToStr(v.wantError)
			if got != want {
				t.Errorf("got %v, want %v", got, want)
			}

			if err != nil {
				return
			}

			diff := deep.Equal(reply, v.wantReply)
			if diff != nil {
				t.Errorf("got/want diff:\n%v",
					spew.Sdump(diff))
			}
		})
	}
}

type expectedCodeStats struct {
	Month           int
	Year            int
	MergeAdditions  int
	MergeDeletions  int
	ReviewAdditions int
	ReviewDeletions int
	PRs             []string
	Reviews         []string
}

// Creates a mocked set of code stats that will be updated to a test
// user's db information and an expected code stats results set is returned
// as well to confirm information.
func createMockedStats(username string) ([]user.CodeStats, []expectedCodeStats) {

	numberOfMonths := 3
	startingMonth := 3
	numberOfMonthPrs := 5
	numberOfMonthReviews := 3
	codeStats := make([]user.CodeStats, 0, numberOfMonths)
	year := 2020
	expectedResults := make([]expectedCodeStats, 0, numberOfMonths)

	for month := startingMonth; month <= numberOfMonths; month++ {
		expected := expectedCodeStats{}
		expected.Month = month
		expected.Year = year
		prs := make([]codetracker.PullRequestInformation, 0, numberOfMonthPrs)
		for i := 1; i <= numberOfMonthPrs; i++ {
			prNumber := i + month*10
			url := fmt.Sprintf("http://github.com/test/%v/pull/%v", numberOfMonthPrs, prNumber)
			additions := 100
			deletions := 100
			prs = append(prs, codetracker.PullRequestInformation{
				Repository: fmt.Sprintf("%v", numberOfMonthPrs),
				URL:        url,
				Number:     prNumber,
				Additions:  int64(additions),
				Deletions:  int64(deletions),
				Date:       time.Date(year, time.Month(month), numberOfMonthPrs, 0, 0, 0, 0, time.UTC).String(),
				State:      "MERGED",
			})
			if len(expected.PRs) == 0 {
				expected.PRs = make([]string, 0, numberOfMonthPrs)
				expected.PRs = append(expected.PRs, url)
			} else {
				expected.PRs = append(expected.PRs, url)
			}
			expected.MergeAdditions += additions
			expected.MergeDeletions += additions
		}
		reviews := make([]codetracker.ReviewInformation, 0, numberOfMonthReviews)
		for i := 1; i <= numberOfMonthReviews; i++ {
			prNumber := i + month*10
			url := fmt.Sprintf("http://github.com/test/%v/pull/%v", numberOfMonthReviews, prNumber)
			additions := 10
			deletions := 10
			reviews = append(reviews, codetracker.ReviewInformation{
				Repository: fmt.Sprintf("%v", numberOfMonthPrs),
				URL:        url,
				Number:     prNumber,
				Additions:  additions,
				Deletions:  deletions,
				Date:       time.Date(year, time.Month(month), numberOfMonthPrs, 0, 0, 0, 0, time.UTC).String(),
				State:      "MERGED",
			})
			if len(expected.PRs) == 0 {
				expected.PRs = make([]string, 0, numberOfMonthPrs)
				expected.PRs = append(expected.PRs, url)
			} else {
				expected.PRs = append(expected.PRs, url)
			}
			expected.ReviewAdditions += additions
			expected.ReviewDeletions += deletions
		}

		codeStats = append(codeStats, convertPRsToUserCodeStats(username, year,
			month, prs, reviews)...)

		expectedResults = append(expectedResults, expected)
	}
	return codeStats, expectedResults
}
