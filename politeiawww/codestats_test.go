package main

import (
	"fmt"
	"math/rand"
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

const (
	numberOfMonths = 3
	startingMonth  = 11
	startingYear   = 2019

	numberOfMonthPrs     = 5
	numberOfMonthReviews = 3
)

func TestProcessUserCodeStats(t *testing.T) {
	p, cleanup := newTestCMSwww(t)
	defer cleanup()

	requestedUser := newCMSUser(t, p, false, true, cms.DomainTypeDeveloper,
		cms.ContractorTypeDirect)

	// mockedCodeStats currently creates mocked code stats in user db
	mockedCodeStats := createMockedStats(requestedUser.GitHubName)

	oneMonthStartDate := time.Date(startingYear, time.Month(startingMonth),
		1, 0, 0, 0, 0, time.UTC)
	oneMonthEndDate := time.Date(startingYear, time.Month(startingMonth+1),
		1, 0, 0, 0, 0, time.UTC)

	oneMonthExpectedReply := convertExpectedResults(mockedCodeStats,
		oneMonthStartDate, oneMonthEndDate)

	oneMonthExpectedNoEndReply := convertExpectedResults(mockedCodeStats,
		oneMonthStartDate, oneMonthStartDate)

	twoMonthStartDate := time.Date(startingYear, time.Month(startingMonth),
		1, 0, 0, 0, 0, time.UTC)
	twoMonthEndDate := time.Date(startingYear, time.Month(startingMonth+2),
		1, 0, 0, 0, 0, time.UTC)

	twoMonthExpectedReply := convertExpectedResults(mockedCodeStats,
		twoMonthStartDate, twoMonthEndDate)

	threeMonthStartDate := time.Date(startingYear, time.Month(startingMonth),
		1, 0, 0, 0, 0, time.UTC)
	threeMonthEndDate := time.Date(startingYear,
		time.Month(startingMonth+numberOfMonths), 1, 0, 0, 0, 0, time.UTC)

	threeMonthExpectedReply := convertExpectedResults(mockedCodeStats,
		threeMonthStartDate, threeMonthEndDate)

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
		Command: user.CmdNewCMSUserCodeStats,
		Payload: string(payload),
	}
	_, err = p.db.PluginExec(pc)
	if err != nil {
		t.Fatalf("unable to execute update code stats payload %v", err)
	}

	randomUUID := uuid.New().String()
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
			"error no dates",
			cms.UserCodeStats{
				UserID: requestedUser.ID.String(),
			},
			www.UserError{
				ErrorCode: cms.ErrorStatusInvalidDatesRequested,
			},
			&admin.User,
			nil,
		},
		{
			"error no start date",
			cms.UserCodeStats{
				UserID:  requestedUser.ID.String(),
				EndTime: 872841440,
			},
			www.UserError{
				ErrorCode: cms.ErrorStatusInvalidDatesRequested,
			},
			&admin.User,
			nil,
		},
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
				UserID:    randomUUID,
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
		{
			"success one month range",
			cms.UserCodeStats{
				UserID:    requestedUser.ID.String(),
				StartTime: oneMonthStartDate.Unix(),
				EndTime:   oneMonthEndDate.Unix(),
			},
			nil,
			&admin.User,
			oneMonthExpectedReply,
		},
		{
			"success one month range no end",
			cms.UserCodeStats{
				UserID:    requestedUser.ID.String(),
				StartTime: oneMonthStartDate.Unix(),
			},
			nil,
			&admin.User,
			oneMonthExpectedNoEndReply,
		},
		{
			"success two month range",
			cms.UserCodeStats{
				UserID:    requestedUser.ID.String(),
				StartTime: twoMonthStartDate.Unix(),
				EndTime:   twoMonthEndDate.Unix(),
			},
			nil,
			&admin.User,
			twoMonthExpectedReply,
		},
		{
			"success three month range",
			cms.UserCodeStats{
				UserID:    requestedUser.ID.String(),
				StartTime: threeMonthStartDate.Unix(),
				EndTime:   threeMonthEndDate.Unix(),
			},
			nil,
			&admin.User,
			threeMonthExpectedReply,
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

// Creates a mocked set of code stats that will be updated to a test
// user's db information and an expected code stats results set is returned
// as well to confirm information.
func createMockedStats(username string) []user.CodeStats {

	codeStats := make([]user.CodeStats, 0, numberOfMonths)
	year := startingYear

	for month := startingMonth; month < numberOfMonths+startingMonth; month++ {
		mergedPRs := make([]codetracker.PullRequestInformation, 0, numberOfMonthPrs)
		updatePRs := make([]codetracker.PullRequestInformation, 0, numberOfMonthPrs)
		for i := 1; i <= numberOfMonthPrs; i++ {
			date := time.Date(startingYear, time.Month(month), i, 0, 0, 0, 0,
				time.UTC)
			prNumber := i + month*10
			url := fmt.Sprintf("http://github.com/test/%v/pull/%v", month,
				prNumber)
			additions := rand.Intn(100)
			deletions := rand.Intn(100)
			mergedPRs = append(mergedPRs, codetracker.PullRequestInformation{
				Repository: fmt.Sprintf("%v", month),
				URL:        url,
				Number:     prNumber,
				Additions:  int64(additions),
				Deletions:  int64(deletions),
				Date:       date.String(),
				State:      "MERGED",
			})
		}
		reviews := make([]codetracker.ReviewInformation, 0,
			numberOfMonthReviews)
		for i := 1; i <= numberOfMonthReviews; i++ {
			date := time.Date(startingYear, time.Month(month), i, 0, 0, 0, 0,
				time.UTC)
			prNumber := i + month*10
			url := fmt.Sprintf("http://github.com/test/%v/pull/%v", month,
				prNumber)
			additions := rand.Intn(100)
			deletions := rand.Intn(100)
			reviews = append(reviews, codetracker.ReviewInformation{
				Repository: fmt.Sprintf("%v", month),
				URL:        url,
				Number:     prNumber,
				Additions:  additions,
				Deletions:  deletions,
				Date:       date.String(),
				State:      "APPROVED",
			})
		}
		codeStats = append(codeStats, convertPRsToUserCodeStats(username, year,
			month, mergedPRs, updatePRs, reviews)...)
	}
	return codeStats
}

func convertExpectedResults(codeStats []user.CodeStats, start, end time.Time) *cms.UserCodeStatsReply {
	reply := &cms.UserCodeStatsReply{}
	rangeCodeStats := make([]user.CodeStats, 0, 6)
	for !start.After(end) {
		for _, codeStat := range codeStats {
			if codeStat.Month == int(start.Month()) &&
				codeStat.Year == start.Year() {
				rangeCodeStats = append(rangeCodeStats, codeStat)
			}
		}
		start = time.Date(start.Year(), start.Month()+1,
			start.Day(), start.Hour(), start.Minute(), 0, 0,
			time.UTC)
	}
	reply.RepoStats = convertCodeStatsFromDatabase(rangeCodeStats)

	return reply
}
