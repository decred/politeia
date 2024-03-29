// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cockroachdb

import (
	"fmt"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/decred/politeia/politeiawww/legacy/user"
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

// Tests
func TestNewCodeStats(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	// Arguments
	githubName := "github"
	repo := "decred"
	monthAug := 8
	prsAug := []string{"https://github.com/decred/pr/pull/1",
		"https://github.com/decred/pr/pull/2"}
	reviewsAug := []string{"https://github.com/decred/review/pull/1",
		"https://github.com/decred/review/pull/1"}
	mergeAdditionsAug := 100
	mergeDeletionsAug := 99
	updatedAdditionsAug := 300
	updatedDeletionsAug := 299
	reviewAdditionsAug := 200
	reviewDeletionsAug := 199
	commitAdditionsAug := 200
	commitDeletionsAug := 199

	monthSept := 9
	prsSept := []string{"https://github.com/decred/pr/pull/3",
		"https://github.com/decred/pr/pull/4"}
	reviewsSept := []string{"https://github.com/decred/review/pull/3",
		"https://github.com/decred/review/pull/4"}
	mergeAdditionsSept := 100
	mergeDeletionsSept := 99
	updatedAdditionsSept := 300
	updatedDeletionsSept := 299
	reviewAdditionsSept := 200
	reviewDeletionsSept := 199
	commitAdditionsSept := 200
	commitDeletionsSept := 199

	year := 2020

	augID := fmt.Sprintf("%v-%v-%v-%v", githubName, repo, strconv.Itoa(monthAug),
		strconv.Itoa(year))
	codeStats := make([]user.CodeStats, 0, 2)
	codeStats = append(codeStats, user.CodeStats{
		GitHubName:       githubName,
		Repository:       repo,
		Month:            monthAug,
		Year:             year,
		PRs:              prsAug,
		Reviews:          reviewsAug,
		MergedAdditions:  int64(mergeAdditionsAug),
		MergedDeletions:  int64(mergeDeletionsAug),
		UpdatedAdditions: int64(updatedAdditionsAug),
		UpdatedDeletions: int64(updatedDeletionsAug),
		ReviewAdditions:  int64(reviewAdditionsAug),
		ReviewDeletions:  int64(reviewDeletionsAug),
		CommitAdditions:  int64(commitAdditionsAug),
		CommitDeletions:  int64(commitDeletionsAug),
	})
	septID := fmt.Sprintf("%v-%v-%v-%v", githubName, repo,
		strconv.Itoa(monthSept), strconv.Itoa(year))
	codeStats = append(codeStats, user.CodeStats{
		GitHubName:       githubName,
		Repository:       repo,
		Month:            monthSept,
		Year:             year,
		PRs:              prsSept,
		Reviews:          reviewsSept,
		MergedAdditions:  int64(mergeAdditionsSept),
		MergedDeletions:  int64(mergeDeletionsSept),
		UpdatedAdditions: int64(updatedAdditionsSept),
		UpdatedDeletions: int64(updatedDeletionsSept),
		ReviewAdditions:  int64(reviewAdditionsSept),
		ReviewDeletions:  int64(reviewDeletionsSept),
		CommitAdditions:  int64(commitAdditionsSept),
		CommitDeletions:  int64(commitDeletionsSept),
	})
	convertedCodeStatsAug := convertCodestatsToDatabase(codeStats[0])
	convertedCodeStatsSept := convertCodestatsToDatabase(codeStats[1])
	nu := &user.NewCMSCodeStats{
		UserCodeStats: codeStats,
	}

	// Queries
	sqlInsertCMSCodeStats := `INSERT INTO "cms_code_stats" ` +
		`("id","git_hub_name","repository","month","year","p_rs","reviews",` +
		`"commits",` +
		`"merged_additions","merged_deletions","updated_additions",` +
		`"updated_deletions","review_additions",` +
		`"review_deletions","commit_additions","commit_deletions") VALUES ` +
		`($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) ` +
		`RETURNING "cms_code_stats"."id"`

	// Success Expectations
	mock.ExpectBegin()
	// Insert user to db
	mock.ExpectQuery(regexp.QuoteMeta(sqlInsertCMSCodeStats)).
		WithArgs(
			sqlmock.AnyArg(),
			convertedCodeStatsAug.GitHubName,
			convertedCodeStatsAug.Repository,
			convertedCodeStatsAug.Month,
			convertedCodeStatsAug.Year,
			convertedCodeStatsAug.PRs,
			convertedCodeStatsAug.Reviews,
			convertedCodeStatsAug.Commits,
			convertedCodeStatsAug.MergedAdditions,
			convertedCodeStatsAug.MergedDeletions,
			convertedCodeStatsAug.UpdatedAdditions,
			convertedCodeStatsAug.UpdatedDeletions,
			convertedCodeStatsAug.ReviewAdditions,
			convertedCodeStatsAug.ReviewDeletions,
			convertedCodeStatsAug.CommitAdditions,
			convertedCodeStatsAug.CommitDeletions).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(augID))
	mock.ExpectQuery(regexp.QuoteMeta(sqlInsertCMSCodeStats)).
		WithArgs(sqlmock.AnyArg(),
			convertedCodeStatsSept.GitHubName,
			convertedCodeStatsSept.Repository,
			convertedCodeStatsSept.Month,
			convertedCodeStatsSept.Year,
			convertedCodeStatsSept.PRs,
			convertedCodeStatsSept.Reviews,
			convertedCodeStatsSept.Commits,
			convertedCodeStatsSept.MergedAdditions,
			convertedCodeStatsSept.MergedDeletions,
			convertedCodeStatsSept.UpdatedAdditions,
			convertedCodeStatsSept.UpdatedDeletions,
			convertedCodeStatsSept.ReviewAdditions,
			convertedCodeStatsSept.ReviewDeletions,
			convertedCodeStatsSept.CommitAdditions,
			convertedCodeStatsSept.CommitDeletions).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(septID))
	mock.ExpectCommit()

	// Execute method
	err := cdb.NewCMSCodeStats(nu)
	if err != nil {
		t.Errorf("UserNew unwanted error: %s", err)
	}

	// Make sure expectations were met for both success and failure
	// conditions
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestUpdateCodeStats(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	// Arguments
	githubName := "github"
	repo := "decred"
	monthAug := 8
	mergeAdditionsAug := 100
	mergeDeletionsAug := 99
	updatedAdditionsAug := 300
	updatedDeletionsAug := 299
	reviewAdditionsAug := 200
	reviewDeletionsAug := 199
	commitAdditionsAug := 200
	commitDeletionsAug := 199
	year := 2020
	prsAug := []string{"https://github.com/decred/pr/pull/1",
		"https://github.com/decred/pr/pull/2"}
	reviewsAug := []string{"https://github.com/decred/review/pull/1",
		"https://github.com/decred/review/pull/1"}
	codeStats := make([]user.CodeStats, 0, 1)
	codeStats = append(codeStats, user.CodeStats{
		GitHubName:       githubName,
		Repository:       repo,
		Month:            monthAug,
		Year:             year,
		PRs:              prsAug,
		Reviews:          reviewsAug,
		MergedAdditions:  int64(mergeAdditionsAug),
		MergedDeletions:  int64(mergeDeletionsAug),
		UpdatedAdditions: int64(updatedAdditionsAug),
		UpdatedDeletions: int64(updatedDeletionsAug),
		ReviewAdditions:  int64(reviewAdditionsAug),
		ReviewDeletions:  int64(reviewDeletionsAug),
		CommitAdditions:  int64(commitAdditionsAug),
		CommitDeletions:  int64(commitDeletionsAug),
	})
	ucs := &user.UpdateCMSCodeStats{
		UserCodeStats: codeStats,
	}
	convertCodeStats := convertCodestatsToDatabase(codeStats[0])
	// Query
	sqlUpdateCMSCodeStats := `UPDATE "cms_code_stats" ` +
		`SET "git_hub_name" = $1, "repository" = $2, "month" = $3, ` +
		`"year" = $4, "p_rs" = $5, "reviews" = $6, "commits" = $7, ` +
		`"merged_additions" = $8, ` +
		`"merged_deletions" = $9, "updated_additions" = $10, ` +
		`"updated_deletions" = $11, "review_additions" = $12, ` +
		`"review_deletions" = $13, "commit_additions" = $14, ` +
		`"commit_deletions" = $15 ` +
		`WHERE "cms_code_stats"."id" = $16`

	augID := fmt.Sprintf("%v-%v-%v-%v", githubName, repo,
		strconv.Itoa(monthAug), strconv.Itoa(year))

	// Success Expectations
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(sqlUpdateCMSCodeStats)).
		WithArgs(
			convertCodeStats.GitHubName,
			convertCodeStats.Repository,
			convertCodeStats.Month,
			convertCodeStats.Year,
			convertCodeStats.PRs,
			convertCodeStats.Reviews,
			convertCodeStats.Commits,
			convertCodeStats.MergedAdditions,
			convertCodeStats.MergedDeletions,
			convertCodeStats.UpdatedAdditions,
			convertCodeStats.UpdatedDeletions,
			convertCodeStats.ReviewAdditions,
			convertCodeStats.ReviewDeletions,
			convertCodeStats.CommitAdditions,
			convertCodeStats.CommitDeletions,
			augID).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	// Execute method
	err := cdb.UpdateCMSCodeStats(ucs)
	if err != nil {
		t.Errorf("UserUpdate unwanted error: %s", err)
	}

	// Make sure expectations were met
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestCodeStatsByUserMonthYear(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	// Arguments
	now := time.Now()
	githubName := "github"
	repo := "decred"
	monthAug := 8
	mergeAdditionsAug := 100
	mergeDeletionsAug := 99
	reviewAdditionsAug := 200
	reviewDeletionsAug := 199
	year := 2020

	prsAug := "https://github.com/decred/pr/pull/1,https://github.com/decred/pr/pull/2"
	reviewsAug := "https://github.com/decred/review/pull/1,https://github.com/decred/review/pull/1"

	augID := githubName + repo + strconv.Itoa(monthAug) +
		strconv.Itoa(year)

	// Mock rows data
	rows := sqlmock.NewRows([]string{
		"id",
		"git_hub_name",
		"repository",
		"month",
		"year",
		"prs",
		"reviews",
		"merge_additions",
		"merge_deletions",
		"review_additions",
		"review_deletions",
		"created_at",
		"updated_at",
	}).AddRow(augID, githubName, repo, monthAug, year, prsAug, reviewsAug,
		mergeAdditionsAug, mergeDeletionsAug, reviewAdditionsAug,
		reviewDeletionsAug, now, now)

	// Query
	sql := `SELECT * FROM "cms_code_stats" WHERE (git_hub_name = $1 AND ` +
		`month = $2 AND year = $3)`

	// Success Expectations
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(githubName, monthAug, year).
		WillReturnRows(rows)

	csbm := &user.CMSCodeStatsByUserMonthYear{
		GithubName: githubName,
		Month:      monthAug,
		Year:       year,
	}
	// Execute method
	cs, err := cdb.CMSCodeStatsByUserMonthYear(csbm)
	if err != nil {
		t.Errorf("CMSCodeStatsByUserMonthYear unwanted error: %s", err)
	}
	for _, codeStat := range cs {
		// Make sure correct code stat was fetched
		if codeStat.ID != augID {
			t.Errorf("expecting user of id %s but received %s", codeStat.ID,
				augID)
		}
	}
	// Negative Expectations
	randomGithubName := "random"
	csbm = &user.CMSCodeStatsByUserMonthYear{
		GithubName: randomGithubName,
		Month:      monthAug,
		Year:       year,
	}
	expectedError := user.ErrCodeStatsNotFound
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(randomGithubName, monthAug, year).
		WillReturnError(expectedError)

	// Execute method
	cs, err = cdb.CMSCodeStatsByUserMonthYear(csbm)
	if err == nil {
		t.Errorf("expecting error but there was none")
	}

	if len(cs) > 0 {
		t.Errorf("expecting nil user to be returned, but got code stats of "+
			"len %v", len(cs))
	}

	// Make sure we got the expected error
	if err != expectedError {
		t.Errorf("expecting error %s but got %s", expectedError, err)
	}

	// Make sure expectations were met for both success and failure
	// conditions
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}
