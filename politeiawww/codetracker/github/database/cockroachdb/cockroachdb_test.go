// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cockroachdb

import (
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/decred/politeia/politeiawww/codetracker/github/database"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

func setupTestDB(t *testing.T) (*cockroachdb, sqlmock.Sqlmock, func()) {
	t.Helper()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("error %s while creating stub db conn", err)
	}

	gdb, err := gorm.Open("postgres", db)
	if err != nil {
		t.Fatalf("error %s while opening db with gorm", err)
	}

	c := &cockroachdb{
		recordsdb: gdb,
	}

	return c, mock, func() {
		db.Close()
	}
}

// Tests
func TestNewPullRequests(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	now := time.Now()
	// Arguments
	pr := &database.PullRequest{
		Repo:         "github",
		Organization: "decred",
		URL:          "https://github.com/decred/github/pull/1",
		Number:       1,
		User:         "stakey",
		UpdatedAt:    now.Unix(),
		ClosedAt:     now.Unix(),
		MergedAt:     now.Unix(),
		Merged:       true,
		State:        "MERGED",
		Additions:    100,
		Deletions:    99,
		MergedBy:     "davec",
	}

	// Queries
	sqlInsertPullRequests := `INSERT INTO "pullrequests" ` +
		`("repo","organization","url","number","author","updated_at","closed_at",` +
		`"merged_at","merged","state","additions","deletions","merged_by") ` +
		`VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) ` +
		`RETURNING "pullrequests"."url"`

	// Success Expectations
	mock.ExpectBegin()
	// Insert user to db
	mock.ExpectQuery(regexp.QuoteMeta(sqlInsertPullRequests)).
		WithArgs(
			pr.Repo,
			pr.Organization,
			pr.URL,
			pr.Number,
			pr.User,
			pr.UpdatedAt,
			pr.ClosedAt,
			pr.MergedAt,
			pr.Merged,
			pr.State,
			pr.Additions,
			pr.Deletions,
			pr.MergedBy).
		WillReturnRows(sqlmock.NewRows([]string{"url"}).AddRow(pr.URL))
	mock.ExpectCommit()

	// Execute method
	err := cdb.NewPullRequest(pr)
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

func TestUpdatePullRequests(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	now := time.Now()
	// Arguments
	pr := &database.PullRequest{
		Repo:         "github",
		Organization: "decred",
		URL:          "https://github.com/decred/github/pull/1",
		Number:       1,
		User:         "stakey",
		UpdatedAt:    now.Unix(),
		ClosedAt:     now.Unix(),
		MergedAt:     now.Unix(),
		Merged:       true,
		State:        "MERGED",
		Additions:    100,
		Deletions:    99,
		MergedBy:     "davec",
	}
	// Arguments
	sqlUpdatePullRequests := `UPDATE "pullrequests" ` +
		`SET "repo" = $1, "organization" = $2, "number" = $3, ` +
		`"author" = $4, "updated_at" = $5, "closed_at" = $6, ` +
		`"merged_at" = $7, "merged" = $8, "state" = $9, "additions" = $10, ` +
		`"deletions" = $11, "merged_by" = $12 ` +
		`WHERE "pullrequests"."url" = $13`

	// Success Expectations
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(sqlUpdatePullRequests)).
		WithArgs(
			pr.Repo,
			pr.Organization,
			pr.Number,
			pr.User,
			pr.UpdatedAt,
			pr.ClosedAt,
			pr.MergedAt,
			pr.Merged,
			pr.State,
			pr.Additions,
			pr.Deletions,
			pr.MergedBy,
			pr.URL).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	// Execute method
	err := cdb.UpdatePullRequest(pr)
	if err != nil {
		t.Errorf("UpdatePullRequest unwanted error: %s", err)
	}

	// Make sure expectations were met
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestNewPullRequestsReview(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	now := time.Now()
	// Arguments
	review := &database.PullRequestReview{
		PullRequestURL: "https://github.com/decred/github/pull/1",
		Author:         "stakey",
		State:          "APPROVED",
		SubmittedAt:    now.Unix(),
		Repo:           "github",
		Number:         1,
		ID:             4934324,
	}

	// Queries
	sqlInsertPullRequests := `INSERT INTO "reviews" ` +
		`("pull_request_url","id","author","state","submitted_at",` +
		`"commit_id","repo","number") ` +
		`VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ` +
		`RETURNING "reviews"."id"`

	// Success Expectations
	mock.ExpectBegin()
	// Insert user to db
	mock.ExpectQuery(regexp.QuoteMeta(sqlInsertPullRequests)).
		WithArgs(
			review.PullRequestURL,
			review.ID,
			review.Author,
			review.State,
			review.SubmittedAt,
			sqlmock.AnyArg(),
			review.Repo,
			review.Number,
		).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(review.ID))
	mock.ExpectCommit()

	// Execute method
	err := cdb.NewPullRequestReview(review)
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

func TestUpdatePullRequestsReview(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	now := time.Now()
	// Arguments
	review := &database.PullRequestReview{
		PullRequestURL: "https://github.com/decred/github/pull/1",
		Author:         "stakey",
		State:          "APPROVED",
		SubmittedAt:    now.Unix(),
		Repo:           "github",
		Number:         1,
		ID:             4934324,
	}
	// Queries
	sqlUpdatePullRequests := `UPDATE "reviews" ` +
		`SET "pull_request_url" = $1, "author" = $2, "state" = $3, ` +
		`"submitted_at" = $4, "commit_id" = $5, "repo" = $6, "number" = $7 ` +
		`WHERE "reviews"."id" = $8`

	// Success Expectations
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(sqlUpdatePullRequests)).
		WithArgs(
			review.PullRequestURL,
			review.Author,
			review.State,
			review.SubmittedAt,
			sqlmock.AnyArg(),
			review.Repo,
			review.Number,
			review.ID).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	// Execute method
	err := cdb.UpdatePullRequestReview(review)
	if err != nil {
		t.Errorf("UpdatePullRequestReview unwanted error: %s", err)
	}

	// Make sure expectations were met
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

func TestPullRequestByURL(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	// Arguments
	now := time.Now()
	pr := &database.PullRequest{
		Repo:         "github",
		Organization: "decred",
		URL:          "https://github.com/decred/github/pull/1",
		Number:       1,
		User:         "stakey",
		UpdatedAt:    now.Unix(),
		ClosedAt:     now.Unix(),
		MergedAt:     now.Unix(),
		Merged:       true,
		State:        "MERGED",
		Additions:    100,
		Deletions:    99,
		MergedBy:     "davec",
	}

	url := "https://github.com/decred/pr/pull/1"

	urlNotFound := "https://github.com/decred/pr/pull/2"

	// Mock rows data
	rows := sqlmock.NewRows([]string{
		"repo",
		"organization",
		"url",
		"number",
		"author",
		"updated_at",
		"closed_at",
		"merged_at",
		"merged",
		"state",
		"additions",
		"deletions",
		"merged_by",
	}).AddRow(
		pr.Repo,
		pr.Organization,
		pr.URL,
		pr.Number,
		pr.User,
		pr.UpdatedAt,
		pr.ClosedAt,
		pr.MergedAt,
		pr.Merged,
		pr.State,
		pr.Additions,
		pr.Deletions,
		pr.MergedBy,
	)

	// Query
	sql := `SELECT * FROM "pullrequests" WHERE "pullrequests"."url" = $1`

	// Success Expectations
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(url).
		WillReturnRows(rows)

	// Execute method
	_, err := cdb.PullRequestByURL(url)
	if err != nil {
		t.Errorf("PullRequestByURL unwanted error: %s", err)
	}

	expectedError := database.ErrNoPullRequestFound
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(urlNotFound).
		WillReturnError(expectedError)

	foundPr, err := cdb.PullRequestByURL(urlNotFound)
	if err == nil {
		t.Errorf("expecting error but there was none")
	}

	if foundPr != nil {
		t.Errorf("expecting nil pr to be returned, but got non-nil pr")
	}

	// Make sure we got the expected error
	if err != expectedError {
		t.Errorf("expecting error %s but got %s", expectedError, err)
	}

	// Make sure expectations were met
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

/*
func TestPullRequestsByUserDates(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()
	// Execute method
	_, err := cdb.PullRequestsByUserDates("username", 10, 10)
	if err != nil {
		t.Errorf("PullRequestByUserDates unwanted error: %s", err)
	}
	// Make sure expectations were met
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}
*/
func TestReviewsByUserDates(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()

	now := time.Now()
	authorStakey := "stakey"

	prURLFirst := "https://github.com/decred/github/pull/1"
	prURLSecond := "https://github.com/decred/github/pull/2"
	prURLThird := "https://github.com/decred/github/pull/3"

	reviewFirst := &database.PullRequestReview{
		ID:             434234234,
		Repo:           "github",
		PullRequestURL: prURLFirst,
		Number:         1,
		Author:         authorStakey,
		SubmittedAt:    now.Unix(),
		State:          "APPROVED",
		Additions:      11,
		Deletions:      11,
		CommitID:       "abcd1234",
	}

	reviewSecond := &database.PullRequestReview{
		ID:             434234235,
		Repo:           "github",
		PullRequestURL: prURLSecond,
		Number:         2,
		Author:         authorStakey,
		SubmittedAt:    now.Add(-1 * time.Hour).Unix(),
		State:          "APPROVED",
		Additions:      22,
		Deletions:      22,
		CommitID:       "abcd1236",
	}
	/*
		reviewThird := &database.PullRequestReview{
			ID:             434234234,
			Repo:           "github",
			PullRequestURL: prURLThird,
			Number:         3,
			Author:         authorTicket,
			SubmittedAt:    now.Unix(),
			State:          "APPROVED",
			Additions:      33,
			Deletions:      33,
			CommitID:       "abcd1238",
		}
	*/
	prFirst := &database.PullRequest{
		Repo:         "github",
		Organization: "decred",
		URL:          prURLFirst,
		Number:       1,
		User:         "stakey_author",
		UpdatedAt:    now.Unix(),
		ClosedAt:     now.Unix(),
		MergedAt:     now.Unix(),
		Merged:       true,
		State:        "MERGED",
		Additions:    11,
		Deletions:    11,
		MergedBy:     "davec",
	}

	prSecond := &database.PullRequest{
		Repo:         "github",
		Organization: "decred",
		URL:          prURLSecond,
		Number:       1,
		User:         "stakey_author",
		UpdatedAt:    now.Unix(),
		ClosedAt:     now.Unix(),
		MergedAt:     now.Unix(),
		Merged:       true,
		State:        "MERGED",
		Additions:    22,
		Deletions:    22,
		MergedBy:     "davec",
	}

	prThird := &database.PullRequest{
		Repo:         "github",
		Organization: "decred",
		URL:          prURLThird,
		Number:       1,
		User:         "stakey_author",
		UpdatedAt:    now.Unix(),
		ClosedAt:     now.Unix(),
		MergedAt:     now.Unix(),
		Merged:       true,
		State:        "MERGED",
		Additions:    33,
		Deletions:    33,
		MergedBy:     "davec",
	}

	// Mock rows data
	rows := sqlmock.NewRows([]string{
		"repo",
		"organization",
		"url",
		"number",
		"author",
		"updated_at",
		"closed_at",
		"merged_at",
		"merged",
		"state",
		"additions",
		"deletions",
		"merged_by",
	}).AddRow(
		prFirst.Repo,
		prFirst.Organization,
		prFirst.URL,
		prFirst.Number,
		prFirst.User,
		prFirst.UpdatedAt,
		prFirst.ClosedAt,
		prFirst.MergedAt,
		prFirst.Merged,
		prFirst.State,
		prFirst.Additions,
		prFirst.Deletions,
		prFirst.MergedBy,
	).AddRow(
		prSecond.Repo,
		prSecond.Organization,
		prSecond.URL,
		prSecond.Number,
		prSecond.User,
		prSecond.UpdatedAt,
		prSecond.ClosedAt,
		prSecond.MergedAt,
		prSecond.Merged,
		prSecond.State,
		prSecond.Additions,
		prSecond.Deletions,
		prSecond.MergedBy,
	).AddRow(
		prThird.Repo,
		prThird.Organization,
		prThird.URL,
		prThird.Number,
		prThird.User,
		prThird.UpdatedAt,
		prThird.ClosedAt,
		prThird.MergedAt,
		prThird.Merged,
		prThird.State,
		prThird.Additions,
		prThird.Deletions,
		prThird.MergedBy,
	)
	rows = sqlmock.NewRows([]string{
		"pull_request_url",
		"id",
		"author",
		"state",
		"submitted_at",
		"commit_id",
		"repo",
		"number",
	}).AddRow(
		reviewFirst.PullRequestURL,
		reviewFirst.ID,
		reviewFirst.Author,
		reviewFirst.State,
		reviewFirst.SubmittedAt,
		reviewFirst.CommitID,
		reviewFirst.Repo,
		reviewFirst.Number,
	).AddRow(
		reviewSecond.PullRequestURL,
		reviewSecond.ID,
		reviewSecond.Author,
		reviewSecond.State,
		reviewSecond.SubmittedAt,
		reviewSecond.CommitID,
		reviewSecond.Repo,
		reviewSecond.Number,
	)

	bothRangeStart := now.Add(-2 * time.Hour).Unix()
	bothRangeEnd := now.Add(time.Minute).Unix()

	// Query
	sql := `
    SELECT 
	  reviews.pull_request_url,
	  reviews.id,
	  reviews.author,
	  reviews.state,
	  reviews.submitted_at,
	  reviews.commit_id,
	  reviews.repo,
	  reviews.number,
	  pullrequests.additions,
	  pullrequests.deletions
    FROM reviews
    INNER JOIN pullrequests
	  ON pullrequests.url = reviews.pull_request_url
    WHERE reviews.author = $1 AND reviews.state = $2 AND 
	  reviews.submitted_at BETWEEN $3 AND $4`

	// Success Expectations
	mock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(reviewFirst.Author, "APPROVED", bothRangeStart, bothRangeEnd).
		WillReturnRows(rows)

	// Execute method
	_, err := cdb.ReviewsByUserDates(reviewFirst.Author, bothRangeStart,
		bothRangeEnd)
	if err != nil {
		t.Errorf("ReviewsByUserDate unwanted error: %s", err)
	}

	// Make sure expectations were met
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}

/*
func TestAllUsersByDates(t *testing.T) {
	cdb, mock, close := setupTestDB(t)
	defer close()
	// Execute method
	_, err := cdb.AllUsersByDates(10, 10)
	if err != nil {
		t.Errorf("AllUsersByDates unwanted error: %s", err)
	}
	// Make sure expectations were met
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Errorf("unfulfilled expectations: %s", err)
	}
}
*/
